"""
Database Model and SQLite Schema Management
Provides thread-safe connections, schema creation, data seeding, and indexing.
"""

import os
import sqlite3
import json
import csv
from datetime import datetime

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "threat_intelligence.db"
)

def get_db_connection(db_path=None):
    """Obtain a SQLite database connection with row factory enabled and concurrency safety."""
    path = db_path or os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path=None):
    """Initialize database tables, views, and indexes."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Threats Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        threat_id TEXT PRIMARY KEY,
        threat_name TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        confidence_score INTEGER NOT NULL,
        status TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        country_or_region TEXT,
        source_name TEXT NOT NULL
    );
    """)

    # 2. Indicators Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS indicators (
        indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        FOREIGN KEY (threat_id) REFERENCES threats(threat_id) ON DELETE CASCADE
    );
    """)

    # 3. Sources Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sources (
        source_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_name TEXT UNIQUE NOT NULL,
        reliability TEXT NOT NULL,
        reliability_score REAL NOT NULL
    );
    """)

    # 4. ATT&CK Mappings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_mappings (
        mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT NOT NULL,
        tactic TEXT NOT NULL,
        technique TEXT NOT NULL,
        technique_id_optional TEXT,
        FOREIGN KEY (threat_id) REFERENCES threats(threat_id) ON DELETE CASCADE
    );
    """)

    # 5. Vulnerabilities Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE NOT NULL,
        product_category TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        published_date TEXT NOT NULL,
        patch_available TEXT NOT NULL,
        exploitation_status_demo TEXT,
        description TEXT,
        priority_score INTEGER NOT NULL
    );
    """)

    # 6. Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        threat_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        confidence_score INTEGER NOT NULL,
        observation_count INTEGER DEFAULT 1,
        description TEXT,
        status TEXT NOT NULL,
        FOREIGN KEY (threat_id) REFERENCES threats(threat_id) ON DELETE CASCADE
    );
    """)

    # 7. Analyst Notes Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyst_notes (
        note_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT NOT NULL,
        analyst_name TEXT NOT NULL,
        note TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (threat_id) REFERENCES threats(threat_id) ON DELETE CASCADE
    );
    """)

    # 8. Awareness Modules Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS awareness_modules (
        module_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        estimated_read_time TEXT NOT NULL,
        what_is_it TEXT NOT NULL,
        why_it_matters TEXT NOT NULL,
        warning_signs TEXT NOT NULL,
        safe_practices TEXT NOT NULL,
        incident_guidance TEXT NOT NULL
    );
    """)

    # 9. Quiz Results Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS quiz_results (
        result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        anonymous_user_id_optional TEXT,
        overall_score INTEGER NOT NULL,
        grade TEXT NOT NULL,
        category_scores TEXT NOT NULL,
        weak_areas TEXT NOT NULL,
        recommendations TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # Create Indexes for Query Optimization
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(category);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_risk ON threats(risk_score);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(indicator_value);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(indicator_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat ON alerts(threat_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_tactic ON attack_mappings(tactic);")

    conn.commit()
    conn.close()
    print("[+] Database initialized successfully.")

def seed_database_if_empty(db_path=None, force=False):
    """Seed SQLite database from CSV datasets and JSON files if tables are empty."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    threat_csv = os.path.join(base_dir, "data", "threat_intelligence_dataset.csv")
    vuln_csv = os.path.join(base_dir, "data", "vulnerabilities.csv")
    modules_json = os.path.join(base_dir, "awareness", "modules.json")

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Check threat count
    cursor.execute("SELECT COUNT(*) AS count FROM threats;")
    count = cursor.fetchone()["count"]

    if count == 0 or force:
        print("[*] Seeding database from datasets...")

        # 1. Seed Sources
        sources_data = [
            ("Internal SOC", "A – Highly Reliable", 0.95),
            ("Security Vendor", "A – Highly Reliable", 0.90),
            ("Public Threat Feed", "B – Usually Reliable", 0.75),
            ("Research Report", "B – Usually Reliable", 0.80),
            ("Community Submission", "C – Fairly Reliable", 0.60),
            ("Unknown Source", "D – Reliability Unknown", 0.40)
        ]
        for name, rel, score in sources_data:
            cursor.execute("""
                INSERT OR IGNORE INTO sources (source_name, reliability, reliability_score)
                VALUES (?, ?, ?)
            """, (name, rel, score))

        # 2. Seed Threats and Indicators
        if os.path.exists(threat_csv):
            with open(threat_csv, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cursor.execute("""
                        INSERT OR REPLACE INTO threats (
                            threat_id, threat_name, category, description, severity,
                            risk_score, confidence_score, status, first_seen, last_seen,
                            country_or_region, source_name
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        row["threat_id"], row["threat_name"], row["threat_category"],
                        row["description"], row["severity"], int(row["risk_score"]),
                        int(row["confidence_score"]), row["status"], row["first_seen"],
                        row["last_seen"], row.get("country_or_region_optional", ""),
                        row["source_name"]
                    ))

                    cursor.execute("""
                        INSERT INTO indicators (
                            threat_id, indicator_type, indicator_value, first_seen, last_seen
                        ) VALUES (?, ?, ?, ?, ?)
                    """, (
                        row["threat_id"], row["indicator_type"], row["indicator_value"],
                        row["first_seen"], row["last_seen"]
                    ))

                    # If MITRE tactic exists
                    if row.get("mitre_tactic_optional"):
                        tactic = row["mitre_tactic_optional"]
                        technique = row.get("mitre_technique_optional", "")
                        tech_id = ""
                        if "(" in technique and ")" in technique:
                            tech_id = technique.split("(")[-1].replace(")", "").strip()
                        cursor.execute("""
                            INSERT INTO attack_mappings (
                                threat_id, tactic, technique, technique_id_optional
                            ) VALUES (?, ?, ?, ?)
                        """, (row["threat_id"], tactic, technique, tech_id))

                    # Generate baseline alerts for Critical and High threats
                    if row["severity"] in ["CRITICAL", "HIGH"] and int(row["risk_score"]) >= 75:
                        alert_id = f"ALT-{row['threat_id']}"
                        cursor.execute("""
                            INSERT OR IGNORE INTO alerts (
                                alert_id, threat_id, timestamp, alert_type, severity,
                                risk_score, confidence_score, observation_count, description, status
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            alert_id, row["threat_id"], row["last_seen"],
                            f"Automated High-Risk Alert: {row['threat_category']}",
                            row["severity"], int(row["risk_score"]), int(row["confidence_score"]),
                            1, f"Automated defensive alert triggered by risk threshold: {row['threat_name']}",
                            "NEW" if row["status"] == "NEW" else "MONITORING"
                        ))

        # 3. Seed Demonstration Scenario Analyst Note
        cursor.execute("""
            INSERT OR IGNORE INTO analyst_notes (threat_id, analyst_name, note, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            "THR-2026-001",
            "SOC Tier-1 Analyst (Alex)",
            "Indicator appears in multiple synthetic phishing observations. Correlated with staging IP 198.51.100.25. Defensive monitoring active.",
            datetime(2026, 9, 28, 9, 30, 0).isoformat() + "Z"
        ))

        # 4. Seed Vulnerabilities
        if os.path.exists(vuln_csv):
            with open(vuln_csv, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cursor.execute("""
                        INSERT OR REPLACE INTO vulnerabilities (
                            cve_id, product_category, severity, cvss_score,
                            published_date, patch_available, exploitation_status_demo,
                            description, priority_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        row["cve_id"], row["product_category"], row["severity"],
                        float(row["cvss_score"]), row["published_date"],
                        row["patch_available"], row.get("exploitation_status_demo", ""),
                        row["description"], int(row["priority_score"])
                    ))

        # 5. Seed Awareness Modules
        if os.path.exists(modules_json):
            with open(modules_json, mode="r", encoding="utf-8") as f:
                modules = json.load(f)
                for m in modules:
                    cursor.execute("""
                        INSERT OR REPLACE INTO awareness_modules (
                            module_id, title, category, difficulty, estimated_read_time,
                            what_is_it, why_it_matters, warning_signs, safe_practices, incident_guidance
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        m["module_id"], m["title"], m["category"], m["difficulty"],
                        m["estimated_read_time"], m["what_is_it"], m["why_it_matters"],
                        json.dumps(m["warning_signs"]), json.dumps(m["safe_practices"]),
                        m["incident_guidance"]
                    ))

        conn.commit()
        print(f"[+] Seeding complete! Database ready with {cursor.execute('SELECT COUNT(*) FROM threats').fetchone()[0]} threats.")
    else:
        print(f"[i] Database already populated with {count} threat records.")

    conn.close()

if __name__ == "__main__":
    init_db()
    seed_database_if_empty(force=True)
