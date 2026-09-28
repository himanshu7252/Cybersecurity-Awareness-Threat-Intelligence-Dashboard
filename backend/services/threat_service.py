"""
Threat Intelligence Service Layer
Author: Defensive Cybersecurity Engineering Team
Purpose: Coordinates data retrieval, filtering, pagination, sorting,
         analyst notes, statistics aggregation, and trend computations.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.models.database import get_db_connection
from backend.services.risk_engine import calculate_threat_risk, get_source_reliability
from backend.services.attack_mapper import map_category_to_attack

def get_threats(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    indicator_type: Optional[str] = None,
    status: Optional[str] = None,
    min_risk: Optional[int] = None,
    max_risk: Optional[int] = None,
    min_confidence: Optional[int] = None,
    search: Optional[str] = None,
    sort_by: str = "last_seen",
    order: str = "desc",
    page: int = 1,
    page_size: int = 25
) -> Dict[str, Any]:
    """Retrieve filtered, sorted, paginated threats with associated indicators."""
    conn = get_db_connection()
    cursor = conn.cursor()

    conditions = []
    params = []

    if category:
        conditions.append("LOWER(t.category) = LOWER(?)")
        params.append(category)

    if severity:
        conditions.append("LOWER(t.severity) = LOWER(?)")
        params.append(severity)

    if status:
        conditions.append("LOWER(t.status) = LOWER(?)")
        params.append(status)

    if indicator_type:
        conditions.append("LOWER(i.indicator_type) = LOWER(?)")
        params.append(indicator_type)

    if min_risk is not None:
        conditions.append("t.risk_score >= ?")
        params.append(min_risk)

    if max_risk is not None:
        conditions.append("t.risk_score <= ?")
        params.append(max_risk)

    if min_confidence is not None:
        conditions.append("t.confidence_score >= ?")
        params.append(min_confidence)

    if search:
        search_pattern = f"%{search.strip().lower()}%"
        conditions.append("""(
            LOWER(t.threat_id) LIKE ? OR
            LOWER(t.threat_name) LIKE ? OR
            LOWER(t.description) LIKE ? OR
            LOWER(i.indicator_value) LIKE ?
        )""")
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # Count total matching
    count_sql = f"""
        SELECT COUNT(DISTINCT t.threat_id) as total
        FROM threats t
        LEFT JOIN indicators i ON t.threat_id = i.threat_id
        {where_clause}
    """
    cursor.execute(count_sql, params)
    total_records = cursor.fetchone()["total"]

    # Safe sorting fields
    valid_sorts = {
        "last_seen": "t.last_seen",
        "first_seen": "t.first_seen",
        "risk_score": "t.risk_score",
        "confidence_score": "t.confidence_score",
        "threat_id": "t.threat_id",
        "severity": "t.risk_score"
    }
    sort_column = valid_sorts.get(sort_by, "t.last_seen")
    sort_dir = "ASC" if order.lower() == "asc" else "DESC"

    offset = (page - 1) * page_size
    query_sql = f"""
        SELECT t.*, i.indicator_type, i.indicator_value
        FROM threats t
        LEFT JOIN indicators i ON t.threat_id = i.threat_id
        {where_clause}
        GROUP BY t.threat_id
        ORDER BY {sort_column} {sort_dir}
        LIMIT ? OFFSET ?
    """
    cursor.execute(query_sql, params + [page_size, offset])
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    total_pages = max(1, (total_records + page_size - 1) // page_size)

    return {
        "total_records": total_records,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "threats": rows
    }

def get_threat_by_id(threat_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full details of a specific threat, including indicators, notes, and mappings."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,))
    threat = cursor.fetchone()
    if not threat:
        conn.close()
        return None

    threat_dict = dict(threat)

    # Indicators
    cursor.execute("SELECT * FROM indicators WHERE threat_id = ?", (threat_id,))
    threat_dict["indicators"] = [dict(r) for r in cursor.fetchall()]

    # ATT&CK Mappings
    cursor.execute("SELECT * FROM attack_mappings WHERE threat_id = ?", (threat_id,))
    mappings = [dict(r) for r in cursor.fetchall()]
    if not mappings:
        mappings = map_category_to_attack(threat_dict["category"])
    threat_dict["attack_mappings"] = mappings

    # Alerts
    cursor.execute("SELECT * FROM alerts WHERE threat_id = ? ORDER BY timestamp DESC", (threat_id,))
    threat_dict["alerts"] = [dict(r) for r in cursor.fetchall()]

    # Analyst Notes
    cursor.execute("SELECT * FROM analyst_notes WHERE threat_id = ? ORDER BY created_at DESC", (threat_id,))
    threat_dict["analyst_notes"] = [dict(r) for r in cursor.fetchall()]

    # Source info
    threat_dict["source_reliability"] = get_source_reliability(threat_dict.get("source_name", "Internal SOC"))

    # Defensive Actions
    cat = threat_dict["category"]
    actions = [
        f"Defensive Action: Inspect perimeter log telemetry for matching {cat} indicators.",
        "Check endpoint security sensors for execution telemetry or process tampering.",
        "Verify internal asset isolation status and review credential access logs.",
        "Document analyst findings in the case notes and monitor indicator persistence."
    ]
    threat_dict["recommended_actions"] = actions

    conn.close()
    return threat_dict

def create_threat(threat_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new threat record with indicator and risk calculation."""
    conn = get_db_connection()
    cursor = conn.cursor()

    threat_id = threat_data.get("threat_id")
    if not threat_id:
        cursor.execute("SELECT COUNT(*) as count FROM threats")
        count = cursor.fetchone()["count"]
        threat_id = f"THR-2026-{count + 1:04d}"

    now_iso = datetime.utcnow().isoformat() + "Z"
    first_seen = threat_data.get("first_seen", now_iso)
    last_seen = threat_data.get("last_seen", now_iso)

    # Compute risk score using risk engine
    calc = calculate_threat_risk(
        severity=threat_data.get("severity", "MEDIUM"),
        confidence_score=int(threat_data.get("confidence_score", 70)),
        source_name=threat_data.get("source_name", "Internal SOC")
    )
    risk_score = threat_data.get("risk_score") or calc["risk_score"]

    cursor.execute("""
        INSERT OR REPLACE INTO threats (
            threat_id, threat_name, category, description, severity,
            risk_score, confidence_score, status, first_seen, last_seen,
            country_or_region, source_name
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        threat_id,
        threat_data.get("threat_name", "Unspecified Defensive Indicator"),
        threat_data.get("category", "NETWORK THREATS"),
        threat_data.get("description", "Analyst ingested defensive indicator."),
        threat_data.get("severity", "MEDIUM"),
        risk_score,
        int(threat_data.get("confidence_score", 70)),
        threat_data.get("status", "NEW"),
        first_seen,
        last_seen,
        threat_data.get("country_or_region", "Global / Multi-region"),
        threat_data.get("source_name", "Internal SOC")
    ))

    # Add Indicator
    ind_type = threat_data.get("indicator_type", "IP ADDRESS")
    ind_val = threat_data.get("indicator_value", "192.0.2.100")
    cursor.execute("""
        INSERT INTO indicators (
            threat_id, indicator_type, indicator_value, first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?)
    """, (threat_id, ind_type, ind_val, first_seen, last_seen))

    conn.commit()
    conn.close()

    return {"success": True, "threat_id": threat_id, "risk_score": risk_score}

def update_threat(threat_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Update fields of an existing threat record."""
    conn = get_db_connection()
    cursor = conn.cursor()

    allowed = ["threat_name", "category", "description", "severity", "status", "risk_score", "confidence_score"]
    fields = []
    values = []

    for k, v in updates.items():
        if k in allowed:
            fields.append(f"{k} = ?")
            values.append(v)

    if not fields:
        conn.close()
        return {"success": False, "error": "No valid fields provided for update."}

    values.append(threat_id)
    cursor.execute(f"UPDATE threats SET {', '.join(fields)} WHERE threat_id = ?", values)
    conn.commit()
    conn.close()

    return {"success": True, "threat_id": threat_id}

def add_analyst_note(threat_id: str, analyst_name: str, note: str) -> Dict[str, Any]:
    """Add a documented observation note to a threat."""
    conn = get_db_connection()
    cursor = conn.cursor()

    now_iso = datetime.utcnow().isoformat() + "Z"
    cursor.execute("""
        INSERT INTO analyst_notes (threat_id, analyst_name, note, created_at)
        VALUES (?, ?, ?, ?)
    """, (threat_id, analyst_name or "SOC Analyst", note, now_iso))

    note_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {"success": True, "note_id": note_id, "created_at": now_iso}

def get_dashboard_stats() -> Dict[str, Any]:
    """Aggregate top high-level SOC metrics for dashboard display."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM threats;")
    total_threats = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as count FROM threats WHERE severity = 'CRITICAL';")
    critical_threats = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM threats WHERE severity = 'HIGH';")
    high_threats = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM indicators;")
    active_indicators = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM threats WHERE status IN ('NEW', 'UNDER_REVIEW', 'MONITORING');")
    open_investigations = cursor.fetchone()["count"]

    cursor.execute("SELECT AVG(confidence_score) as avg_conf FROM threats;")
    avg_conf = round(cursor.fetchone()["avg_conf"] or 0.0, 1)

    cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities;")
    vulnerabilities_tracked = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE status IN ('NEW', 'INVESTIGATING');")
    active_alerts = cursor.fetchone()["count"]

    conn.close()

    return {
        "total_threats": total_threats,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "active_indicators": active_indicators,
        "open_investigations": open_investigations,
        "average_confidence": avg_conf,
        "vulnerabilities_tracked": vulnerabilities_tracked,
        "active_alerts": active_alerts
    }

def get_dashboard_trends() -> Dict[str, Any]:
    """Compile chart data points for the 10 SOC visual analytics."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Threats Over Time (Group by month)
    cursor.execute("""
        SELECT SUBSTR(last_seen, 1, 7) as month_period, COUNT(*) as count
        FROM threats
        GROUP BY month_period
        ORDER BY month_period ASC
        LIMIT 12
    """)
    threats_over_time = [{"period": r["month_period"], "count": r["count"]} for r in cursor.fetchall()]

    # 2. Threats by Severity
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM threats
        GROUP BY severity
        ORDER BY count DESC
    """)
    threats_by_severity = {r["severity"]: r["count"] for r in cursor.fetchall()}

    # 3. Threats by Category
    cursor.execute("""
        SELECT category, COUNT(*) as count
        FROM threats
        GROUP BY category
        ORDER BY count DESC
    """)
    threats_by_category = [{"category": r["category"], "count": r["count"]} for r in cursor.fetchall()]

    # 4. IOC Type Distribution
    cursor.execute("""
        SELECT indicator_type, COUNT(*) as count
        FROM indicators
        GROUP BY indicator_type
        ORDER BY count DESC
    """)
    ioc_distribution = {r["indicator_type"]: r["count"] for r in cursor.fetchall()}

    # 5. Top MITRE ATT&CK Tactics
    cursor.execute("""
        SELECT tactic, COUNT(*) as count
        FROM attack_mappings
        GROUP BY tactic
        ORDER BY count DESC
        LIMIT 8
    """)
    attack_tactics = [{"tactic": r["tactic"], "count": r["count"]} for r in cursor.fetchall()]

    # 6. Risk Score Distribution (Buckets)
    cursor.execute("""
        SELECT 
            SUM(CASE WHEN risk_score <= 20 THEN 1 ELSE 0 END) as info_count,
            SUM(CASE WHEN risk_score > 20 AND risk_score <= 40 THEN 1 ELSE 0 END) as low_count,
            SUM(CASE WHEN risk_score > 40 AND risk_score <= 60 THEN 1 ELSE 0 END) as med_count,
            SUM(CASE WHEN risk_score > 60 AND risk_score <= 80 THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN risk_score > 80 THEN 1 ELSE 0 END) as crit_count
        FROM threats
    """)
    risk_row = cursor.fetchone()
    risk_distribution = {
        "0-20 (Informational)": risk_row["info_count"] or 0,
        "21-40 (Low)": risk_row["low_count"] or 0,
        "41-60 (Medium)": risk_row["med_count"] or 0,
        "61-80 (High)": risk_row["high_count"] or 0,
        "81-100 (Critical)": risk_row["crit_count"] or 0
    }

    # 7. Confidence Score Distribution (Buckets)
    cursor.execute("""
        SELECT 
            SUM(CASE WHEN confidence_score <= 40 THEN 1 ELSE 0 END) as low_conf,
            SUM(CASE WHEN confidence_score > 40 AND confidence_score <= 70 THEN 1 ELSE 0 END) as med_conf,
            SUM(CASE WHEN confidence_score > 70 THEN 1 ELSE 0 END) as high_conf
        FROM threats
    """)
    conf_row = cursor.fetchone()
    confidence_distribution = {
        "Low Confidence (0-40%)": conf_row["low_conf"] or 0,
        "Moderate Confidence (41-70%)": conf_row["med_conf"] or 0,
        "High Confidence (71-100%)": conf_row["high_conf"] or 0
    }

    # 8. Vulnerabilities by Severity
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM vulnerabilities
        GROUP BY severity
        ORDER BY count DESC
    """)
    vulns_by_severity = {r["severity"]: r["count"] for r in cursor.fetchall()}

    # 9. Top Threat Categories (Top 5)
    top_categories = threats_by_category[:5]

    # 10. Threat Status Distribution
    cursor.execute("""
        SELECT status, COUNT(*) as count
        FROM threats
        GROUP BY status
        ORDER BY count DESC
    """)
    threat_status_distribution = {r["status"]: r["count"] for r in cursor.fetchall()}

    conn.close()

    return {
        "threats_over_time": threats_over_time,
        "threats_by_severity": threats_by_severity,
        "threats_by_category": threats_by_category,
        "ioc_distribution": ioc_distribution,
        "attack_tactics": attack_tactics,
        "risk_distribution": risk_distribution,
        "confidence_distribution": confidence_distribution,
        "vulns_by_severity": vulns_by_severity,
        "top_categories": top_categories,
        "threat_status_distribution": threat_status_distribution
    }
