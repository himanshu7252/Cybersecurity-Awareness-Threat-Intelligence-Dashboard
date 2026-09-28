"""
Local Defensive Threat Enrichment Engine
Author: Defensive Cybersecurity Engineering Team
Purpose: Correlates and enriches indicators using local synthetic intelligence data.
CRITICAL DEFENSIVE RULE:
No automated external network connection is ever made to searched hosts, IPs, or URLs.
Enrichment is strictly performed through passive local database and telemetry lookups.
"""

from typing import Dict, Any, List
from backend.models.database import get_db_connection
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import get_source_reliability
from backend.services.attack_mapper import map_category_to_attack

def enrich_indicator(indicator_value: str) -> Dict[str, Any]:
    """
    Passively enrich a given indicator against local synthetic threat intelligence.
    
    Args:
        indicator_value (str): The indicator string (IP, Domain, Hash, URL, CVE, Email).
        
    Returns:
        dict: Complete enriched intelligence dossier.
    """
    # 1. Syntactic format validation
    val_result = validate_indicator(indicator_value)
    clean_val = val_result["normalized_value"] or indicator_value.strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2. Query threats and indicators database
    cursor.execute("""
        SELECT t.*, i.indicator_type, i.indicator_value
        FROM threats t
        JOIN indicators i ON t.threat_id = i.threat_id
        WHERE LOWER(i.indicator_value) = LOWER(?)
           OR LOWER(t.threat_id) = LOWER(?)
        ORDER BY t.last_seen DESC
    """, (clean_val, clean_val))
    records = cursor.fetchall()

    if not records:
        # Check if it matches a CVE in vulnerabilities table
        cursor.execute("SELECT * FROM vulnerabilities WHERE LOWER(cve_id) = LOWER(?)", (clean_val,))
        vuln = cursor.fetchone()
        conn.close()

        if vuln:
            return {
                "searched_indicator": indicator_value,
                "normalized_value": clean_val,
                "syntactic_validation": val_result,
                "known_in_demo_dataset": True,
                "indicator_type": "CVE ID",
                "sightings_count": 1,
                "first_seen": vuln["published_date"],
                "last_seen": vuln["published_date"],
                "severity": vuln["severity"],
                "risk_score": vuln["priority_score"],
                "confidence_score": 90,
                "status": "MONITORING",
                "associated_categories": ["VULNERABILITY EXPOSURE"],
                "sources": [{"name": "Public Vulnerability Repository", "reliability": "A – Highly Reliable"}],
                "description": vuln["description"],
                "vulnerability_details": dict(vuln),
                "mitre_mapping": [
                    {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application (T1190)", "id": "T1190"}
                ],
                "related_alerts": [],
                "related_indicators": [],
                "analyst_notes": [],
                "defensive_recommendations": [
                    f"Review inventory for affected '{vuln['product_category']}' software packages.",
                    f"Verify patch status: Patch Available = {vuln['patch_available']}.",
                    "Implement network perimeter filtering or workarounds if patching requires downtime.",
                    "Review host/network telemetry for attempted exploitation signatures."
                ],
                "defensive_notice": "Passive database lookup only. No active external scanning was performed."
            }

        # Unknown indicator response
        return {
            "searched_indicator": indicator_value,
            "normalized_value": clean_val,
            "syntactic_validation": val_result,
            "known_in_demo_dataset": False,
            "indicator_type": val_result["indicator_type"],
            "sightings_count": 0,
            "first_seen": None,
            "last_seen": None,
            "severity": "INFORMATIONAL",
            "risk_score": 10,
            "confidence_score": 20,
            "status": "UNOBSERVED",
            "associated_categories": [],
            "sources": [],
            "description": "Indicator not observed in local synthetic threat intelligence dataset.",
            "mitre_mapping": [],
            "related_alerts": [],
            "related_indicators": [],
            "analyst_notes": [],
            "defensive_recommendations": [
                "Submit indicator to internal SOC queue for retrospective firewall/proxy log search.",
                "Verify format correctness and ensure no active scanning is initiated.",
                "Monitor boundary gateways for potential first-time sightings."
            ],
            "defensive_notice": "Passive database lookup only. No connection established."
        }

    # Aggregate records
    threat_ids = [r["threat_id"] for r in records]
    categories = list(set([r["category"] for r in records]))
    max_risk = max([r["risk_score"] for r in records])
    avg_conf = int(sum([r["confidence_score"] for r in records]) / len(records))
    highest_severity = records[0]["severity"]
    first_seen = min([r["first_seen"] for r in records])
    last_seen = max([r["last_seen"] for r in records])
    status = records[0]["status"]
    ind_type = records[0]["indicator_type"]
    sources = []
    for r in records:
        s_name = r["source_name"]
        s_rel = get_source_reliability(s_name)
        sources.append({"name": s_name, "reliability": f"{s_rel['grade']} – {s_rel['label']}"})

    # Related alerts
    cursor.execute(f"""
        SELECT * FROM alerts WHERE threat_id IN ({','.join(['?']*len(threat_ids))})
    """, threat_ids)
    alerts = [dict(a) for a in cursor.fetchall()]

    # Analyst notes
    cursor.execute(f"""
        SELECT * FROM analyst_notes WHERE threat_id IN ({','.join(['?']*len(threat_ids))})
        ORDER BY created_at DESC
    """, threat_ids)
    notes = [dict(n) for n in cursor.fetchall()]

    # ATT&CK Mappings
    cursor.execute(f"""
        SELECT * FROM attack_mappings WHERE threat_id IN ({','.join(['?']*len(threat_ids))})
    """, threat_ids)
    attack_rows = cursor.fetchall()
    attack_mappings = [dict(row) for row in attack_rows]
    if not attack_mappings and categories:
        attack_mappings = map_category_to_attack(categories[0])

    # Related indicators in same campaign / cluster
    cursor.execute("""
        SELECT i.indicator_type, i.indicator_value, t.threat_id, t.threat_name
        FROM indicators i
        JOIN threats t ON i.threat_id = t.threat_id
        WHERE t.category IN ({seq})
          AND LOWER(i.indicator_value) != LOWER(?)
        LIMIT 6
    """.format(seq=','.join(['?']*len(categories))), (*categories, clean_val))
    related_inds = [dict(i) for i in cursor.fetchall()]

    conn.close()

    # Recommended defensive actions by category
    defensive_actions = [
        "Review historical firewall, proxy, and DNS query logs for internal resolution of this indicator.",
        "Check endpoint detection & response (EDR) telemetry for matching hashes or outbound socket connections.",
        "If confirmed malicious by senior analyst, add to defensive perimeter blocklist (firewall/DNS sinkhole).",
        "Deploy user awareness advisory if category relates to phishing or social engineering campaigns.",
        "Maintain monitoring status for 14-30 days to observe potential reinfection attempts."
    ]

    return {
        "searched_indicator": indicator_value,
        "normalized_value": clean_val,
        "syntactic_validation": val_result,
        "known_in_demo_dataset": True,
        "threat_id": records[0]["threat_id"],
        "threat_name": records[0]["threat_name"],
        "indicator_type": ind_type,
        "sightings_count": len(records),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "severity": highest_severity,
        "risk_score": max_risk,
        "confidence_score": avg_conf,
        "status": status,
        "associated_categories": categories,
        "sources": sources,
        "description": records[0]["description"],
        "mitre_mapping": attack_mappings,
        "related_alerts": alerts,
        "related_indicators": related_inds,
        "analyst_notes": notes,
        "defensive_recommendations": defensive_actions,
        "defensive_notice": "Passive database lookup only. No automated external network connection was established."
    }
