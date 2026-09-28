"""
Defensive Alert Engine & De-Duplication Correlation Service
Author: Defensive Cybersecurity Engineering Team
Purpose: Generates actionable security alerts based on risk thresholds and correlates
         repetitive sightings to prevent SOC analyst alert fatigue.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.models.database import get_db_connection

def generate_threat_alert(
    threat_id: str,
    threat_name: str,
    category: str,
    severity: str,
    risk_score: int,
    confidence_score: int,
    custom_desc: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate or correlate an alert for a threat record.
    If an open alert already exists for this threat, increments observation_count (Alert Fatigue Reduction).
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    now_iso = datetime.utcnow().isoformat() + "Z"

    # Check for existing open alert for this threat
    cursor.execute("""
        SELECT * FROM alerts
        WHERE threat_id = ? AND status IN ('NEW', 'INVESTIGATING', 'MONITORING')
        ORDER BY timestamp DESC LIMIT 1
    """, (threat_id,))
    existing = cursor.fetchone()

    if existing:
        # Correlate alert: increment observation count and update timestamp
        alert_id = existing["alert_id"]
        new_count = existing["observation_count"] + 1
        cursor.execute("""
            UPDATE alerts
            SET observation_count = ?,
                timestamp = ?,
                risk_score = MAX(risk_score, ?),
                confidence_score = MAX(confidence_score, ?)
            WHERE alert_id = ?
        """, (new_count, now_iso, risk_score, confidence_score, alert_id))
        conn.commit()
        conn.close()

        return {
            "status": "CORRELATED",
            "alert_id": alert_id,
            "observation_count": new_count,
            "message": f"Alert {alert_id} deduplicated: observation count incremented to {new_count} to prevent alert fatigue."
        }

    # Otherwise, create a new alert
    alert_id = f"ALT-{threat_id}-{int(datetime.utcnow().timestamp())}"
    alert_type = f"Threshold Breach: {category.title()}"
    description = custom_desc or f"Defensive alert triggered by elevated risk ({risk_score}/100) on threat {threat_name}."

    cursor.execute("""
        INSERT INTO alerts (
            alert_id, threat_id, timestamp, alert_type, severity,
            risk_score, confidence_score, observation_count, description, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_id, threat_id, now_iso, alert_type, severity,
        risk_score, confidence_score, 1, description, "NEW"
    ))
    conn.commit()
    conn.close()

    return {
        "status": "CREATED",
        "alert_id": alert_id,
        "observation_count": 1,
        "message": f"New security alert {alert_id} created in SOC queue."
    }

def update_alert_status(alert_id: str, new_status: str, analyst_note: Optional[str] = None) -> Dict[str, Any]:
    """
    Update the triage status of an alert (NEW, INVESTIGATING, MONITORING, RESOLVED, FALSE_POSITIVE).
    """
    valid_statuses = ["NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"]
    if new_status.upper() not in valid_statuses:
        return {"success": False, "error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"}

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    alert = cursor.fetchone()
    if not alert:
        conn.close()
        return {"success": False, "error": f"Alert '{alert_id}' not found."}

    cursor.execute("""
        UPDATE alerts SET status = ? WHERE alert_id = ?
    """, (new_status.upper(), alert_id))

    # If analyst note provided, append to analyst_notes
    if analyst_note:
        now_iso = datetime.utcnow().isoformat() + "Z"
        cursor.execute("""
            INSERT INTO analyst_notes (threat_id, analyst_name, note, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            alert["threat_id"],
            "SOC Analyst",
            f"Alert {alert_id} status changed to {new_status.upper()}: {analyst_note}",
            now_iso
        ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "alert_id": alert_id,
        "new_status": new_status.upper(),
        "message": f"Alert {alert_id} successfully transitioned to {new_status.upper()}."
    }

def get_alerts(status_filter: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve security alerts with threat and indicator context."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT a.*, t.threat_name, t.category, i.indicator_type, i.indicator_value
        FROM alerts a
        JOIN threats t ON a.threat_id = t.threat_id
        LEFT JOIN indicators i ON t.threat_id = i.threat_id
    """
    params = []
    if status_filter:
        query += " WHERE LOWER(a.status) = LOWER(?)"
        params.append(status_filter)

    query += " ORDER BY a.risk_score DESC, a.timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    alerts = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return alerts
