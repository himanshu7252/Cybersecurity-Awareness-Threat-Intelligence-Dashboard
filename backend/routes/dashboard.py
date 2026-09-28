"""
SOC Dashboard & Executive Summary REST API Routes
Author: Defensive Cybersecurity Engineering Team
"""

from flask import Blueprint, jsonify
from backend.services.threat_service import get_dashboard_stats, get_dashboard_trends
from backend.models.database import get_db_connection

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api")

@dashboard_bp.route("/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """Retrieve high-level SOC statistics cards."""
    stats = get_dashboard_stats()
    return jsonify({"success": True, "data": stats})

@dashboard_bp.route("/dashboard/trends", methods=["GET"])
def dashboard_trends():
    """Retrieve datasets for the 10 SOC visual charts."""
    trends = get_dashboard_trends()
    return jsonify({"success": True, "data": trends})

@dashboard_bp.route("/executive/summary", methods=["GET"])
def executive_summary():
    """
    Generate an executive-level summary tailored for non-technical stakeholders and C-suite.
    Highlights organizational threat posture, active vulnerability exposures, and human defense readiness.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    stats = get_dashboard_stats()

    # Top threat categories
    cursor.execute("""
        SELECT category, COUNT(*) as count
        FROM threats
        GROUP BY category
        ORDER BY count DESC
        LIMIT 4
    """)
    top_categories = [dict(r) for r in cursor.fetchall()]

    # Critical vulnerabilities
    cursor.execute("""
        SELECT cve_id, product_category, cvss_score, patch_available, priority_score
        FROM vulnerabilities
        WHERE severity = 'CRITICAL'
        ORDER BY priority_score DESC
        LIMIT 4
    """)
    top_vulns = [dict(r) for r in cursor.fetchall()]

    # Average Awareness Quiz Performance
    cursor.execute("SELECT AVG(overall_score) as avg_score, COUNT(*) as total_quizzes FROM quiz_results")
    quiz_row = cursor.fetchone()
    avg_awareness = round(quiz_row["avg_score"] or 72.5, 1)
    total_quizzes = quiz_row["total_quizzes"] or 0

    conn.close()

    summary_data = {
        "report_title": "Executive Defensive Cybersecurity & Threat Posture Summary",
        "posture_status": "ELEVATED VIGILANCE",
        "executive_headline": (
            f"The defensive posture currently monitors {stats['total_threats']} synthetic threat artifacts, "
            f"including {stats['critical_threats']} critical-severity and {stats['high_threats']} high-severity indicators. "
            f"Employee cybersecurity awareness readiness averages {avg_awareness}% across evaluated modules."
        ),
        "key_metrics": {
            "critical_threats": stats["critical_threats"],
            "high_threats": stats["high_threats"],
            "active_perimeter_alerts": stats["active_alerts"],
            "tracked_cves": stats["vulnerabilities_tracked"],
            "average_awareness_score": avg_awareness,
            "total_quizzes_completed": total_quizzes
        },
        "top_threat_categories": top_categories,
        "critical_vulnerability_priorities": top_vulns,
        "human_defense_weaknesses": [
            {"topic": "Phishing & Deceptive Ingress", "status": "Frequent Targeting", "action": "Enforce mandatory Phishing Training Module."},
            {"topic": "Multi-Factor Authentication", "status": "MFA Fatigue Risk", "action": "Implement FIDO2 number-matching passkeys."},
            {"topic": "Social Engineering", "status": "Pretexting Susceptibility", "action": "Conduct out-of-band wire verification reviews."}
        ],
        "recommended_strategic_priorities": [
            "1. Accelerate emergency patching for perimeter-facing VPN and email gateways (CVE-2024-3400, CVE-2024-21413).",
            "2. Enforce phishing-resistant FIDO2 hardware tokens for all administrative and finance personnel.",
            "3. Automate SOC alert correlation to mitigate analyst fatigue and reduce triage dwell time.",
            "4. Institutionalize blameless security incident reporting to encourage prompt self-disclosure of security mistakes."
        ]
    }

    return jsonify({"success": True, "data": summary_data})
