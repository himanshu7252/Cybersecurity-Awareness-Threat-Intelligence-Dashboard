"""
Vulnerability Awareness & Prioritization REST API Routes
Author: Defensive Cybersecurity Engineering Team
"""

from flask import Blueprint, request, jsonify
from backend.models.database import get_db_connection
from backend.services.risk_engine import calculate_vulnerability_priority
from backend.utils.helpers import sanitize_input

vulnerabilities_bp = Blueprint("vulnerabilities", __name__, url_prefix="/api/vulnerabilities")

@vulnerabilities_bp.route("", methods=["GET"])
def list_vulnerabilities():
    """Retrieve defensive vulnerability records with sorting and filters."""
    severity = request.args.get("severity")
    patch = request.args.get("patch_available")
    search = request.args.get("search")

    conn = get_db_connection()
    cursor = conn.cursor()

    conditions = []
    params = []

    if severity:
        conditions.append("LOWER(severity) = LOWER(?)")
        params.append(severity)

    if patch:
        conditions.append("LOWER(patch_available) = LOWER(?)")
        params.append(patch)

    if search:
        pattern = f"%{search.strip().lower()}%"
        conditions.append("(LOWER(cve_id) LIKE ? OR LOWER(product_category) LIKE ? OR LOWER(description) LIKE ?)")
        params.extend([pattern, pattern, pattern])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT * FROM vulnerabilities
        {where_clause}
        ORDER BY priority_score DESC, cvss_score DESC
    """
    cursor.execute(query, params)
    vulns = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({"success": True, "count": len(vulns), "data": vulns})

@vulnerabilities_bp.route("/<cve_id>", methods=["GET"])
def get_vulnerability(cve_id):
    """Retrieve a single vulnerability record with contextual prioritization."""
    clean_cve = sanitize_input(cve_id)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM vulnerabilities WHERE LOWER(cve_id) = LOWER(?)", (clean_cve,))
    vuln = cursor.fetchone()
    conn.close()

    if not vuln:
        return jsonify({"success": False, "error": f"Vulnerability '{clean_cve}' not found."}), 404

    vuln_dict = dict(vuln)
    # Include dynamic contextual calculation
    vuln_dict["contextual_evaluation"] = calculate_vulnerability_priority(
        cvss_score=vuln_dict["cvss_score"],
        asset_criticality="HIGH",
        internet_exposed=True,
        exploitation_status=vuln_dict.get("exploitation_status_demo", ""),
        patch_available=vuln_dict.get("patch_available", "YES")
    )

    return jsonify({"success": True, "data": vuln_dict})

@vulnerabilities_bp.route("/prioritize", methods=["POST"])
def evaluate_prioritization():
    """Dynamically calculate contextual patching priority based on environment factors."""
    payload = request.get_json()
    if not payload or "cvss_score" not in payload:
        return jsonify({"success": False, "error": "Field 'cvss_score' is required."}), 400

    try:
        cvss = float(payload["cvss_score"])
    except ValueError:
        return jsonify({"success": False, "error": "'cvss_score' must be a valid float (0.0 to 10.0)."}), 400

    crit = sanitize_input(payload.get("asset_criticality", "HIGH"))
    exposed = bool(payload.get("internet_exposed", True))
    exploit_status = sanitize_input(payload.get("exploitation_status", "Active In-The-Wild Exploitation Known"))
    patch_avail = sanitize_input(payload.get("patch_available", "YES"))

    result = calculate_vulnerability_priority(
        cvss_score=cvss,
        asset_criticality=crit,
        internet_exposed=exposed,
        exploitation_status=exploit_status,
        patch_available=patch_avail
    )
    return jsonify({"success": True, "data": result})
