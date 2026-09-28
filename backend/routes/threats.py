"""
Threat Intelligence REST API Routes
Author: Defensive Cybersecurity Engineering Team
"""

from flask import Blueprint, request, jsonify
from backend.services.threat_service import (
    get_threats, get_threat_by_id, create_threat, update_threat, add_analyst_note
)
from backend.services.correlation_engine import correlate_threats
from backend.utils.helpers import sanitize_input, format_api_response

threats_bp = Blueprint("threats", __name__, url_prefix="/api/threats")

@threats_bp.route("", methods=["GET"])
def list_threats():
    """Retrieve paginated, filtered, and sorted threats."""
    category = request.args.get("category")
    severity = request.args.get("severity")
    indicator_type = request.args.get("indicator_type")
    status = request.args.get("status")
    search = request.args.get("search")
    sort_by = request.args.get("sort_by", "last_seen")
    order = request.args.get("order", "desc")
    
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(100, max(5, int(request.args.get("page_size", 25))))
        min_risk = int(request.args.get("min_risk")) if request.args.get("min_risk") else None
        max_risk = int(request.args.get("max_risk")) if request.args.get("max_risk") else None
        min_conf = int(request.args.get("min_confidence")) if request.args.get("min_confidence") else None
    except ValueError:
        return jsonify({"success": False, "error": "Invalid numeric parameter for page, risk, or confidence."}), 400

    data = get_threats(
        category=category,
        severity=severity,
        indicator_type=indicator_type,
        status=status,
        min_risk=min_risk,
        max_risk=max_risk,
        min_confidence=min_conf,
        search=search,
        sort_by=sort_by,
        order=order,
        page=page,
        page_size=page_size
    )
    return jsonify({"success": True, "data": data})

@threats_bp.route("/<threat_id>", methods=["GET"])
def get_threat(threat_id):
    """Retrieve complete details for a single threat."""
    clean_id = sanitize_input(threat_id)
    threat = get_threat_by_id(clean_id)
    if not threat:
        return jsonify({"success": False, "error": f"Threat '{clean_id}' not found."}), 404
    return jsonify({"success": True, "data": threat})

@threats_bp.route("", methods=["POST"])
def add_threat():
    """Create a new threat record."""
    payload = request.get_json()
    if not payload:
        return jsonify({"success": False, "error": "Missing JSON request body."}), 400

    # Basic validation
    if not payload.get("threat_name") or not payload.get("category"):
        return jsonify({"success": False, "error": "Fields 'threat_name' and 'category' are required."}), 400

    sanitized = {k: sanitize_input(v) if isinstance(v, str) else v for k, v in payload.items()}
    result = create_threat(sanitized)
    return jsonify({"success": True, "data": result}), 201

@threats_bp.route("/<threat_id>", methods=["PUT"])
def modify_threat(threat_id):
    """Update fields on an existing threat."""
    clean_id = sanitize_input(threat_id)
    payload = request.get_json()
    if not payload:
        return jsonify({"success": False, "error": "Missing JSON request body."}), 400

    sanitized = {k: sanitize_input(v) if isinstance(v, str) else v for k, v in payload.items()}
    result = update_threat(clean_id, sanitized)
    if not result.get("success"):
        return jsonify({"success": False, "error": result.get("error", "Update failed.")}), 400
    return jsonify({"success": True, "data": result})

@threats_bp.route("/<threat_id>/notes", methods=["POST"])
def post_note(threat_id):
    """Append a SOC analyst investigation note to a threat."""
    clean_id = sanitize_input(threat_id)
    payload = request.get_json()
    if not payload or not payload.get("note"):
        return jsonify({"success": False, "error": "Field 'note' is required."}), 400

    analyst = sanitize_input(payload.get("analyst_name", "SOC Analyst"))
    note = sanitize_input(payload["note"])
    result = add_analyst_note(clean_id, analyst, note)
    return jsonify({"success": True, "data": result}), 201

@threats_bp.route("/<threat_id>/correlation", methods=["GET"])
def get_correlation(threat_id):
    """Retrieve correlated threat cluster and event timeline."""
    clean_id = sanitize_input(threat_id)
    cluster = correlate_threats(clean_id)
    return jsonify({"success": True, "data": cluster})
