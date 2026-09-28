"""
Alert Management REST API Routes
Author: Defensive Cybersecurity Engineering Team
"""

from flask import Blueprint, request, jsonify
from backend.services.alert_engine import get_alerts, update_alert_status, generate_threat_alert
from backend.utils.helpers import sanitize_input

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")

@alerts_bp.route("", methods=["GET"])
def list_alerts():
    """Retrieve security alerts with optional status filtering."""
    status = request.args.get("status")
    limit = min(100, max(5, int(request.args.get("limit", 50))))
    alerts = get_alerts(status_filter=status, limit=limit)
    return jsonify({"success": True, "data": alerts})

@alerts_bp.route("/<alert_id>/status", methods=["PUT"])
def set_status(alert_id):
    """Transition alert triage status (NEW, INVESTIGATING, MONITORING, RESOLVED, FALSE_POSITIVE)."""
    clean_id = sanitize_input(alert_id)
    payload = request.get_json()
    if not payload or not payload.get("status"):
        return jsonify({"success": False, "error": "Field 'status' is required in request body."}), 400

    new_status = sanitize_input(payload["status"])
    note = sanitize_input(payload.get("note", "")) if payload.get("note") else None

    result = update_alert_status(clean_id, new_status, note)
    if not result.get("success"):
        return jsonify({"success": False, "error": result.get("error")}), 400

    return jsonify({"success": True, "data": result})

@alerts_bp.route("", methods=["POST"])
def create_manual_alert():
    """Manually dispatch a threat alert into the SOC queue."""
    payload = request.get_json()
    if not payload or not payload.get("threat_id"):
        return jsonify({"success": False, "error": "Field 'threat_id' is required."}), 400

    result = generate_threat_alert(
        threat_id=sanitize_input(payload["threat_id"]),
        threat_name=sanitize_input(payload.get("threat_name", "Manual Alert")),
        category=sanitize_input(payload.get("category", "NETWORK THREATS")),
        severity=sanitize_input(payload.get("severity", "HIGH")),
        risk_score=int(payload.get("risk_score", 75)),
        confidence_score=int(payload.get("confidence_score", 80)),
        custom_desc=sanitize_input(payload.get("description", ""))
    )
    return jsonify({"success": True, "data": result}), 201
