"""
Indicator Validation & Search REST API Routes
Author: Defensive Cybersecurity Engineering Team
"""

from flask import Blueprint, request, jsonify
from backend.services.ioc_validator import validate_indicator
from backend.services.enrichment_engine import enrich_indicator
from backend.utils.helpers import sanitize_input

indicators_bp = Blueprint("indicators", __name__, url_prefix="/api/indicators")

@indicators_bp.route("/search", methods=["GET"])
def search_indicator():
    """
    Search and enrich an indicator against local synthetic threat intelligence.
    DEFENSIVE RULE: Performs database lookups only; never initiates outbound network connections.
    """
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"success": False, "error": "Query parameter 'q' is required."}), 400

    enriched = enrich_indicator(query)
    return jsonify({"success": True, "data": enriched})

@indicators_bp.route("/validate", methods=["POST"])
def validate_ioc():
    """
    Validate the syntactic format of an indicator (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, CVE).
    Confirms syntax correctness only, not malicious reputation.
    """
    payload = request.get_json()
    if not payload or not payload.get("indicator"):
        return jsonify({"success": False, "error": "Field 'indicator' is required in request body."}), 400

    raw_indicator = payload["indicator"]
    result = validate_indicator(raw_indicator)
    return jsonify({"success": True, "data": result})
