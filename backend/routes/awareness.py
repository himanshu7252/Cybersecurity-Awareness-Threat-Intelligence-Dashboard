"""
Cybersecurity Awareness Center REST API Routes
Author: Defensive Cybersecurity Engineering Team
"""

import json
from flask import Blueprint, request, jsonify
from backend.services.awareness_service import (
    get_awareness_modules, get_awareness_module_by_id,
    get_quiz_questions, evaluate_quiz_submission
)
from backend.models.database import get_db_connection
from backend.utils.helpers import sanitize_input

awareness_bp = Blueprint("awareness", __name__, url_prefix="/api")

@awareness_bp.route("/awareness/modules", methods=["GET"])
def list_modules():
    """Retrieve all educational awareness modules."""
    category = request.args.get("category")
    modules = get_awareness_modules()
    if category:
        modules = [m for m in modules if m.get("category", "").lower() == category.lower()]
    return jsonify({"success": True, "count": len(modules), "data": modules})

@awareness_bp.route("/awareness/modules/<module_id>", methods=["GET"])
def get_module(module_id):
    """Retrieve details for a specific awareness module."""
    clean_id = sanitize_input(module_id)
    mod = get_awareness_module_by_id(clean_id)
    if not mod:
        return jsonify({"success": False, "error": f"Module '{clean_id}' not found."}), 404
    return jsonify({"success": True, "data": mod})

@awareness_bp.route("/quiz", methods=["GET"])
def list_quiz_questions():
    """Retrieve all defensive security awareness quiz questions."""
    questions = get_quiz_questions()
    # Omit correct answers if client requested safe exam mode
    exam_mode = request.args.get("exam_mode", "false").lower() == "true"
    if exam_mode:
        sanitized = []
        for q in questions:
            copy_q = dict(q)
            copy_q.pop("correct_answer", None)
            copy_q.pop("explanation", None)
            sanitized.append(copy_q)
        return jsonify({"success": True, "count": len(sanitized), "data": sanitized})

    return jsonify({"success": True, "count": len(questions), "data": questions})

@awareness_bp.route("/quiz/submit", methods=["POST"])
def submit_quiz():
    """
    Evaluate user quiz responses and generate personalized awareness score and learning paths.
    """
    payload = request.get_json()
    if not payload or "answers" not in payload:
        return jsonify({"success": False, "error": "Field 'answers' is required in request body."}), 400

    answers = payload["answers"]
    user_id = sanitize_input(payload.get("user_id", "anonymous_student"))

    result = evaluate_quiz_submission(answers, user_id)
    return jsonify({"success": True, "data": result})

@awareness_bp.route("/quiz/history", methods=["GET"])
def quiz_history():
    """Retrieve past quiz results and trend history."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM quiz_results
        ORDER BY created_at DESC
        LIMIT 20
    """)
    rows = cursor.fetchall()
    conn.close()

    history = []
    for r in rows:
        d = dict(r)
        d["category_scores"] = json.loads(d["category_scores"])
        d["weak_areas"] = json.loads(d["weak_areas"])
        d["recommendations"] = json.loads(d["recommendations"])
        history.append(d)

    return jsonify({"success": True, "count": len(history), "data": history})
