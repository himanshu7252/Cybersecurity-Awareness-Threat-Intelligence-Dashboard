"""
Security Awareness & Quiz Recommendation Engine
Author: Defensive Cybersecurity Engineering Team
Purpose: Calculates educational awareness scores, evaluates quiz responses,
         determines category competencies, and generates personalized learning paths.
"""

import os
import json
from typing import Dict, Any, List
from backend.models.database import get_db_connection

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODULES_PATH = os.path.join(BASE_DIR, "awareness", "modules.json")
QUIZ_PATH = os.path.join(BASE_DIR, "awareness", "quiz_questions.json")

# Module mapping by category for personalized recommendations
CATEGORY_MODULE_MAP = {
    "Phishing": {"module_id": "MOD-001", "title": "Phishing Awareness & Deceptive Communication"},
    "Passwords": {"module_id": "MOD-002", "title": "Password Security & Modern Passphrases"},
    "MFA": {"module_id": "MOD-003", "title": "Multi-Factor Authentication (MFA) & Phishing Resistance"},
    "Social Engineering": {"module_id": "MOD-004", "title": "Social Engineering & Pretexting Defenses"},
    "Safe Browsing": {"module_id": "MOD-005", "title": "Safe Web Browsing & Malicious Domain Awareness"},
    "Wi-Fi": {"module_id": "MOD-006", "title": "Secure Wi-Fi & Network Perimeter Defense"},
    "Software Updates": {"module_id": "MOD-007", "title": "Software Patching & Vulnerability Awareness"},
    "Ransomware": {"module_id": "MOD-008", "title": "Ransomware Defense & Extortion Awareness"},
    "Privacy": {"module_id": "MOD-010", "title": "Data Privacy, Classification & Leakage Prevention"},
    "Mobile Security": {"module_id": "MOD-011", "title": "Mobile Device Security & App Hygiene"},
    "Incident Reporting": {"module_id": "MOD-014", "title": "Incident Reporting & Timely Escalation"}
}

def get_awareness_modules() -> List[Dict[str, Any]]:
    """Retrieve all educational awareness modules."""
    if os.path.exists(MODULES_PATH):
        with open(MODULES_PATH, mode="r", encoding="utf-8") as f:
            return json.load(f)
    return []

def get_awareness_module_by_id(module_id: str) -> Dict[str, Any]:
    """Retrieve a single awareness module by ID."""
    modules = get_awareness_modules()
    for m in modules:
        if m.get("module_id") == module_id:
            return m
    return {}

def get_quiz_questions() -> List[Dict[str, Any]]:
    """Retrieve quiz questions (with options and explanations)."""
    if os.path.exists(QUIZ_PATH):
        with open(QUIZ_PATH, mode="r", encoding="utf-8") as f:
            return json.load(f)
    return []

def generate_learning_recommendations(category_scores: Dict[str, float]) -> List[Dict[str, Any]]:
    """
    Generate tailored learning module recommendations based on category quiz performance.
    Prioritizes categories scoring below 70%.
    """
    recommendations = []
    for cat, score in category_scores.items():
        mod_info = CATEGORY_MODULE_MAP.get(cat)
        if score < 60:
            rec = {
                "category": cat,
                "score_percent": score,
                "urgency": "High Priority",
                "recommendation": f"Score of {score}% indicates high knowledge gaps. Complete module '{mod_info['title'] if mod_info else cat}'.",
                "module_id": mod_info["module_id"] if mod_info else "MOD-001"
            }
            recommendations.append(rec)
        elif score < 80:
            rec = {
                "category": cat,
                "score_percent": score,
                "urgency": "Moderate Priority",
                "recommendation": f"Score of {score}%. Review key warning signs in '{mod_info['title'] if mod_info else cat}'.",
                "module_id": mod_info["module_id"] if mod_info else "MOD-001"
            }
            recommendations.append(rec)

    # Sort so lowest score comes first
    recommendations.sort(key=lambda x: x["score_percent"])
    return recommendations

def evaluate_quiz_submission(answers: Dict[str, str], user_id: str = "anonymous_student") -> Dict[str, Any]:
    """
    Evaluate user quiz responses, compute category breakdown, and produce learning recommendations.
    
    Args:
        answers (dict): Mapping of question id (str or int) to selected option letter ("A", "B", "C", "D").
        user_id (str): Optional identifier for analytics.
    """
    questions = get_quiz_questions()
    q_map = {str(q["id"]): q for q in questions}

    total_questions = len(questions)
    correct_count = 0
    detailed_results = []
    cat_stats = {}

    for q_id_str, q_obj in q_map.items():
        cat = q_obj["category"]
        if cat not in cat_stats:
            cat_stats[cat] = {"total": 0, "correct": 0}
        cat_stats[cat]["total"] += 1

        user_ans = answers.get(q_id_str, "").strip().upper()
        correct_ans = q_obj["correct_answer"].strip().upper()
        is_correct = (user_ans == correct_ans)

        if is_correct:
            correct_count += 1
            cat_stats[cat]["correct"] += 1

        detailed_results.append({
            "question_id": int(q_id_str),
            "category": cat,
            "question": q_obj["question"],
            "user_answer": user_ans,
            "correct_answer": correct_ans,
            "is_correct": is_correct,
            "explanation": q_obj["explanation"]
        })

    overall_score = int(round((correct_count / max(1, total_questions)) * 100))

    if overall_score >= 81:
        grade = "Strong Awareness"
    elif overall_score >= 61:
        grade = "Good Awareness"
    elif overall_score >= 41:
        grade = "Basic Awareness"
    else:
        grade = "Needs Improvement"

    category_scores = {}
    weak_areas = []
    for cat, stats in cat_stats.items():
        pct = int(round((stats["correct"] / max(1, stats["total"])) * 100))
        category_scores[cat] = pct
        if pct < 70:
            weak_areas.append(cat)

    recommendations = generate_learning_recommendations(category_scores)

    # Save to database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO quiz_results (
            anonymous_user_id_optional, overall_score, grade, category_scores,
            weak_areas, recommendations, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    """, (
        user_id,
        overall_score,
        grade,
        json.dumps(category_scores),
        json.dumps(weak_areas),
        json.dumps(recommendations)
    ))
    conn.commit()
    conn.close()

    return {
        "overall_score": overall_score,
        "grade": grade,
        "total_questions": total_questions,
        "correct_answers": correct_count,
        "category_scores": category_scores,
        "weak_areas": weak_areas,
        "recommendations": recommendations,
        "detailed_results": detailed_results,
        "disclaimer": (
            "Educational Evaluation Only: This score reflects defensive cybersecurity knowledge "
            "and does NOT represent employee fitness, performance, or operational competency."
        )
    }
