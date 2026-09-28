"""
Cybersecurity Awareness & Threat Intelligence Dashboard
Main Flask Application Server
Author: Defensive Cybersecurity Engineering Team
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, send_from_directory, jsonify
from backend.models.database import init_db, seed_database_if_empty
from backend.routes.threats import threats_bp
from backend.routes.indicators import indicators_bp
from backend.routes.dashboard import dashboard_bp
from backend.routes.alerts import alerts_bp
from backend.routes.vulnerabilities import vulnerabilities_bp
from backend.routes.awareness import awareness_bp

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

def create_app(test_config=None):
    """Application factory for the Flask backend."""
    app = Flask(__name__, static_folder=None)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cybersecurity-defensive-lab-2026")
    app.config["JSON_SORT_KEYS"] = False

    if test_config:
        app.config.update(test_config)

    # Initialize Database & Seed data if empty
    with app.app_context():
        init_db()
        seed_database_if_empty()

    # Register API Blueprints
    app.register_blueprint(threats_bp)
    app.register_blueprint(indicators_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(awareness_bp)

    # Healthcheck Endpoint
    @app.route("/api/health", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "healthy",
            "service": "Cybersecurity Awareness & Threat Intelligence Dashboard",
            "version": "1.0.0",
            "mode": "Defensive Analysis & Education"
        })

    # Serve Frontend Static Assets (CSS, JS, Images)
    @app.route("/css/<path:filename>")
    def serve_css(filename):
        return send_from_directory(os.path.join(FRONTEND_DIR, "css"), filename)

    @app.route("/js/<path:filename>")
    def serve_js(filename):
        return send_from_directory(os.path.join(FRONTEND_DIR, "js"), filename)

    # Serve Frontend HTML Pages
    @app.route("/")
    @app.route("/index.html")
    def serve_index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/threat-dashboard")
    @app.route("/threat-dashboard.html")
    def serve_threat_dashboard():
        return send_from_directory(FRONTEND_DIR, "threat-dashboard.html")

    @app.route("/threat-details")
    @app.route("/threat-details.html")
    def serve_threat_details():
        return send_from_directory(FRONTEND_DIR, "threat-details.html")

    @app.route("/awareness")
    @app.route("/awareness.html")
    def serve_awareness():
        return send_from_directory(FRONTEND_DIR, "awareness.html")

    @app.route("/quiz")
    @app.route("/quiz.html")
    def serve_quiz():
        return send_from_directory(FRONTEND_DIR, "quiz.html")

    # Global Error Handlers
    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({"success": False, "error": "Endpoint or resource not found."}), 404

    @app.errorhandler(500)
    def handle_server_error(e):
        return jsonify({"success": False, "error": "Internal server error."}), 500

    return app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    app = create_app()
    print(f"\n========================================================")
    print(f" CYBERSECURITY AWARENESS & THREAT INTELLIGENCE DASHBOARD")
    print(f" Defensive SOC Platform & Training Environment")
    print(f" Server running at: http://{host}:{port}/")
    print(f"========================================================\n")
    app.run(host=host, port=port, debug=True)
