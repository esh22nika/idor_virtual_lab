"""
Flask Application Factory for the IDOR Virtual Lab.
Configures session security, initializes SQLite database and seed data,
and registers blueprints for authentication and educational lab exercises.
"""

import os
from flask import Flask, session, jsonify, render_template
from app.database import init_app, init_db, get_db_path
from app.seed import seed_database


def create_app(test_config=None):
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    # Determine default instance path and ensure it exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    db_default_path = os.path.join(app.instance_path, "idor_lab.sqlite")

    # Detect if running in cloud production environments like Render
    is_render = bool(os.environ.get("RENDER"))
    cookie_secure_default = "True" if is_render else "False"

    # Safe defaults
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "idor-virtual-lab-insecure-educational-key-2026"),
        DATABASE=os.environ.get("DATABASE_PATH", db_default_path),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", cookie_secure_default).lower() in ("true", "1"),
        LAB_MODE=os.environ.get("LAB_MODE", "secure").lower(),
    )

    if test_config is not None:
        app.config.from_mapping(test_config)

    # Enable ProxyFix when running behind a cloud reverse proxy (Render, Nginx)
    if is_render or os.environ.get("USE_PROXY_FIX", "False").lower() in ("true", "1"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Initialize database teardown
    init_app(app)

    # Auto-initialize and seed database schema and test accounts
    with app.app_context():
        init_db(app)
        seed_database()

    # Register Blueprints
    from app.auth import auth_bp
    from app.lab_routes import lab_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(lab_bp)

    # Global template context processor
    @app.context_processor
    def inject_global_template_context():
        from app.security import get_current_lab_mode, generate_csrf_token
        user_info = None
        if "user_id" in session:
            user_info = {
                "id": session.get("user_id"),
                "username": session.get("username"),
                "full_name": session.get("full_name"),
                "role": session.get("role"),
            }
        return {
            "current_user": user_info,
            "current_mode": get_current_lab_mode(),
            "csrf_token": generate_csrf_token() if "user_id" in session else "",
        }

    # Error Handlers
    @app.errorhandler(400)
    def bad_request_error(e):
        return jsonify({"error": "Bad Request", "message": str(e)}), 400

    @app.errorhandler(403)
    def forbidden_error(e):
        return jsonify({"error": "Forbidden", "message": "Access denied."}), 403

    @app.errorhandler(404)
    def not_found_error(e):
        return jsonify({"error": "Not Found", "message": "The requested resource was not found."}), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        # Do not expose stack traces to clients
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500

    return app
