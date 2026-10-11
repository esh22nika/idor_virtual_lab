"""
Authentication and session management blueprint for the IDOR Virtual Lab.
Provides user login, logout, session verification, and current identity endpoints.
"""

from functools import wraps
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
)
from werkzeug.security import check_password_hash
from app.database import get_db
from app.security import generate_csrf_token, validate_csrf, get_current_lab_mode

auth_bp = Blueprint("auth", __name__)


def login_required(f):
    """Decorator requiring an active authenticated session for route access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            # If the request expects JSON, return a 401 response
            if request.path.startswith("/api/"):
                return (
                    jsonify({
                        "error": "Unauthorized",
                        "message": "Authentication required. Please log in first.",
                    }),
                    401,
                )
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle user login via standard form submission or asynchronous JSON request."""
    # Already logged in? Redirect to dashboard
    if "user_id" in session and request.method == "GET":
        return redirect(url_for("lab.dashboard"))

    if request.method == "POST":
        # Extract credentials
        if request.is_json:
            data = request.get_json(silent=True) or {}
            username = data.get("username", "").strip()
            password = data.get("password", "")
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

        error = None
        if not username or not password:
            error = "Both username and password are required."
        else:
            db = get_db()
            user = db.execute(
                "SELECT id, username, password_hash, full_name, role FROM users WHERE username = ?",
                (username.lower(),),
            ).fetchone()

            # If database was unseeded, automatically seed and retry
            if user is None and username.lower() in ("alice", "bob"):
                from app.seed import seed_database
                seed_database(db)
                user = db.execute(
                    "SELECT id, username, password_hash, full_name, role FROM users WHERE username = ?",
                    (username.lower(),),
                ).fetchone()

            if user is None:
                error = f"User '{username}' not found. The seeded test accounts are 'alice' and 'bob'."
            elif not (check_password_hash(user["password_hash"], password) or check_password_hash(user["password_hash"], password.strip())):
                error = f"Incorrect password for '{username}'. The password for alice is: AliceLab123! (case-sensitive)."

        if error is None:
            # Establish clean authenticated session
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            token = generate_csrf_token()

            if request.is_json:
                return jsonify({
                    "success": True,
                    "message": f"Welcome back, {user['username']}!",
                    "user": {
                        "id": user["id"],
                        "username": user["username"],
                        "full_name": user["full_name"],
                        "role": user["role"],
                    },
                    "csrf_token": token,
                    "redirect_url": url_for("lab.dashboard"),
                })
            return redirect(request.args.get("next") or url_for("lab.dashboard"))

        # Authentication failed
        if request.is_json:
            return jsonify({"error": "Authentication failed", "message": error}), 401

        flash(error, "danger")

    csrf_token = generate_csrf_token()
    return render_template(
        "login.html",
        csrf_token=csrf_token,
        lab_mode=get_current_lab_mode(),
    )


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    """Invalidate the session and log the user out."""
    session.clear()
    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({"success": True, "message": "Successfully logged out."})
    return redirect(url_for("auth.login"))


@auth_bp.route("/api/me", methods=["GET"])
@login_required
def get_current_user():
    """Return identity and status of the currently authenticated user."""
    return jsonify({
        "authenticated": True,
        "user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "full_name": session.get("full_name"),
            "role": session.get("role"),
        },
        "lab_mode": get_current_lab_mode(),
        "csrf_token": generate_csrf_token(),
    })
