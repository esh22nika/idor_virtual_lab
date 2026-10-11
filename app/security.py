"""
Security controls, CSRF utilities, and access control engines for the IDOR Virtual Lab.
Provides explicit separation between vulnerable and secure object-level authorization paths.
"""

import os
import hmac
import secrets
from functools import wraps
from flask import session, request, abort, jsonify, g, current_app
from app.database import get_db


# ---------------------------------------------------------------------------
# CSRF Protection Utilities
# ---------------------------------------------------------------------------

def generate_csrf_token():
    """Generate or retrieve a CSRF token tied to the current session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf():
    """
    Validate the CSRF token on state-changing HTTP requests.
    Inspects X-CSRF-Token header or csrf_token form/JSON field.
    """
    # Safe methods do not require CSRF token
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True

    expected = session.get("_csrf_token")
    if not expected:
        return False

    received = (
        request.headers.get("X-CSRF-Token")
        or request.form.get("csrf_token")
        or (request.is_json and request.get_json(silent=True) and request.get_json(silent=True).get("csrf_token"))
    )

    if not received or not hmac.compare_digest(expected, received):
        return False
    return True


def csrf_protect(f):
    """Decorator to enforce CSRF validation on a view function."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not validate_csrf():
            return (
                jsonify({
                    "error": "CSRF validation failed",
                    "message": "Invalid or missing CSRF token. Please refresh and try again.",
                }),
                400,
            )
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Lab Mode Configuration & Retrieval
# ---------------------------------------------------------------------------

def get_current_lab_mode():
    """
    Determine the current operating mode ('vulnerable' or 'secure').
    Evaluates session override (if educational switching enabled) or app config.
    Default launch configuration is always 'secure'.
    """
    # Session-level mode override for the student lab session if configured
    if "lab_mode" in session:
        mode = session["lab_mode"]
        if mode in ("vulnerable", "secure"):
            return mode

    # Application-level configuration default
    if current_app:
        return current_app.config.get("LAB_MODE", "secure").lower()

    return os.environ.get("LAB_MODE", "secure").lower()


def set_current_lab_mode(mode):
    """
    Switch the current educational lab mode.
    Validated to only accept 'vulnerable' or 'secure'.
    """
    if mode not in ("vulnerable", "secure"):
        raise ValueError("Invalid lab mode. Allowed modes are 'vulnerable' and 'secure'.")
    session["lab_mode"] = mode
    return mode


# ---------------------------------------------------------------------------
# Document Access Control Implementations
# ---------------------------------------------------------------------------

def get_document_vulnerable(doc_id):
    """
    VULNERABLE IMPLEMENTATION (Mode A):
    Retrieves the document solely by its identifier without checking whether
    the authenticated user owns it.
    
    This deliberately omits the ownership verification (CWE-634).
    """
    db = get_db()
    # Direct database lookup using user-supplied ID alone
    doc = db.execute(
        """
        SELECT d.id, d.owner_id, d.title, d.content, d.classification, d.created_at,
               u.username as owner_username, u.full_name as owner_name
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        WHERE d.id = ?
        """,
        (doc_id,),
    ).fetchone()

    return doc


def get_document_secure(doc_id, user_id):
    """
    SECURE IMPLEMENTATION (Mode B):
    Enforces server-side object-level authorization.
    Verifies that the requested document belongs to the authenticated user.
    
    Returns:
        (doc, status_code, error_message)
        - If document exists and belongs to user: (doc, 200, None)
        - If document exists but belongs to someone else: (None, 403, "Forbidden")
        - If document does not exist: (None, 404, "Not Found")
    """
    db = get_db()

    # 1. Look up the document to determine existence and ownership
    doc = db.execute(
        """
        SELECT d.id, d.owner_id, d.title, d.content, d.classification, d.created_at,
               u.username as owner_username, u.full_name as owner_name
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        WHERE d.id = ?
        """,
        (doc_id,),
    ).fetchone()

    if not doc:
        return None, 404, "Document not found."

    # 2. Strict authorization check: owner must match authenticated user_id
    if doc["owner_id"] != user_id:
        # Document belongs to someone else -> Access Denied (HTTP 403)
        return None, 403, "Access denied: you do not have permission to view this document."

    return doc, 200, None


def update_document_secure(doc_id, user_id, title, content):
    """
    Secure document update ensuring only the owner can modify their resource.
    """
    db = get_db()
    # Check ownership first
    doc = db.execute("SELECT owner_id FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        return False, 404, "Document not found."
    if doc["owner_id"] != user_id:
        return False, 403, "Access denied: you cannot modify documents you do not own."

    db.execute(
        """
        UPDATE documents
        SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND owner_id = ?
        """,
        (title, content, doc_id, user_id),
    )
    db.commit()
    return True, 200, "Document updated successfully."


def update_document_vulnerable(doc_id, title, content):
    """
    Vulnerable document update demonstrating unauthorized modification.
    """
    db = get_db()
    doc = db.execute("SELECT id FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        return False, 404, "Document not found."

    db.execute(
        """
        UPDATE documents
        SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (title, content, doc_id),
    )
    db.commit()
    return True, 200, "Document updated (Vulnerable Mode: no ownership checked)."


def log_lab_action(user_id, username, endpoint, method, target_id, lab_mode, status_code, is_cross_user=0):
    """Log an access attempt for telemetry and lab pass/fail validation."""
    try:
        db = get_db()
        db.execute(
            """
            INSERT INTO lab_audit_logs (user_id, username, endpoint, method, target_id, lab_mode, status_code, is_cross_user)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, endpoint, method, str(target_id), lab_mode, status_code, 1 if is_cross_user else 0),
        )
        db.commit()
    except Exception:
        # Non-critical telemetry failure
        pass
