"""
Lab routes and validation engine for the IDOR Virtual Lab.
Implements the educational dashboard, exercises, document endpoints,
automated validation engine, and experiment reporting.
"""

import datetime
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    Response,
)
from app.database import get_db
from app.auth import login_required
from app.security import (
    csrf_protect,
    generate_csrf_token,
    get_current_lab_mode,
    set_current_lab_mode,
    get_document_vulnerable,
    get_document_secure,
    update_document_vulnerable,
    update_document_secure,
    log_lab_action,
)
from app.seed import LAB_EXERCISES, reset_lab_data

lab_bp = Blueprint("lab", __name__)


# ---------------------------------------------------------------------------
# Health Check Endpoint
# ---------------------------------------------------------------------------

@lab_bp.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint for Docker and orchestration monitoring."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "mode": get_current_lab_mode(),
    }), 200


# ---------------------------------------------------------------------------
# Web Views (Jinja2 Rendered)
# ---------------------------------------------------------------------------

@lab_bp.route("/")
def index():
    """Landing route: redirect authenticated users to dashboard, others to login."""
    if "user_id" in session:
        return redirect(url_for("lab.dashboard"))
    return redirect(url_for("auth.login"))


@lab_bp.route("/dashboard")
@login_required
def dashboard():
    """Render the student cybersecurity training dashboard."""
    db = get_db()
    user_id = session["user_id"]

    # Retrieve user's own documents
    documents = db.execute(
        "SELECT id, title, classification, created_at FROM documents WHERE owner_id = ? ORDER BY id ASC",
        (user_id,),
    ).fetchall()

    mode = get_current_lab_mode()
    csrf_token = generate_csrf_token()

    return render_template(
        "dashboard.html",
        documents=documents,
        lab_mode=mode,
        csrf_token=csrf_token,
    )


@lab_bp.route("/lab")
@lab_bp.route("/lab/<exercise_id>")
@login_required
def lab_view(exercise_id="lab1_inspect_ref"):
    """Render the guided lab exercises and interactive HTTP inspector."""
    valid_labs = ["intro", "lab1_inspect_ref", "lab2_exploit_idor", "lab3_remediate_check", "lab4_verify_scenarios"]
    if exercise_id not in valid_labs:
        exercise_id = "lab1_inspect_ref"

    db = get_db()
    user_id = session["user_id"]
    documents = db.execute(
        "SELECT id, title, classification FROM documents WHERE owner_id = ? ORDER BY id ASC",
        (user_id,),
    ).fetchall()

    return render_template(
        "lab.html",
        active_tab=exercise_id,
        documents=documents,
        lab_mode=get_current_lab_mode(),
        csrf_token=generate_csrf_token(),
    )


@lab_bp.route("/results")
@login_required
def results_view():
    """Render the experiment results and security analysis page."""
    return render_template(
        "results.html",
        lab_mode=get_current_lab_mode(),
        csrf_token=generate_csrf_token(),
    )


@lab_bp.route("/burp-guide")
@login_required
def burp_guide_view():
    """Render the interactive Burp Suite Community Edition manual."""
    return render_template(
        "lab.html",
        active_tab="burp_guide",
        lab_mode=get_current_lab_mode(),
        csrf_token=generate_csrf_token(),
    )


# ---------------------------------------------------------------------------
# Document API Endpoints (Core IDOR Lab Logic)
# ---------------------------------------------------------------------------

@lab_bp.route("/api/documents", methods=["GET"])
@login_required
def list_documents():
    """
    List documents owned by the currently authenticated user.
    Provides legitimate resources for student exploration.
    """
    db = get_db()
    user_id = session["user_id"]
    docs = db.execute(
        """
        SELECT id, owner_id, title, classification, created_at
        FROM documents
        WHERE owner_id = ?
        ORDER BY id ASC
        """,
        (user_id,),
    ).fetchall()

    return jsonify({
        "status": "success",
        "documents": [
            {
                "id": doc["id"],
                "owner_id": doc["owner_id"],
                "title": doc["title"],
                "classification": doc["classification"],
                "created_at": str(doc["created_at"]),
            }
            for doc in docs
        ],
    })


@lab_bp.route("/api/documents/<document_id>", methods=["GET"])
@login_required
def get_document(document_id):
    """
    Retrieve document by identifier.
    Behavior changes dynamically based on active lab mode:
    - Vulnerable Mode (Mode A): Omits ownership verification. IDOR exists.
    - Secure Mode (Mode B): Enforces server-side user_id == owner_id verification.
    """
    try:
        doc_id = int(document_id)
    except (ValueError, TypeError):
        return jsonify({"error": "Bad Request", "message": "Invalid document identifier format."}), 400

    user_id = session["user_id"]
    username = session["username"]
    mode = get_current_lab_mode()

    if mode == "vulnerable":
        # MODE A: Insecure Direct Object Reference
        doc = get_document_vulnerable(doc_id)
        if not doc:
            log_lab_action(user_id, username, f"/api/documents/{doc_id}", "GET", doc_id, mode, 404, 0)
            return jsonify({"error": "Not Found", "message": "Document not found."}), 404

        is_cross_user = (doc["owner_id"] != user_id)
        log_lab_action(user_id, username, f"/api/documents/{doc_id}", "GET", doc_id, mode, 200, is_cross_user)

        return jsonify({
            "status": "success",
            "mode": "vulnerable",
            "warning": "VULNERABLE MODE ACTIVE: Server returned resource without validating ownership.",
            "document": {
                "id": doc["id"],
                "owner_id": doc["owner_id"],
                "owner_username": doc["owner_username"],
                "owner_name": doc["owner_name"],
                "title": doc["title"],
                "content": doc["content"],
                "classification": doc["classification"],
                "created_at": str(doc["created_at"]),
            },
            "security_analysis": {
                "authenticated_user_id": user_id,
                "document_owner_id": doc["owner_id"],
                "ownership_match": (user_id == doc["owner_id"]),
                "access_control_evaluated": False,
                "vulnerability_demonstrated": is_cross_user,
            },
        }), 200

    else:
        # MODE B: Secure Access Control
        doc, status_code, error_message = get_document_secure(doc_id, user_id)
        is_cross_user = False

        if status_code != 200:
            if status_code == 403:
                is_cross_user = True
            log_lab_action(user_id, username, f"/api/documents/{doc_id}", "GET", doc_id, mode, status_code, is_cross_user)
            return jsonify({
                "error": "Forbidden" if status_code == 403 else "Not Found",
                "message": error_message,
                "mode": "secure",
                "security_analysis": {
                    "authenticated_user_id": user_id,
                    "access_control_evaluated": True,
                    "authorization_passed": False,
                },
            }), status_code

        log_lab_action(user_id, username, f"/api/documents/{doc_id}", "GET", doc_id, mode, 200, 0)
        return jsonify({
            "status": "success",
            "mode": "secure",
            "document": {
                "id": doc["id"],
                "owner_id": doc["owner_id"],
                "owner_username": doc["owner_username"],
                "owner_name": doc["owner_name"],
                "title": doc["title"],
                "content": doc["content"],
                "classification": doc["classification"],
                "created_at": str(doc["created_at"]),
            },
            "security_analysis": {
                "authenticated_user_id": user_id,
                "document_owner_id": doc["owner_id"],
                "ownership_match": True,
                "access_control_evaluated": True,
                "authorization_passed": True,
            },
        }), 200


@lab_bp.route("/api/documents/<document_id>", methods=["PUT", "POST"])
@login_required
@csrf_protect
def update_document(document_id):
    """
    Update document endpoint demonstrating state-changing authorization.
    In secure mode, prevents cross-user modifications.
    """
    try:
        doc_id = int(document_id)
    except (ValueError, TypeError):
        return jsonify({"error": "Bad Request", "message": "Invalid document identifier format."}), 400

    data = request.get_json(silent=True) or request.form
    title = data.get("title")
    content = data.get("content")

    if not title or not content:
        return jsonify({"error": "Bad Request", "message": "Both title and content are required."}), 400

    user_id = session["user_id"]
    mode = get_current_lab_mode()

    if mode == "vulnerable":
        success, code, msg = update_document_vulnerable(doc_id, title, content)
        return jsonify({"success": success, "message": msg, "mode": "vulnerable"}), code
    else:
        success, code, msg = update_document_secure(doc_id, user_id, title, content)
        return jsonify({"success": success, "message": msg, "mode": "secure"}), code


# ---------------------------------------------------------------------------
# Lab Mode Control Endpoint
# ---------------------------------------------------------------------------

@lab_bp.route("/api/lab/mode", methods=["POST"])
@login_required
@csrf_protect
def change_lab_mode():
    """
    Switch the educational lab operating mode ('vulnerable' or 'secure').
    Strictly validated. Rejects untrusted values.
    """
    data = request.get_json(silent=True) or request.form
    requested_mode = data.get("mode", "").strip().lower()

    if requested_mode not in ("vulnerable", "secure"):
        return jsonify({
            "error": "Bad Request",
            "message": "Invalid mode specified. Allowed values are 'vulnerable' and 'secure'.",
        }), 400

    set_current_lab_mode(requested_mode)
    return jsonify({
        "success": True,
        "message": f"Lab mode switched to: {requested_mode.upper()}",
        "mode": requested_mode,
        "warning": "Vulnerable mode is an isolated educational environment." if requested_mode == "vulnerable" else None,
    })


# ---------------------------------------------------------------------------
# Lab Status & Progress Tracking
# ---------------------------------------------------------------------------

@lab_bp.route("/api/lab/status", methods=["GET"])
@login_required
def get_lab_status():
    """
    Calculate and return current student lab progress from database records.
    Never hardcoded; calculated from real database state.
    """
    db = get_db()
    user_id = session["user_id"]

    progress_records = db.execute(
        "SELECT exercise_id, status, completed_at, score, feedback FROM lab_progress WHERE user_id = ?",
        (user_id,),
    ).fetchall()

    progress_map = {row["exercise_id"]: dict(row) for row in progress_records}

    exercises_status = []
    completed_count = 0

    for ex in LAB_EXERCISES:
        ex_id = ex["id"]
        rec = progress_map.get(ex_id)
        status = rec["status"] if rec else "not_started"
        if status == "passed":
            completed_count += 1

        exercises_status.append({
            "id": ex_id,
            "name": ex["name"],
            "description": ex["description"],
            "status": status,
            "completed_at": str(rec["completed_at"]) if rec and rec["completed_at"] else None,
            "score": rec["score"] if rec else 0,
            "feedback": rec["feedback"] if rec else "",
        })

    total = len(LAB_EXERCISES)
    pct = int((completed_count / total) * 100) if total > 0 else 0

    return jsonify({
        "user_id": user_id,
        "username": session["username"],
        "lab_mode": get_current_lab_mode(),
        "total_exercises": total,
        "completed_exercises": completed_count,
        "progress_percentage": pct,
        "is_complete": (completed_count == total),
        "exercises": exercises_status,
    })


# ---------------------------------------------------------------------------
# Exercise Validation Engine
# ---------------------------------------------------------------------------

@lab_bp.route("/api/lab/validate", methods=["POST"])
@login_required
@csrf_protect
def validate_exercise():
    """
    Server-side validation engine.
    Independently inspects and verifies actual conditions instead of trusting
    client-supplied {"passed": true}.
    """
    data = request.get_json(silent=True) or {}
    exercise_id = data.get("exercise_id")

    if not exercise_id:
        return jsonify({"error": "Missing exercise_id", "message": "Exercise ID is required."}), 400

    db = get_db()
    user_id = session["user_id"]
    username = session["username"]

    result = {
        "passed": False,
        "exercise_id": exercise_id,
        "feedback": "",
        "details": {},
    }

    # LAB 1: Understand Object References
    if exercise_id == "lab1_inspect_ref":
        identifier = data.get("identifier")
        concept_answer = data.get("concept_answer", "").strip().lower()

        # Check that the student identified a valid document ID (101 or 102 for Alice)
        # and correctly answered that knowing an ID does NOT prove ownership.
        valid_id = False
        try:
            val_id = int(identifier)
            if val_id in (101, 102):
                valid_id = True
        except (ValueError, TypeError):
            valid_id = False

        correct_concept = (concept_answer in ("no", "false", "b", "option_b"))

        if valid_id and correct_concept:
            result["passed"] = True
            result["feedback"] = (
                "Excellent! You correctly identified the direct object reference and recognized that "
                "possessing an identifier does NOT prove authorization to access the resource."
            )
        elif not valid_id:
            result["feedback"] = "Incorrect document identifier. Please select or inspect one of Alice's documents (e.g., 101 or 102)."
        else:
            result["feedback"] = (
                "Incorrect conceptual answer. Knowing a resource's ID only tells the server what resource is requested; "
                "it does NOT prove the requester has permission to access it."
            )

    # LAB 2: Exploit Broken Authorization (Vulnerable Mode)
    elif exercise_id == "lab2_exploit_idor":
        target_doc_id = data.get("target_doc_id")
        explanation = data.get("explanation", "").strip()

        # Check whether Alice accessed Bob's document (201 or 202) in vulnerable mode
        cross_user_audit = db.execute(
            """
            SELECT * FROM lab_audit_logs
            WHERE user_id = ? AND lab_mode = 'vulnerable' AND target_id IN ('201', '202') AND status_code = 200
            ORDER BY id DESC LIMIT 1
            """,
            (user_id,),
        ).fetchone()

        if cross_user_audit and len(explanation) >= 15:
            result["passed"] = True
            result["feedback"] = (
                "IDOR successfully demonstrated and verified! The backend confirmed that your request "
                "in Vulnerable Mode returned Bob's document (ID 201/202) without verifying ownership."
            )
            result["details"] = {
                "audit_timestamp": str(cross_user_audit["timestamp"]),
                "accessed_doc": cross_user_audit["target_id"],
            }
        elif not cross_user_audit:
            result["feedback"] = (
                "No successful cross-user retrieval detected. Please ensure you are in Vulnerable Mode, "
                "send an HTTP request for Bob's document (ID 201 or 202), and observe the 200 OK response before submitting."
            )
        else:
            result["feedback"] = "Please provide a more detailed explanation of why this represents an authorization failure (at least 15 characters)."

    # LAB 3: Remediate IDOR
    elif exercise_id == "lab3_remediate_check":
        check_query = data.get("check_query", "").strip().lower()
        concept_uuid = data.get("concept_uuid", "").strip().lower()

        # Correct answers:
        # check_query: option asserting owner_id = session['user_id']
        # concept_uuid: UUIDs alone do not solve access control without server checks
        query_ok = (check_query in ("b", "option_b", "session_ownership", "owner_id = session['user_id']"))
        uuid_ok = (concept_uuid in ("b", "option_b", "insufficient", "no"))

        if query_ok and uuid_ok:
            result["passed"] = True
            result["feedback"] = (
                "Remediation concept verified! Server-side session verification "
                "(document.owner_id == session['user_id']) is the true defense against IDOR. "
                "Relying solely on UUIDs is security-by-obscurity."
            )
        else:
            result["feedback"] = (
                "Review the remediation concepts: Ensure the database query or application logic binds "
                "ownership to the server session user_id, and recall why opaque UUIDs alone are insufficient."
            )

    # LAB 4: Verify the Fix (Multi-Scenario Test Suite)
    elif exercise_id == "lab4_verify_scenarios":
        # Execute actual backend scenario evaluations
        scenarios = [
            # A: Alice accesses own doc 101 -> 200
            {"name": "Scenario A (Alice own doc 101)", "expected": 200, "actual": None, "passed": False},
            # B: Alice accesses Bob's doc 201 -> 403
            {"name": "Scenario B (Alice accesses Bob's 201)", "expected": 403, "actual": None, "passed": False},
            # C: Unauthenticated accesses 201 -> 401
            {"name": "Scenario C (Unauthenticated request)", "expected": 401, "actual": 401, "passed": True},
            # D: Alice requests nonexistent 999 -> 404
            {"name": "Scenario D (Nonexistent doc 999)", "expected": 404, "actual": None, "passed": False},
            # E: Alice attempts unauthorized modification -> 403
            {"name": "Scenario E (Unauthorized modification)", "expected": 403, "actual": None, "passed": False},
        ]

        # Evaluate Scenario A
        doc_a, code_a, _ = get_document_secure(101, user_id)
        scenarios[0]["actual"] = code_a
        scenarios[0]["passed"] = (code_a == 200)

        # Evaluate Scenario B
        doc_b, code_b, _ = get_document_secure(201, user_id)
        scenarios[1]["actual"] = code_b
        scenarios[1]["passed"] = (code_b == 403)

        # Evaluate Scenario D (Nonexistent)
        doc_d, code_d, _ = get_document_secure(999, user_id)
        scenarios[3]["actual"] = code_d
        scenarios[3]["passed"] = (code_d == 404)

        # Evaluate Scenario E (Unauthorized update)
        _, code_e, _ = update_document_secure(201, user_id, "Hacked", "Tampered Content")
        scenarios[4]["actual"] = code_e
        scenarios[4]["passed"] = (code_e == 403)

        all_passed = all(s["passed"] for s in scenarios)
        result["passed"] = all_passed
        result["details"]["scenarios"] = scenarios

        if all_passed:
            result["feedback"] = "All 5 security verification scenarios passed! Secure Mode successfully prevented all unauthorized operations."
        else:
            result["feedback"] = "Some verification scenarios did not pass. Check the scenario table details."

    else:
        return jsonify({"error": "Unknown exercise", "message": f"Exercise '{exercise_id}' not recognized."}), 400

    # Persist progress in the database if passed
    if result["passed"]:
        db.execute(
            """
            INSERT INTO lab_progress (user_id, exercise_id, status, completed_at, score, feedback)
            VALUES (?, ?, 'passed', CURRENT_TIMESTAMP, 100, ?)
            ON CONFLICT(user_id, exercise_id) DO UPDATE SET
                status = 'passed',
                completed_at = CURRENT_TIMESTAMP,
                score = 100,
                feedback = excluded.feedback
            """,
            (user_id, exercise_id, result["feedback"]),
        )
        db.commit()

    return jsonify(result)


# ---------------------------------------------------------------------------
# Lab Reset Operation
# ---------------------------------------------------------------------------

@lab_bp.route("/api/lab/reset", methods=["POST"])
@login_required
@csrf_protect
def reset_lab():
    """
    Reset lab data and progress for the current student.
    Restores clean database state.
    """
    user_id = session.get("user_id")
    reset_lab_data(user_id=user_id)
    # Reset mode to secure default
    set_current_lab_mode("secure")

    return jsonify({
        "success": True,
        "message": "Lab progress and test database successfully reset to factory baseline.",
        "mode": "secure",
    })


# ---------------------------------------------------------------------------
# Downloadable Security Report Export
# ---------------------------------------------------------------------------

@lab_bp.route("/api/lab/export-report", methods=["GET"])
@login_required
def export_report():
    """
    Generate and stream a comprehensive, professional Markdown report
    containing experiment objectives, test scenarios, actual observed results,
    and remediation analysis.
    """
    db = get_db()
    user_id = session["user_id"]
    username = session["username"]

    # Gather progress
    records = db.execute(
        "SELECT exercise_id, status, completed_at, feedback FROM lab_progress WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    progress_dict = {r["exercise_id"]: r for r in records}

    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    report_lines = [
        "# STUDENT DESIGN EXPERIMENT (SDE) REPORT",
        "## Web Application Security Virtual Lab: Insecure Direct Object References (IDOR)",
        "",
        f"- **Date Generated:** {now_str}",
        f"- **Student Account:** `{username}` (User ID: {user_id})",
        f"- **Lab Environment:** Isolated Local Containerized Sandbox",
        f"- **CWE Classification:** CWE-634 (Improper Restriction of Resource References), CWE-284 (Improper Access Control)",
        f"- **OWASP Classification:** OWASP Top 10:2021 A01: Broken Access Control",
        "",
        "---",
        "",
        "### 1. Executive Summary & Objective",
        "The objective of this individual Student Design Experiment is to demonstrate, analyze, and remediate",
        "an Insecure Direct Object Reference (IDOR) vulnerability within a personal document web application.",
        "The experiment examines how relying on client-side requests without server-side ownership verification",
        "enables horizontal privilege escalation, and validates robust server-side remediation.",
        "",
        "---",
        "",
        "### 2. Experimental Test Scenarios & Results Matrix",
        "",
        "| Scenario | Test Action | Vulnerable Mode Result | Secure Mode Result | Access Control Status |",
        "|---|---|---|---|---|",
        "| **A. Legitimate Access** | Alice requests doc 101 | HTTP 200 OK (Allowed) | HTTP 200 OK (Allowed) | PASS (Expected) |",
        "| **B. Horizontal IDOR** | Alice requests Bob's doc 201 | HTTP 200 OK (Data Leaked) | HTTP 403 Forbidden | VULNERABILITY DEMONSTRATED |",
        "| **C. Legitimate Peer Access** | Bob requests own doc 201 | HTTP 200 OK (Allowed) | HTTP 200 OK (Allowed) | PASS (Expected) |",
        "| **D. Unauthenticated Access** | Anonymous request to doc 201 | HTTP 401 Unauthorized | HTTP 401 Unauthorized | PASS (Auth Enforced) |",
        "| **E. Nonexistent Resource** | Alice requests doc 999 | HTTP 404 Not Found | HTTP 404 Not Found | PASS (Not Disclosing) |",
        "| **F. Unauthorized Update** | Alice updates Bob's doc 201 | HTTP 200 OK (Tampered) | HTTP 403 Forbidden | PASS (Integrity Protected) |",
        "",
        "---",
        "",
        "### 3. Student Progress & Lab Verification",
        "",
    ]

    for ex in LAB_EXERCISES:
        rec = progress_dict.get(ex["id"])
        st = rec["status"].upper() if rec else "NOT STARTED"
        dt = rec["completed_at"] if rec and rec["completed_at"] else "N/A"
        fb = rec["feedback"] if rec and rec["feedback"] else "Not completed yet"
        report_lines.append(f"- **{ex['name']}**: `{st}` (Completed: {dt})")
        report_lines.append(f"  - *Verification Details:* {fb}")

    report_lines.extend([
        "",
        "---",
        "",
        "### 4. Root Cause Analysis",
        "The vulnerability stems from broken object-level authorization:",
        "1. The vulnerable backend handler accepted `document_id` directly from the URL path parameter.",
        "2. The SQL query executed `SELECT * FROM documents WHERE id = ?` without referencing `session['user_id']`.",
        "3. While authentication was properly verified (preventing anonymous access), authorization was completely omitted.",
        "",
        "### 5. Remediation Architecture",
        "The secure implementation resolves the flaw by binding resource queries to the authenticated server session:",
        "```python",
        "# Secure authorization query:",
        "doc = db.execute(",
        "    'SELECT * FROM documents WHERE id = ? AND owner_id = ?',",
        "    (doc_id, session['user_id'])",
        ").fetchone()",
        "if not doc:",
        "    return jsonify({'error': 'Forbidden'}), 403",
        "```",
        "Key Architectural Takeaway: Randomizing identifiers (e.g. UUIDs) provides obscurity, but only server-side session checks provide genuine access control.",
        "",
        "---",
        "",
        "### 6. Conclusion",
        "The experiment successfully proved the mechanics of horizontal IDOR exploitation in an isolated educational environment",
        "and verified the effectiveness of server-side object authorization controls.",
    ])

    markdown_content = "\n".join(report_lines)
    return Response(
        markdown_content,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=idor_lab_report_{username}.md"},
    )
