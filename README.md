# Web Application Security Virtual Lab: Broken Access Control (IDOR)

> **Student Design Experiment (SDE) &bull; Web Application Security Course**  
> An interactive virtual laboratory for identifying, exploiting, and remediating Insecure Direct Object Reference (IDOR) / Broken Object-Level Authorization (BOLA) vulnerabilities.

[![Tests](https://img.shields.io/badge/pytest-24%20passed%20(100%25)-brightgreen)]()
[![OWASP](https://img.shields.io/badge/OWASP-A01%3A2021%20Broken%20Access%20Control-red)]()
[![CWE](https://img.shields.io/badge/CWE-634%20%2F%20284-orange)]()
[![License](https://img.shields.io/badge/license-MIT%20(Educational)-blue)]()

---

## 1. Project Overview

This project is a complete, containerized educational virtual laboratory designed to teach cybersecurity students how **Insecure Direct Object References (IDOR)** function in modern web applications. 

Rather than a static simulation, this lab contains a **fully functioning Flask and SQLite web application** featuring:
- Real server-side authentication and session handling with hashed credentials.
- A **dual-mode engine** providing an intentionally vulnerable endpoint (Mode A) and a remediated, secure endpoint (Mode B).
- An **Interactive HTTP Request/Response Inspector** that executes live asynchronous HTTP requests against the backend.
- Full compatibility with **PortSwigger Burp Suite Community Edition** for manual HTTP proxying and request replay.
- An **automated validation engine** with server-side progress tracking and fraud prevention.
- A downloadable, professional Markdown **experiment report generator**.

---

## 2. Problem Statement & Educational Concept

**Insecure Direct Object References (CWE-634 / OWASP Top 10 A01:2021)** occur when an application exposes a reference to an internal object (such as a database primary key in a URL) without performing server-side access control checks to verify that the authenticated client owns or is authorized to access that object.

The lab demonstrates this flaw through a **Personal Document Management System**:
- **Alice** (User ID 1) owns confidential documents `101` and `102`.
- **Bob** (User ID 2) owns confidential documents `201` and `202`.

In **Vulnerable Mode**, Alice can tamper with the URL parameter (`/api/documents/201`) and retrieve Bob's confidential research notes because the server queries by document identifier alone without checking ownership.

In **Secure Mode**, the server evaluates `owner_id == session['user_id']` on every request, rejecting Alice's unauthorized query with **HTTP 403 Forbidden**.

---

## 3. Technology Stack

- **Backend:** Python 3.11+, Flask 3.0+, SQLite3, Werkzeug password hashing.
- **Frontend:** HTML5, CSS3 (Dark Cybersecurity / SecOps theme), Vanilla JavaScript (Fetch API), Jinja2 templates.
- **Security Testing:** `pytest` (24 automated test cases), Flask test client, PortSwigger Burp Suite Community Edition.
- **Deployment:** Docker, Docker Compose, Gunicorn WSGI server, non-root container security profile.

---

## 4. Application Architecture

```
idor-virtual-lab/
├── app/
│   ├── __init__.py           # Application factory, session security, blueprints
│   ├── auth.py               # Authentication routes, session management, @login_required
│   ├── database.py           # SQLite connection management and lifecycle
│   ├── lab_routes.py         # Document API, mode toggle, validation engine, report export
│   ├── schema.sql            # Database schema for users, documents, progress, and audit
│   ├── security.py           # Access control logic, CSRF utilities, telemetry logging
│   ├── seed.py               # Seed data generator with hashed passwords
│   ├── static/
│   │   ├── css/style.css     # Cybersecurity training operations UI stylesheet
│   │   └── js/app.js         # Interactive HTTP inspector, validation engine client
│   └── templates/
│       ├── base.html         # Base layout with mode badge, user indicator, sidebar
│       ├── dashboard.html    # Progress overview, architectural diagrams, documents list
│       ├── lab.html          # Interactive guided exercises (Labs 1-4 & Burp guide)
│       ├── login.html        # Clean cybersecurity login with seeded credentials
│       └── results.html      # Test matrix, root cause analysis, report download
├── docs/
│   ├── burp-suite-guide.md   # Step-by-step Burp Suite Community Edition walkthrough
│   ├── security-analysis.md  # Academic paper on IDOR, BOLA, and remediation
│   ├── setup-guide.md        # Comprehensive deployment and troubleshooting guide
│   └── student-lab-manual.md # Step-by-step student experiment lab manual
├── tests/
│   ├── conftest.py           # Pytest fixtures and isolated database setup
│   ├── test_auth.py          # Authentication and session security tests
│   ├── test_idor_secure.py   # Secure Mode access control verification tests
│   ├── test_idor_vulnerable.py# Vulnerable Mode intentional flaw demonstration tests
│   └── test_lab_validation.py# Progress tracking and validation engine tests
├── .dockerignore
├── .env.example              # Environment variables template
├── .gitignore
├── compose.yaml              # Docker Compose configuration (localhost bound)
├── Dockerfile                # Multi-stage non-root runtime container
├── README.md                 # Project documentation and reproduction guide
└── requirements.txt          # Pinned Python dependencies
```

---

## 5. Seeded Lab Accounts

The application is seeded automatically with two test accounts:

| Username | Password | Full Name | Owned Documents |
|---|---|---|---|
| `alice` | `AliceLab123!` | Alice Cooper (Student Researcher) | `101`, `102` |
| `bob` | `BobLab123!` | Bob Martin (Peer Reviewer) | `201`, `202` |

> [!WARNING]
> These credentials are for this disposable local lab environment only. Passwords are stored in SQLite as cryptographic hashes (`scrypt:` / `pbkdf2:`) and never in plaintext.

---

## 6. Installation & Quickstart

### Method A: Docker Compose (Recommended)

1. **Clone repository and navigate to folder:**
   ```bash
   cd idor-virtual-lab
   ```

2. **Build and start the application:**
   ```bash
   docker compose up --build
   ```

3. **Access the web interface:**
   Navigate to `http://localhost:5000` in your web browser.

4. **Follow container logs:**
   ```bash
   docker compose logs -f
   ```

5. **Stop the container:**
   ```bash
   docker compose down
   ```

6. **Reset the disposable database:**
   ```bash
   docker compose down -v
   ```

---

### Method B: Native Python Setup

1. **Create and activate a virtual environment:**
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the application:**
   You can use the built-in auto-detecting launcher:
   ```bash
   python run.py
   ```
   *Or specify a custom port directly (e.g. port 5001 if port 5000 is occupied by Docker Desktop / AirPlay):*
   ```bash
   python -c "from app import create_app; app = create_app(); app.run(host='127.0.0.1', port=5001, debug=False)"
   ```

### Method C: Cloud Deployment (Render)

The repository includes a ready-to-use Render Blueprint ([`render.yaml`](render.yaml)) and cloud proxy support:

1. Push your repository to GitHub.
2. In your [Render Dashboard](https://dashboard.render.com), click **New +** &rarr; **Blueprint** and select your repository.
3. Render automatically provisions the service on Python 3.11 with Gunicorn, generates `SECRET_KEY`, and enables HTTPS.
4. For detailed step-by-step instructions, see [docs/render-deployment-guide.md](docs/render-deployment-guide.md).

---

## 7. Operating Modes: Vulnerable vs. Secure

The application features a dynamic mode switch in the top navigation header:

| Feature | Vulnerable Mode (Mode A) | Secure Mode (Mode B) |
|---|---|---|
| **Endpoint** | `GET /api/documents/<id>` | `GET /api/documents/<id>` |
| **Authentication** | Required (Session cookie) | Required (Session cookie) |
| **Backend Query** | `SELECT * FROM docs WHERE id = ?` | `SELECT * FROM docs WHERE id = ? AND owner_id = ?` |
| **Alice requests 101** | `200 OK` (Own doc) | `200 OK` (Own doc) |
| **Alice requests 201** | **`200 OK` (Bob's doc leaked!)** | **`403 Forbidden` (Blocked)** |
| **Anonymous access** | `401 Unauthorized` | `401 Unauthorized` |
| **Nonexistent ID** | `404 Not Found` | `404 Not Found` |

---

## 8. Automated Security Test Results

The automated test suite runs via `pytest` and validates authentication, intentional vulnerability demonstration, secure access control, and server-side validation logic.

### Running the Tests:
```bash
pytest tests -v
```

### Verified Test Execution Summary (24 / 24 Passed):
```
tests/test_auth.py::test_valid_login PASSED
tests/test_auth.py::test_invalid_login_password PASSED
tests/test_auth.py::test_invalid_login_nonexistent_user PASSED
tests/test_auth.py::test_protected_endpoint_without_authentication PASSED
tests/test_auth.py::test_logout_invalidates_session PASSED
tests/test_auth.py::test_passwords_stored_as_strong_hashes PASSED
tests/test_idor_secure.py::test_secure_alice_can_access_own_document PASSED
tests/test_idor_secure.py::test_secure_alice_cannot_access_bob_document PASSED
tests/test_idor_secure.py::test_secure_bob_can_access_own_document PASSED
tests/test_idor_secure.py::test_secure_nonexistent_document_returns_404 PASSED
tests/test_idor_secure.py::test_secure_invalid_identifier_format_handled_safely PASSED
tests/test_idor_secure.py::test_secure_client_cannot_spoof_user_id PASSED
tests/test_idor_secure.py::test_secure_unauthorized_modification_rejected PASSED
tests/test_idor_vulnerable.py::test_vulnerable_alice_can_access_own_document PASSED
tests/test_idor_vulnerable.py::test_vulnerable_alice_can_access_bob_document_demonstrating_idor PASSED
tests/test_idor_vulnerable.py::test_vulnerable_unauthenticated_access_is_still_denied PASSED
tests/test_idor_vulnerable.py::test_vulnerable_nonexistent_document_returns_404 PASSED
tests/test_lab_validation.py::test_lab_status_initial_state PASSED
tests/test_lab_validation.py::test_validation_engine_rejects_arbitrary_client_pass PASSED
tests/test_lab_validation.py::test_lab1_validation_succeeds_with_correct_answers PASSED
tests/test_lab_validation.py::test_lab2_validation_requires_vulnerable_request_audit PASSED
tests/test_lab_validation.py::test_lab3_validation PASSED
tests/test_lab_validation.py::test_lab4_multi_scenario_verification PASSED
tests/test_lab_validation.py::test_lab_reset_operation PASSED

======================== 24 passed in 24.20s (100%) ========================
```

---

## 9. Burp Suite Integration Summary

Students can intercept, inspect, and replay HTTP requests using **Burp Suite Community Edition**:
1. Open Burp Suite Community Edition &rarr; Proxy &rarr; Open Browser.
2. Navigate to `http://localhost:5000` and log in as `alice`.
3. In Burp **HTTP History**, locate `GET /api/documents/101`.
4. Press `Ctrl + R` to send to **Repeater**.
5. Tamper with the path to `GET /api/documents/201`.
6. Send the request in Vulnerable Mode (`HTTP 200 OK` + Bob's data) vs Secure Mode (`HTTP 403 Forbidden`).
7. For full instructions, see [docs/burp-suite-guide.md](docs/burp-suite-guide.md).

---

## 10. Security Boundaries & Safe Defaults

- **Localhost Binding:** Binds strictly to `127.0.0.1` by default in Docker and local execution.
- **Synthetic Data Only:** Contains exclusively fictional users and mock documents.
- **Safe Launch Default:** The default configuration launches in **Secure Mode**. Vulnerable mode requires an explicit local action.
- **Isolated Vulnerability:** The intentional vulnerability is isolated strictly to the object identifier lookup in Mode A. No operating system command injection, remote code execution, or unintended vulnerabilities exist.

---

## 11. Known Limitations

- The lab uses SQLite for ease of portability; multi-container concurrent scaling is not intended for this single-node educational laboratory.
- CSRF validation is intentionally bypassed for unit test clients where `WTF_CSRF_ENABLED=False` is set in test configuration.

---

## 12. License & Academic Integrity

Developed for educational and training purposes. All student submissions must follow academic honesty policies. Exploitation tools and concepts learned in this lab must never be applied against unauthorized third-party systems.
