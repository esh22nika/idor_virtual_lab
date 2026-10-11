"""
Seed data module for the IDOR Virtual Lab.
Creates synthetic, educational user accounts and private documents.
Plaintext passwords are never stored; only strong cryptographic hashes are written.
"""

import os
import sqlite3
from werkzeug.security import generate_password_hash
from app.database import get_db, get_db_path

SEED_USERS = [
    {
        "id": 1,
        "username": "alice",
        "password": "AliceLab123!",
        "full_name": "Alice Cooper (Student Researcher)",
        "role": "student",
    },
    {
        "id": 2,
        "username": "bob",
        "password": "BobLab123!",
        "full_name": "Bob Martin (Peer Reviewer)",
        "role": "student",
    },
]

SEED_DOCUMENTS = [
    {
        "id": 101,
        "owner_id": 1,
        "title": "Alice's Project Notes",
        "content": (
            "Confidential Lab Notes:\n\n"
            "Investigating server-side authorization failures (CWE-634). "
            "Observations show that exposing direct database primary keys "
            "without session-based ownership verification allows horizontal privilege escalation.\n\n"
            "Action Item: Ensure all document API endpoints bind to session['user_id']."
        ),
        "classification": "CONFIDENTIAL - RESTRICTED TO ALICE",
    },
    {
        "id": 102,
        "owner_id": 1,
        "title": "Alice's Lab Report",
        "content": (
            "Midterm Security Experiment Draft:\n\n"
            "Title: Insecure Direct Object References in Modern REST APIs.\n"
            "Hypothesis: Hiding identifiers or disabling UI buttons does not prevent "
            "an attacker from tampering with HTTP GET request parameters in Burp Suite.\n"
            "Status: Draft under review."
        ),
        "classification": "INTERNAL DRAFT",
    },
    {
        "id": 201,
        "owner_id": 2,
        "title": "Bob's Private Notes",
        "content": (
            "Bob's Personal Research Journal:\n\n"
            "Private notes on cryptographic token generation and session handling. "
            "Proprietary research notes not ready for peer publication.\n"
            "Reminder: Do not share these notes outside my personal account."
        ),
        "classification": "CONFIDENTIAL - RESTRICTED TO BOB",
    },
    {
        "id": 202,
        "owner_id": 2,
        "title": "Bob's Assignment Draft",
        "content": (
            "Bob's Coursework Submission Draft:\n\n"
            "Topic: Automated Security Verification with Pytest.\n"
            "Includes personal reflections, draft answers for assignment questions, "
            "and internal system diagrams for review by instructor only."
        ),
        "classification": "ACADEMIC CONFIDENTIAL",
    },
]

LAB_EXERCISES = [
    {
        "id": "lab1_inspect_ref",
        "name": "Lab 1: Understand Object References",
        "description": "Inspect document URLs and understand how direct object identifiers function.",
    },
    {
        "id": "lab2_exploit_idor",
        "name": "Lab 2: Exploit Broken Authorization",
        "description": "Demonstrate horizontal privilege escalation by accessing another user's document in Vulnerable Mode.",
    },
    {
        "id": "lab3_remediate_check",
        "name": "Lab 3: Remediate IDOR",
        "description": "Understand server-side authorization checks and verify code remediation concepts.",
    },
    {
        "id": "lab4_verify_scenarios",
        "name": "Lab 4: Verify the Fix",
        "description": "Run comprehensive security verification scenarios against Secure Mode to confirm remediation.",
    },
]


def seed_database(db=None):
    """
    Idempotently seed the SQLite database with test accounts, documents,
    and exercise progress trackers.
    """
    should_close = False
    if db is None:
        db = get_db()

    # Insert seeded users
    for user in SEED_USERS:
        password_hash = generate_password_hash(user["password"])
        db.execute(
            """
            INSERT OR REPLACE INTO users (id, username, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user["id"], user["username"], password_hash, user["full_name"], user["role"]),
        )

    # Insert seeded documents
    for doc in SEED_DOCUMENTS:
        db.execute(
            """
            INSERT OR REPLACE INTO documents (id, owner_id, title, content, classification)
            VALUES (?, ?, ?, ?, ?)
            """,
            (doc["id"], doc["owner_id"], doc["title"], doc["content"], doc["classification"]),
        )

    # Initialize default settings
    db.execute(
        """
        INSERT OR IGNORE INTO lab_settings (key, value)
        VALUES ('lab_mode', 'secure')
        """
    )

    db.commit()


def reset_lab_data(db=None, user_id=None):
    """
    Completely reset the database state:
    - Clears or resets lab progress.
    - Clears audit logs.
    - Restores pristine document contents and user records.
    """
    if db is None:
        db = get_db()

    if user_id is not None:
        db.execute("DELETE FROM lab_progress WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM lab_audit_logs WHERE user_id = ?", (user_id,))
    else:
        db.execute("DELETE FROM lab_progress")
        db.execute("DELETE FROM lab_audit_logs")
        db.execute("DELETE FROM documents")
        db.execute("DELETE FROM users")

    seed_database(db)
    db.commit()


if __name__ == "__main__":
    from app.database import init_db
    import sqlite3
    db_path = os.environ.get(
        "DATABASE_PATH",
        os.path.join(os.path.dirname(__file__), "..", "instance", "idor_lab.sqlite"),
    )
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    seed_database(conn)
    conn.close()
    print("Database initialized and seeded successfully.")
