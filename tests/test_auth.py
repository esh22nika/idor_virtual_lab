"""
Authentication and session management test suite.
Verifies credentials checking, session isolation, unauthenticated denials,
and secure password hashing in the database.
"""

import pytest
from app.database import get_db
from werkzeug.security import check_password_hash


def test_valid_login(client, auth):
    """Test successful authentication with seeded account credentials."""
    response = auth.login("alice", "AliceLab123!")
    assert response.status_code == 200

    # Verify session identity via /api/me
    me_resp = client.get("/api/me")
    assert me_resp.status_code == 200
    data = me_resp.get_json()
    assert data["authenticated"] is True
    assert data["user"]["username"] == "alice"
    assert data["user"]["id"] == 1


def test_invalid_login_password(client, auth):
    """Test login rejection when password does not match."""
    response = client.post(
        "/login",
        json={"username": "alice", "password": "WrongPassword!"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 401
    data = response.get_json()
    assert "error" in data


def test_invalid_login_nonexistent_user(client):
    """Test login rejection when user does not exist in the database."""
    response = client.post(
        "/login",
        json={"username": "eve_hacker", "password": "Password123!"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 401


def test_protected_endpoint_without_authentication(client):
    """Test that unauthenticated requests to protected endpoints receive HTTP 401."""
    response = client.get("/api/documents")
    assert response.status_code == 401
    data = response.get_json()
    assert data["error"] == "Unauthorized"


def test_logout_invalidates_session(client, auth):
    """Test that logging out removes session attributes and denies subsequent requests."""
    auth.login("alice", "AliceLab123!")
    me_resp = client.get("/api/me")
    assert me_resp.status_code == 200

    logout_resp = auth.logout()
    assert logout_resp.status_code == 200

    # Accessing protected resource should now be rejected
    protected_resp = client.get("/api/me")
    assert protected_resp.status_code == 401


def test_passwords_stored_as_strong_hashes(app):
    """Test that plaintext passwords are never stored in the database."""
    with app.app_context():
        db = get_db()
        users = db.execute("SELECT username, password_hash FROM users").fetchall()

        assert len(users) >= 2
        for u in users:
            # Hash must not match plaintext
            assert u["password_hash"] != "AliceLab123!"
            assert u["password_hash"] != "BobLab123!"
            # Hash must use a recognized Werkzeug hash prefix (scrypt, pbkdf2, argon2)
            assert u["password_hash"].startswith(("scrypt:", "pbkdf2:", "argon2:"))
            # Validate hash can verify the expected password
            if u["username"] == "alice":
                assert check_password_hash(u["password_hash"], "AliceLab123!")
            elif u["username"] == "bob":
                assert check_password_hash(u["password_hash"], "BobLab123!")
