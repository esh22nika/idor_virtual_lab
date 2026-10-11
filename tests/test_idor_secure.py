"""
Secure Mode security test suite.
Verifies that Mode B enforces server-side object-level authorization,
blocking cross-user reads and unauthorized state modifications.
"""

import pytest


@pytest.fixture
def secure_alice(client, auth):
    """Fixture providing Alice authenticated in Secure Mode."""
    auth.login("alice", "AliceLab123!")
    with client.session_transaction() as sess:
        sess["lab_mode"] = "secure"
    return client


@pytest.fixture
def secure_bob(app):
    """Fixture providing Bob authenticated in Secure Mode."""
    bob_client = app.test_client()
    bob_client.post(
        "/login",
        data={"username": "bob", "password": "BobLab123!"},
        follow_redirects=True,
    )
    with bob_client.session_transaction() as sess:
        sess["lab_mode"] = "secure"
    return bob_client


def test_secure_alice_can_access_own_document(secure_alice):
    """Verify that Alice can access document 101 which she owns (HTTP 200)."""
    response = secure_alice.get("/api/documents/101")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["mode"] == "secure"
    assert data["document"]["id"] == 101
    assert data["document"]["owner_id"] == 1


def test_secure_alice_cannot_access_bob_document(secure_alice):
    """
    CRITICAL ACCESS CONTROL DEFENSE TEST:
    Verify that Alice (User ID 1) attempting to access Bob's document (201, User ID 2)
    is denied with HTTP 403 Forbidden.
    """
    response = secure_alice.get("/api/documents/201")
    assert response.status_code == 403
    data = response.get_json()
    assert data["error"] == "Forbidden"
    assert "Access denied" in data["message"]
    # Ensure confidential content was NOT leaked
    assert "document" not in data


def test_secure_bob_can_access_own_document(secure_bob):
    """Verify that Bob (User ID 2) can legitimately access his own document 201 (HTTP 200)."""
    response = secure_bob.get("/api/documents/201")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["document"]["id"] == 201
    assert data["document"]["owner_id"] == 2


def test_secure_nonexistent_document_returns_404(secure_alice):
    """Verify that querying a non-existent document ID returns HTTP 404."""
    response = secure_alice.get("/api/documents/9999")
    assert response.status_code == 404
    data = response.get_json()
    assert data["error"] == "Not Found"


def test_secure_invalid_identifier_format_handled_safely(secure_alice):
    """Verify that non-numeric IDs are handled safely (HTTP 400 Bad Request)."""
    response = secure_alice.get("/api/documents/invalid_string_id")
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "Bad Request"


def test_secure_client_cannot_spoof_user_id(secure_alice):
    """
    Verify that supplying a client-controlled user_id parameter does not bypass authorization.
    The server must solely rely on the authenticated server session.
    """
    response = secure_alice.get("/api/documents/201?user_id=2")
    assert response.status_code == 403


def test_secure_unauthorized_modification_rejected(secure_alice):
    """
    Scenario F: Verify that Alice cannot tamper with or modify Bob's document (201).
    State-changing endpoint must return HTTP 403 Forbidden.
    """
    # Obtain CSRF token from session
    with secure_alice.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token")

    response = secure_alice.post(
        "/api/documents/201",
        json={
            "title": "Tampered Title",
            "content": "Malicious content injected by Alice.",
            "csrf_token": csrf_token,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert response.status_code == 403
