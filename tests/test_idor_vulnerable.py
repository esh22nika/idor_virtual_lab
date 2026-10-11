"""
Vulnerable Mode security test suite.
Verifies that Mode A deliberately exhibits Insecure Direct Object References (IDOR),
enabling horizontal privilege escalation while still enforcing authentication boundaries.
"""

import pytest


@pytest.fixture
def vulnerable_client(client, auth):
    """Fixture providing an authenticated Alice session configured in Vulnerable Mode."""
    auth.login("alice", "AliceLab123!")

    # Switch session mode to vulnerable
    with client.session_transaction() as sess:
        sess["lab_mode"] = "vulnerable"

    return client


def test_vulnerable_alice_can_access_own_document(vulnerable_client):
    """Verify that Alice can retrieve her own seeded document (101) in Vulnerable Mode."""
    response = vulnerable_client.get("/api/documents/101")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["mode"] == "vulnerable"
    assert data["document"]["id"] == 101
    assert data["document"]["owner_id"] == 1
    assert "Alice" in data["document"]["title"]


def test_vulnerable_alice_can_access_bob_document_demonstrating_idor(vulnerable_client):
    """
    CRITICAL EDUCATIONAL TEST:
    Verify that Alice (User ID 1) can retrieve Bob's confidential document (201, User ID 2).
    This confirms the presence of the intentional IDOR vulnerability in Mode A.
    """
    response = vulnerable_client.get("/api/documents/201")
    assert response.status_code == 200
    data = response.get_json()

    # Verify that the document belongs to Bob (User ID 2)
    assert data["status"] == "success"
    assert data["mode"] == "vulnerable"
    assert data["document"]["id"] == 201
    assert data["document"]["owner_id"] == 2
    assert "Bob" in data["document"]["owner_name"]
    assert "Bob's Private Notes" in data["document"]["title"]

    # Verify telemetry flags cross-user exploitation
    assert data["security_analysis"]["vulnerability_demonstrated"] is True
    assert data["security_analysis"]["ownership_match"] is False


def test_vulnerable_unauthenticated_access_is_still_denied(client):
    """
    Verify that even in Vulnerable Mode, unauthenticated clients are denied (HTTP 401).
    IDOR represents an authorization flaw, not an absence of authentication.
    """
    response = client.get("/api/documents/201")
    assert response.status_code == 401
    data = response.get_json()
    assert data["error"] == "Unauthorized"


def test_vulnerable_nonexistent_document_returns_404(vulnerable_client):
    """Verify that requesting a nonexistent ID returns 404 in Vulnerable Mode."""
    response = vulnerable_client.get("/api/documents/9999")
    assert response.status_code == 404
