"""
Test suite for the educational lab validation engine and progress tracking.
Verifies server-side validation integrity, cheat prevention, and reset functionality.
"""

import pytest


@pytest.fixture
def logged_in_alice(client, auth):
    """Alice test client with session established."""
    auth.login("alice", "AliceLab123!")
    return client


def test_lab_status_initial_state(logged_in_alice):
    """Verify initial lab progress metrics for a fresh student account."""
    response = logged_in_alice.get("/api/lab/status")
    assert response.status_code == 200
    data = response.get_json()

    assert data["username"] == "alice"
    assert data["total_exercises"] == 4
    assert data["completed_exercises"] == 0
    assert data["progress_percentage"] == 0
    assert data["is_complete"] is False
    assert len(data["exercises"]) == 4


def test_validation_engine_rejects_arbitrary_client_pass(logged_in_alice):
    """
    Test that submitting an arbitrary {"passed": true} payload without satisfying
    exercise conditions fails and does not mark the exercise as passed.
    """
    with logged_in_alice.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token")

    response = logged_in_alice.post(
        "/api/lab/validate",
        json={
            "exercise_id": "lab1_inspect_ref",
            "passed": True,  # Client attempts to forge pass
            "identifier": "9999",  # Invalid ID
            "concept_answer": "yes",  # Incorrect concept
            "csrf_token": csrf_token,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["passed"] is False


def test_lab1_validation_succeeds_with_correct_answers(logged_in_alice):
    """Verify Lab 1 validation with valid identifier and correct conceptual answer."""
    with logged_in_alice.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token")

    response = logged_in_alice.post(
        "/api/lab/validate",
        json={
            "exercise_id": "lab1_inspect_ref",
            "identifier": 101,
            "concept_answer": "no",
            "csrf_token": csrf_token,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["passed"] is True
    assert "Excellent" in data["feedback"]

    # Verify progress was updated in database
    status_resp = logged_in_alice.get("/api/lab/status")
    status_data = status_resp.get_json()
    assert status_data["completed_exercises"] == 1
    assert status_data["progress_percentage"] == 25


def test_lab2_validation_requires_vulnerable_request_audit(logged_in_alice):
    """
    Verify Lab 2 validation passes only after a real cross-user request
    was executed in Vulnerable Mode.
    """
    with logged_in_alice.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token")
        sess["lab_mode"] = "vulnerable"

    # Step 1: Attempt validation before executing the vulnerable request -> should fail
    resp_fail = logged_in_alice.post(
        "/api/lab/validate",
        json={
            "exercise_id": "lab2_exploit_idor",
            "target_doc_id": 201,
            "explanation": "Access control failed because the server skipped checking ownership.",
            "csrf_token": csrf_token,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert resp_fail.get_json()["passed"] is False

    # Step 2: Actually execute the vulnerable GET request to log the audit event
    get_resp = logged_in_alice.get("/api/documents/201")
    assert get_resp.status_code == 200

    # Step 3: Now validate -> should succeed
    resp_ok = logged_in_alice.post(
        "/api/lab/validate",
        json={
            "exercise_id": "lab2_exploit_idor",
            "target_doc_id": 201,
            "explanation": "The server returned Bob's document because it queried by ID without ownership verification.",
            "csrf_token": csrf_token,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert resp_ok.get_json()["passed"] is True


def test_lab3_validation(logged_in_alice):
    """Verify Lab 3 remediation check validation."""
    with logged_in_alice.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token")

    resp = logged_in_alice.post(
        "/api/lab/validate",
        json={
            "exercise_id": "lab3_remediate_check",
            "check_query": "session_ownership",
            "concept_uuid": "insufficient",
            "csrf_token": csrf_token,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert resp.status_code == 200
    assert resp.get_json()["passed"] is True


def test_lab4_multi_scenario_verification(logged_in_alice):
    """Verify Lab 4 execution of automated scenario suite."""
    with logged_in_alice.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token")
        sess["lab_mode"] = "secure"

    resp = logged_in_alice.post(
        "/api/lab/validate",
        json={
            "exercise_id": "lab4_verify_scenarios",
            "csrf_token": csrf_token,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["passed"] is True
    assert len(data["details"]["scenarios"]) >= 5


def test_lab_reset_operation(logged_in_alice):
    """Verify that calling reset clears progress and restores initial state."""
    with logged_in_alice.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token")

    # Complete Lab 1 first
    logged_in_alice.post(
        "/api/lab/validate",
        json={
            "exercise_id": "lab1_inspect_ref",
            "identifier": 101,
            "concept_answer": "no",
            "csrf_token": csrf_token,
        },
        headers={"X-CSRF-Token": csrf_token},
    )

    # Confirm progress is 1
    assert logged_in_alice.get("/api/lab/status").get_json()["completed_exercises"] == 1

    # Reset
    reset_resp = logged_in_alice.post(
        "/api/lab/reset",
        json={"csrf_token": csrf_token},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert reset_resp.status_code == 200

    # Confirm progress is back to 0
    assert logged_in_alice.get("/api/lab/status").get_json()["completed_exercises"] == 0
