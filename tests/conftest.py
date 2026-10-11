"""
Pytest configuration and fixtures for the IDOR Virtual Lab test suite.
Sets up isolated temporary databases, test clients, and authenticated sessions.
"""

import os
import sys
import tempfile
import pytest

# Ensure the project root containing 'app' is in Python's search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app
from app.database import init_db
from app.seed import seed_database
from app.security import generate_csrf_token


@pytest.fixture
def app():
    """Create and configure a new Flask app instance for each test session."""
    db_fd, db_path = tempfile.mkstemp()
    test_config = {
        "TESTING": True,
        "DATABASE": db_path,
        "SECRET_KEY": "test-secret-key-idor-virtual-lab",
        "LAB_MODE": "secure",
        "WTF_CSRF_ENABLED": False,
    }

    app = create_app(test_config)

    with app.app_context():
        init_db(app)
        seed_database()

    yield app

    os.close(db_fd)
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test CLI runner for the app."""
    return app.test_cli_runner()


class AuthActions:
    """Helper class for authenticating test sessions."""
    def __init__(self, client):
        self._client = client

    def login(self, username="alice", password="AliceLab123!"):
        return self._client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

    def logout(self):
        return self._client.post("/logout", follow_redirects=True)


@pytest.fixture
def auth(client):
    """Fixture providing authentication actions."""
    return AuthActions(client)
