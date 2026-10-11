"""
Database access and initialization module for the IDOR Virtual Lab.
Provides SQLite connection management, schema initialization, and helper functions.
"""

import os
import sqlite3
from flask import g, current_app


def get_db_path():
    """Return the absolute path to the SQLite database file."""
    if current_app:
        return current_app.config.get(
            "DATABASE",
            os.path.join(current_app.instance_path, "idor_lab.sqlite"),
        )
    return os.environ.get(
        "DATABASE_PATH",
        os.path.join(os.path.dirname(__file__), "..", "instance", "idor_lab.sqlite"),
    )


def get_db():
    """Obtain a database connection for the current application context."""
    if "db" not in g:
        db_path = get_db_path()
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        g.db = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app=None):
    """Initialize the database schema from schema.sql."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    if app is not None:
        with app.app_context():
            db = get_db()
            db.executescript(schema_sql)
            db.commit()
    else:
        db = get_db()
        db.executescript(schema_sql)
        db.commit()


def init_app(app):
    """Register database teardown with the Flask application."""
    app.teardown_appcontext(close_db)
