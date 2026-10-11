-- Web Application Security Virtual Lab: Broken Access Control (IDOR)
-- Database Schema for SQLite

PRAGMA foreign_keys = ON;

-- Users table storing seeded accounts with hashed passwords
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Documents table storing private user documents
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Student lab progress tracking table
CREATE TABLE IF NOT EXISTS lab_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    exercise_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'not_started', -- 'not_started', 'in_progress', 'passed'
    completed_at TIMESTAMP,
    score INTEGER DEFAULT 0,
    feedback TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE (user_id, exercise_id)
);

-- Lab audit logging for exercise validation and telemetry
CREATE TABLE IF NOT EXISTS lab_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    target_id TEXT,
    lab_mode TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    is_cross_user INTEGER DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Lab operational state and configurations
CREATE TABLE IF NOT EXISTS lab_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
