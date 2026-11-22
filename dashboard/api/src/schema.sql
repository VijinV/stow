PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS policies (
    revision INTEGER PRIMARY KEY,
    destination_revision INTEGER NOT NULL,
    settings TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    token_hash BLOB UNIQUE,
    last_seen INTEGER,
    applied_revision INTEGER,
    app_version TEXT,
    platform TEXT,
    schedule_enabled INTEGER,
    next_due_at INTEGER,
    last_session_at INTEGER
);
CREATE TABLE IF NOT EXISTS enrollments (
    code_hash BLOB PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    serial INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    id TEXT NOT NULL,
    trigger TEXT NOT NULL,
    revision INTEGER REFERENCES policies(revision),
    started_at INTEGER NOT NULL,
    last_progress_at INTEGER,
    last_lease_at INTEGER NOT NULL,
    aws_expires_at INTEGER NOT NULL DEFAULT 0,
    finished_at INTEGER,
    phase TEXT NOT NULL,
    block_reason TEXT,
    sequence INTEGER NOT NULL DEFAULT 0,
    snapshot TEXT,
    UNIQUE (device_id, id)
);
CREATE INDEX IF NOT EXISTS runs_device_order ON runs(device_id, serial DESC);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
);
