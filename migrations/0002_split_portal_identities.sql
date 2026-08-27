PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS portal_users (
    email TEXT PRIMARY KEY COLLATE NOCASE,
    full_name TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_signups (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name TEXT NOT NULL,
    school_name TEXT NOT NULL,
    country TEXT NOT NULL,
    preferred_currency TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    requested_ip_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_signups_expiry
ON pending_signups(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS owner_magic_links (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    requested_ip_hash TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_owner_magic_links_email_created
ON owner_magic_links(LOWER(email), created_at DESC);

CREATE TABLE IF NOT EXISTS owner_sessions (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_owner_sessions_email
ON owner_sessions(LOWER(email), expires_at);
