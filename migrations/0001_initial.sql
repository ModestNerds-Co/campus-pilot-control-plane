PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    billing_email TEXT NOT NULL,
    preferred_currency TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS account_members (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'billing', 'viewer')),
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_members_active_email
ON account_members(account_id, LOWER(email)) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_account_members_email
ON account_members(LOWER(email)) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'retired')),
    modules_json TEXT NOT NULL DEFAULT '[]',
    features_json TEXT NOT NULL DEFAULT '[]',
    limits_json TEXT NOT NULL DEFAULT '[]',
    trial_days INTEGER NOT NULL DEFAULT 0 CHECK (trial_days >= 0),
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_plans_status_sort ON plans(status, sort_order, name);

CREATE TABLE IF NOT EXISTS plan_prices (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    currency TEXT NOT NULL,
    currency_exponent INTEGER NOT NULL DEFAULT 2 CHECK (currency_exponent BETWEEN 0 AND 4),
    amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0),
    billing_interval TEXT NOT NULL CHECK (billing_interval IN ('month', 'year')),
    external_product_id TEXT,
    external_price_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'retired')),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider, external_price_id)
);

CREATE INDEX IF NOT EXISTS idx_plan_prices_catalog
ON plan_prices(plan_id, status, provider, currency, billing_interval);

CREATE TABLE IF NOT EXISTS billing_customers (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_customer_id TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(account_id, provider),
    UNIQUE(provider, external_customer_id)
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL REFERENCES plans(id),
    plan_price_id TEXT REFERENCES plan_prices(id),
    provider TEXT NOT NULL,
    external_customer_id TEXT,
    external_subscription_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('incomplete', 'trialing', 'active', 'past_due', 'unpaid', 'cancelled', 'paused', 'expired')),
    billing_currency TEXT,
    billing_currency_exponent INTEGER CHECK (billing_currency_exponent BETWEEN 0 AND 4),
    billing_amount_minor INTEGER CHECK (billing_amount_minor >= 0),
    current_period_start TEXT,
    current_period_end TEXT,
    cancel_at_period_end INTEGER NOT NULL DEFAULT 0 CHECK (cancel_at_period_end IN (0, 1)),
    grace_until TEXT,
    ended_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider, external_subscription_id)
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_account_status
ON subscriptions(account_id, status, current_period_end);

CREATE TABLE IF NOT EXISTS activation_codes (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_hint TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT,
    created_by_email TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activation_codes_account
ON activation_codes(account_id, created_at);

CREATE TABLE IF NOT EXISTS installations (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    credential_hash TEXT NOT NULL UNIQUE,
    credential_hint TEXT NOT NULL,
    last_lease_sequence INTEGER NOT NULL DEFAULT 0,
    current_lease_id TEXT,
    last_seen_at TEXT,
    revoked_at TEXT,
    revoked_reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_installations_tenant_deployment
ON installations(tenant_id, deployment_id);

CREATE INDEX IF NOT EXISTS idx_installations_account_status
ON installations(account_id, status);

CREATE TABLE IF NOT EXISTS leases (
    id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'superseded', 'revoked', 'expired')),
    token_fingerprint TEXT NOT NULL UNIQUE,
    catalog_version TEXT NOT NULL,
    claims_json TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    refresh_after TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    grace_until TEXT NOT NULL,
    token_expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_reason TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(installation_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_leases_installation_status
ON leases(installation_id, status, sequence DESC);

CREATE TABLE IF NOT EXISTS magic_links (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    requested_ip_hash TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_magic_links_email_created
ON magic_links(LOWER(email), created_at DESC);

CREATE TABLE IF NOT EXISTS portal_sessions (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_portal_sessions_email
ON portal_sessions(LOWER(email), expires_at);

CREATE TABLE IF NOT EXISTS checkout_attempts (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL REFERENCES plans(id),
    plan_price_id TEXT NOT NULL REFERENCES plan_prices(id),
    requested_by_email TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    provider_checkout_id TEXT NOT NULL,
    quoted_currency TEXT NOT NULL,
    quoted_currency_exponent INTEGER NOT NULL CHECK (quoted_currency_exponent BETWEEN 0 AND 4),
    quoted_amount_minor INTEGER NOT NULL CHECK (quoted_amount_minor >= 0),
    status TEXT NOT NULL DEFAULT 'created' CHECK (status IN ('created', 'completed', 'expired', 'failed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider, provider_checkout_id)
);

CREATE TABLE IF NOT EXISTS payment_events (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    processing_status TEXT NOT NULL CHECK (processing_status IN ('processing', 'processed', 'ignored', 'failed')),
    failure_reason TEXT,
    received_at TEXT NOT NULL,
    processed_at TEXT,
    UNIQUE(provider, provider_event_id)
);

CREATE INDEX IF NOT EXISTS idx_payment_events_received
ON payment_events(received_at DESC);

CREATE TABLE IF NOT EXISTS payment_transactions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    subscription_id TEXT REFERENCES subscriptions(id) ON DELETE SET NULL,
    related_transaction_id TEXT REFERENCES payment_transactions(id) ON DELETE SET NULL,
    provider TEXT NOT NULL,
    external_payment_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('charge', 'refund', 'adjustment')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'cancelled', 'refunded', 'partially_refunded')),
    currency TEXT NOT NULL,
    currency_exponent INTEGER NOT NULL CHECK (currency_exponent BETWEEN 0 AND 4),
    amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0),
    settlement_currency TEXT,
    settlement_currency_exponent INTEGER CHECK (settlement_currency_exponent BETWEEN 0 AND 4),
    settlement_amount_minor INTEGER CHECK (settlement_amount_minor >= 0),
    fee_currency TEXT,
    fee_currency_exponent INTEGER CHECK (fee_currency_exponent BETWEEN 0 AND 4),
    fee_amount_minor INTEGER CHECK (fee_amount_minor >= 0),
    provider_exchange_rate TEXT,
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider, external_payment_id)
);

CREATE INDEX IF NOT EXISTS idx_payment_transactions_account_occurred
ON payment_transactions(account_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('customer', 'owner', 'installation', 'payment_provider', 'system')),
    actor_id TEXT,
    account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    request_id TEXT,
    reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_account_created
ON audit_events(account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_action_created
ON audit_events(action, created_at DESC);

INSERT OR IGNORE INTO plans (
    id, key, name, description, status, modules_json, features_json, limits_json,
    trial_days, sort_order, created_at, updated_at
) VALUES
    (
        'plan_starter', 'starter', 'Starter', 'Core school administration and people records.',
        'draft', '["sis"]', '[]', '[]', 0, 10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
    ),
    (
        'plan_operations', 'operations', 'Operations', 'School operations, people, timetabling, communication, and resources.',
        'draft', '["sis","academics","timetabling","messaging","library","fleet","hostel","health"]',
        '[]', '[]', 0, 20, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
    ),
    (
        'plan_complete', 'complete', 'Complete', 'All currently released Campus Pilot modules, including Agent when available.',
        'draft', '["sis","academics","timetabling","messaging","finance","fees","library","hr_payroll","procurement","fleet","hostel","health","assets_inventory","document_registry","internal_audit","agent"]',
        '[]', '[]', 0, 30, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
    );
