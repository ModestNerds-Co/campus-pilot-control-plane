//! Customer activation-code actions and owner control-plane management operations.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use worker::D1Database;

use crate::audit::{AuditActor, AuditEvent, write};
use crate::auth::{AccountRole, AuthenticatedPortalUser, OwnerOperator};
use crate::clock::{format, now, now_iso};
use crate::config::Config;
use crate::crypto::{hash_secret, random_token};
use crate::domain::{
    CanonicalEmail, LicenseLimit, Money, PaymentProviderKey, module_key_is_valid,
    parse_iso_timestamp, required_text,
};
use crate::error::{ApiError, FieldIssue};
use crate::licensing::installation_by_id;
use crate::store::{all, batch, bind_i64, bind_optional_text, bind_text, execute, first, prepared};

#[derive(Debug, Serialize)]
pub struct ActivationCodeOutput {
    pub activation_code: String,
    pub expires_at: String,
}

#[derive(Debug)]
pub struct CreateAccountInput {
    pub name: String,
    pub billing_email: CanonicalEmail,
    pub member_email: CanonicalEmail,
}

impl CreateAccountInput {
    pub fn parse(name: &str, billing_email: &str, member_email: &str) -> Result<Self, ApiError> {
        Ok(Self {
            name: required_text("name", name, 2, 160)?,
            billing_email: CanonicalEmail::parse(billing_email)?,
            member_email: CanonicalEmail::parse(member_email)?,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct CreatedAccount {
    pub id: String,
    pub slug: String,
}

/// A validated owner-assisted grant of customer administrator access.
///
/// This does not create an owner session or a customer session. The recipient
/// must still prove control of the email address through customer sign-in.
#[derive(Debug)]
pub(crate) struct GrantCustomerAdministratorInput {
    account_id: String,
    email: CanonicalEmail,
}

impl GrantCustomerAdministratorInput {
    pub(crate) fn parse(account_id: &str, email: &str) -> Result<Self, ApiError> {
        let account_id = Uuid::parse_str(account_id)
            .map_err(|_| invalid("account_id", "Expected a valid customer identifier"))?
            .to_string();
        Ok(Self {
            account_id,
            email: CanonicalEmail::parse(email)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CustomerAdministratorGrantOutcome {
    Created,
    Promoted,
    AlreadyAdministrator,
}

#[derive(Debug, Serialize)]
pub(crate) struct CustomerAdministratorGrantOutput {
    member_id: String,
    email: CanonicalEmail,
    role: AccountRole,
    outcome: CustomerAdministratorGrantOutcome,
}

impl CustomerAdministratorGrantOutput {
    pub(crate) fn email(&self) -> &CanonicalEmail {
        &self.email
    }

    pub(crate) fn requires_access_email(&self) -> bool {
        self.outcome != CustomerAdministratorGrantOutcome::AlreadyAdministrator
    }
}

#[derive(Debug, Deserialize)]
struct AccountStatusRow {
    status: String,
}

#[derive(Debug, Deserialize)]
struct AccountMemberRow {
    id: String,
    role: String,
}

#[derive(Debug, Deserialize)]
pub struct PlanPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub modules: Option<Vec<String>>,
    pub features: Option<Vec<String>>,
    pub limits: Option<Vec<LicenseLimit>>,
    pub trial_days: Option<i64>,
    pub sort_order: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct PlanRow {
    name: String,
    description: String,
    status: String,
    modules_json: String,
    features_json: String,
    limits_json: String,
    trial_days: i64,
    sort_order: i64,
}

#[derive(Debug)]
pub struct CreatePlanPriceInput {
    pub plan_id: String,
    pub provider: PaymentProviderKey,
    pub money: Money,
    pub billing_interval: String,
    pub external_product_id: Option<String>,
    pub external_price_id: String,
    pub status: String,
}

impl CreatePlanPriceInput {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        plan_id: &str,
        provider: &str,
        currency: &str,
        currency_exponent: u8,
        amount_minor: i64,
        billing_interval: &str,
        external_product_id: Option<&str>,
        external_price_id: &str,
        status: &str,
    ) -> Result<Self, ApiError> {
        let money = Money::price(currency, currency_exponent, amount_minor)?;
        if !matches!(billing_interval, "month" | "year") {
            return Err(invalid("billing_interval", "Expected month or year"));
        }
        if !matches!(status, "draft" | "active" | "retired") {
            return Err(invalid("status", "Expected draft, active, or retired"));
        }
        Ok(Self {
            plan_id: required_text("plan_id", plan_id, 1, 120)?,
            provider: PaymentProviderKey::parse(provider)?,
            money,
            billing_interval: billing_interval.to_owned(),
            external_product_id: external_product_id
                .map(|value| required_text("external_product_id", value, 2, 200))
                .transpose()?,
            external_price_id: required_text("external_price_id", external_price_id, 2, 200)?,
            status: status.to_owned(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct CreatedPlanPrice {
    pub id: String,
}

pub async fn create_activation_code(
    db: &D1Database,
    user: &AuthenticatedPortalUser,
    account_id: &str,
    label: &str,
    config: &Config,
    request_id: &str,
) -> Result<ActivationCodeOutput, ApiError> {
    user.require_account(account_id, &[AccountRole::Admin])?;
    let label = required_text("label", label, 2, 100)?;
    let pepper = config
        .session_pepper
        .as_deref()
        .ok_or(ApiError::Configuration)?;
    let token = random_token("cpact_")?;
    let token_hash = hash_secret(&token, Some(pepper));
    let id = Uuid::new_v4().to_string();
    let created_at = now_iso()?;
    let expires_at = format(now() + time::Duration::days(1))?;
    execute(
        db,
        "INSERT INTO activation_codes (id, account_id, label, token_hash, token_hint, expires_at, \
         created_by_email, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            bind_text(&id),
            bind_text(account_id),
            bind_text(&label),
            bind_text(&token_hash),
            bind_text(&token[token.len().saturating_sub(8)..]),
            bind_text(&expires_at),
            bind_text(user.identity().email.as_str()),
            bind_text(&created_at),
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Customer,
            actor_id: Some(user.identity().email.as_str()),
            account_id: Some(account_id),
            action: "activation_code.created",
            target_type: "activation_code",
            target_id: Some(&id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({ "expires_at": expires_at }),
        },
    )
    .await?;
    Ok(ActivationCodeOutput {
        activation_code: token,
        expires_at,
    })
}

pub async fn owner_overview(db: &D1Database) -> Result<Value, ApiError> {
    let counts = first::<Value>(
        db,
        "SELECT (SELECT COUNT(*) FROM accounts WHERE deleted_at IS NULL) AS accounts, \
         (SELECT COUNT(*) FROM subscriptions WHERE status IN ('active', 'trialing')) AS active_subscriptions, \
         (SELECT COUNT(*) FROM installations WHERE status = 'active') AS active_installations, \
         (SELECT COUNT(*) FROM subscriptions WHERE status IN ('past_due', 'unpaid')) AS billing_attention, \
         (SELECT COUNT(*) FROM leases WHERE status = 'revoked') AS revoked_leases",
        vec![],
    )
    .await?
    .unwrap_or_else(|| json!({}));
    let recent = all::<Value>(
        db,
        "SELECT audit_events.id, audit_events.actor_type, audit_events.actor_id, audit_events.action, \
         audit_events.target_type, audit_events.target_id, audit_events.reason, audit_events.created_at, \
         accounts.name AS account_name FROM audit_events LEFT JOIN accounts ON accounts.id = audit_events.account_id \
         ORDER BY audit_events.created_at DESC LIMIT 20",
        vec![],
    )
    .await?;
    Ok(json!({ "counts": counts, "recent_activity": recent }))
}

pub async fn owner_accounts(db: &D1Database) -> Result<Value, ApiError> {
    let accounts = all::<Value>(
        db,
        "SELECT accounts.id, accounts.name, accounts.slug, accounts.billing_email, accounts.status, \
         accounts.created_at, subscriptions.id AS subscription_id, subscriptions.provider, \
         subscriptions.status AS subscription_status, subscriptions.current_period_end, plans.name AS plan_name, \
         (SELECT COUNT(*) FROM installations WHERE installations.account_id = accounts.id) AS installation_count \
         FROM accounts LEFT JOIN subscriptions ON subscriptions.id = (SELECT candidate.id FROM subscriptions AS candidate \
         WHERE candidate.account_id = accounts.id ORDER BY candidate.updated_at DESC LIMIT 1) \
         LEFT JOIN plans ON plans.id = subscriptions.plan_id WHERE accounts.deleted_at IS NULL \
         ORDER BY accounts.created_at DESC",
        vec![],
    )
    .await?;
    let members = all::<Value>(
        db,
        "SELECT id, account_id, email, role, created_at FROM account_members \
         WHERE deleted_at IS NULL ORDER BY LOWER(email)",
        vec![],
    )
    .await?;
    Ok(json!({ "accounts": accounts, "members": members }))
}

pub async fn create_account(
    db: &D1Database,
    operator: &OwnerOperator,
    input: CreateAccountInput,
    request_id: &str,
) -> Result<CreatedAccount, ApiError> {
    let id = Uuid::new_v4().to_string();
    let slug = format!("{}-{}", slugify(&input.name), &id[..8]);
    let created_at = now_iso()?;
    batch(
        db,
        vec![
            prepared(
                db,
                "INSERT INTO accounts (id, name, slug, billing_email, status, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, 'active', ?, ?)",
                vec![
                    bind_text(&id),
                    bind_text(&input.name),
                    bind_text(&slug),
                    bind_text(input.billing_email.as_str()),
                    bind_text(&created_at),
                    bind_text(&created_at),
                ],
            )?,
            prepared(
                db,
                "INSERT INTO account_members (id, account_id, email, role, created_at, updated_at) \
                 VALUES (?, ?, ?, 'admin', ?, ?)",
                vec![
                    bind_text(&Uuid::new_v4().to_string()),
                    bind_text(&id),
                    bind_text(input.member_email.as_str()),
                    bind_text(&created_at),
                    bind_text(&created_at),
                ],
            )?,
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Owner,
            actor_id: Some(operator.email().as_str()),
            account_id: Some(&id),
            action: "account.created",
            target_type: "account",
            target_id: Some(&id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({}),
        },
    )
    .await?;
    Ok(CreatedAccount { id, slug })
}

pub(crate) async fn grant_customer_administrator(
    db: &D1Database,
    operator: &OwnerOperator,
    input: GrantCustomerAdministratorInput,
    request_id: &str,
) -> Result<CustomerAdministratorGrantOutput, ApiError> {
    let account = first::<AccountStatusRow>(
        db,
        "SELECT status FROM accounts WHERE id = ? AND deleted_at IS NULL",
        vec![bind_text(&input.account_id)],
    )
    .await?
    .ok_or_else(|| ApiError::client("account_not_found", "Customer not found", 404))?;
    if account.status == "closed" {
        return Err(ApiError::client(
            "account_closed",
            "Customer access cannot be changed for a closed account",
            409,
        ));
    }

    if let Some(existing) = active_account_member(db, &input).await? {
        return ensure_customer_administrator(db, operator, &input, existing, request_id).await;
    }

    let member_id = Uuid::new_v4().to_string();
    let timestamp = now_iso()?;
    let inserted = execute(
        db,
        "INSERT OR IGNORE INTO account_members \
         (id, account_id, email, role, created_at, updated_at) \
         VALUES (?, ?, ?, 'admin', ?, ?)",
        vec![
            bind_text(&member_id),
            bind_text(&input.account_id),
            bind_text(input.email.as_str()),
            bind_text(&timestamp),
            bind_text(&timestamp),
        ],
    )
    .await?;
    if inserted == 0 {
        let existing = active_account_member(db, &input)
            .await?
            .ok_or(ApiError::Internal)?;
        return ensure_customer_administrator(db, operator, &input, existing, request_id).await;
    }

    write_member_grant_audit(db, operator, &input, &member_id, None, request_id).await?;
    Ok(CustomerAdministratorGrantOutput {
        member_id,
        email: input.email,
        role: AccountRole::Admin,
        outcome: CustomerAdministratorGrantOutcome::Created,
    })
}

async fn active_account_member(
    db: &D1Database,
    input: &GrantCustomerAdministratorInput,
) -> Result<Option<AccountMemberRow>, ApiError> {
    first::<AccountMemberRow>(
        db,
        "SELECT id, role FROM account_members WHERE account_id = ? AND LOWER(email) = ? \
         AND deleted_at IS NULL LIMIT 1",
        vec![
            bind_text(&input.account_id),
            bind_text(input.email.as_str()),
        ],
    )
    .await
}

async fn ensure_customer_administrator(
    db: &D1Database,
    operator: &OwnerOperator,
    input: &GrantCustomerAdministratorInput,
    existing: AccountMemberRow,
    request_id: &str,
) -> Result<CustomerAdministratorGrantOutput, ApiError> {
    if existing.role == "admin" {
        return Ok(CustomerAdministratorGrantOutput {
            member_id: existing.id,
            email: input.email.clone(),
            role: AccountRole::Admin,
            outcome: CustomerAdministratorGrantOutcome::AlreadyAdministrator,
        });
    }
    if !matches!(existing.role.as_str(), "billing" | "viewer") {
        return Err(ApiError::Internal);
    }
    let updated = execute(
        db,
        "UPDATE account_members SET role = 'admin', updated_at = ? \
         WHERE id = ? AND account_id = ? AND deleted_at IS NULL",
        vec![
            bind_text(&now_iso()?),
            bind_text(&existing.id),
            bind_text(&input.account_id),
        ],
    )
    .await?;
    if updated != 1 {
        return Err(ApiError::Internal);
    }
    write_member_grant_audit(
        db,
        operator,
        input,
        &existing.id,
        Some(existing.role.as_str()),
        request_id,
    )
    .await?;
    Ok(CustomerAdministratorGrantOutput {
        member_id: existing.id,
        email: input.email.clone(),
        role: AccountRole::Admin,
        outcome: CustomerAdministratorGrantOutcome::Promoted,
    })
}

async fn write_member_grant_audit(
    db: &D1Database,
    operator: &OwnerOperator,
    input: &GrantCustomerAdministratorInput,
    member_id: &str,
    previous_role: Option<&str>,
    request_id: &str,
) -> Result<(), ApiError> {
    let action = if previous_role.is_some() {
        "account_member.administrator_promoted"
    } else {
        "account_member.administrator_added"
    };
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Owner,
            actor_id: Some(operator.email().as_str()),
            account_id: Some(&input.account_id),
            action,
            target_type: "account_member",
            target_id: Some(member_id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({
                "email": input.email.as_str(),
                "previous_role": previous_role,
                "role": "admin"
            }),
        },
    )
    .await
}

pub async fn owner_plans(db: &D1Database) -> Result<Value, ApiError> {
    let plans = all::<Value>(
        db,
        "SELECT id, key, name, description, status, modules_json, features_json, limits_json, trial_days, \
         sort_order, created_at, updated_at FROM plans ORDER BY sort_order, name",
        vec![],
    )
    .await?
    .into_iter()
    .map(expand_plan)
    .collect::<Vec<_>>();
    let prices = all::<Value>(
        db,
        "SELECT id, plan_id, provider, currency, currency_exponent, amount_minor, billing_interval, external_product_id, \
         external_price_id, status, created_at, updated_at FROM plan_prices \
         ORDER BY plan_id, provider, currency, billing_interval",
        vec![],
    )
    .await?;
    Ok(json!({ "plans": plans, "prices": prices }))
}

pub async fn update_plan(
    db: &D1Database,
    operator: &OwnerOperator,
    plan_id: &str,
    patch: PlanPatch,
    request_id: &str,
) -> Result<(), ApiError> {
    validate_plan_patch(&patch)?;
    let current = first::<PlanRow>(
        db,
        "SELECT name, description, status, modules_json, features_json, limits_json, trial_days, sort_order \
         FROM plans WHERE id = ?",
        vec![bind_text(plan_id)],
    )
    .await?
    .ok_or_else(|| ApiError::client("plan_not_found", "Plan not found", 404))?;
    let changed_fields = patch.changed_fields();
    let name = patch.name.unwrap_or(current.name);
    let description = patch.description.unwrap_or(current.description);
    let status = patch.status.unwrap_or(current.status);
    let modules_json = serialize_set(patch.modules, current.modules_json)?;
    let features_json = serialize_set(patch.features, current.features_json)?;
    let limits_json = patch.limits.map_or(Ok(current.limits_json), |limits| {
        serde_json::to_string(&limits).map_err(|_| ApiError::Internal)
    })?;
    let trial_days = patch.trial_days.unwrap_or(current.trial_days);
    let sort_order = patch.sort_order.unwrap_or(current.sort_order);
    execute(
        db,
        "UPDATE plans SET name = ?, description = ?, status = ?, modules_json = ?, \
         features_json = ?, limits_json = ?, trial_days = ?, sort_order = ?, updated_at = ? WHERE id = ?",
        vec![
            bind_text(&name),
            bind_text(&description),
            bind_text(&status),
            bind_text(&modules_json),
            bind_text(&features_json),
            bind_text(&limits_json),
            bind_i64(trial_days)?,
            bind_i64(sort_order)?,
            bind_text(&now_iso()?),
            bind_text(plan_id),
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Owner,
            actor_id: Some(operator.email().as_str()),
            account_id: None,
            action: "plan.updated",
            target_type: "plan",
            target_id: Some(plan_id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({ "changed_fields": changed_fields }),
        },
    )
    .await?;
    Ok(())
}

pub async fn create_plan_price(
    db: &D1Database,
    operator: &OwnerOperator,
    input: CreatePlanPriceInput,
    request_id: &str,
) -> Result<CreatedPlanPrice, ApiError> {
    let id = Uuid::new_v4().to_string();
    let created_at = now_iso()?;
    execute(
        db,
        "INSERT INTO plan_prices (id, plan_id, provider, currency, currency_exponent, amount_minor, billing_interval, \
         external_product_id, external_price_id, status, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            bind_text(&id),
            bind_text(&input.plan_id),
            bind_text(input.provider.as_str()),
            bind_text(input.money.currency.as_str()),
            bind_i64(i64::from(input.money.exponent))?,
            bind_i64(input.money.amount_minor)?,
            bind_text(&input.billing_interval),
            bind_optional_text(input.external_product_id.as_deref()),
            bind_text(&input.external_price_id),
            bind_text(&input.status),
            bind_text(&created_at),
            bind_text(&created_at),
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Owner,
            actor_id: Some(operator.email().as_str()),
            account_id: None,
            action: "plan_price.created",
            target_type: "plan_price",
            target_id: Some(&id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({
                "plan_id": input.plan_id,
                "provider": input.provider,
                "currency": input.money.currency,
                "currency_exponent": input.money.exponent,
                "billing_interval": input.billing_interval,
            }),
        },
    )
    .await?;
    Ok(CreatedPlanPrice { id })
}

pub async fn create_manual_subscription(
    db: &D1Database,
    operator: &OwnerOperator,
    account_id: &str,
    plan_id: &str,
    current_period_end: &str,
    request_id: &str,
) -> Result<String, ApiError> {
    uuid::Uuid::parse_str(account_id)
        .map_err(|_| invalid("account_id", "Expected a UUID account identifier"))?;
    required_text("plan_id", plan_id, 1, 120)?;
    let period_end = parse_iso_timestamp("current_period_end", current_period_end)?;
    if period_end <= now() {
        return Err(invalid(
            "current_period_end",
            "The subscription period must end in the future",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let created_at = now_iso()?;
    execute(
        db,
        "INSERT INTO subscriptions (id, account_id, plan_id, provider, status, current_period_start, \
         current_period_end, created_at, updated_at) VALUES (?, ?, ?, 'manual', 'active', ?, ?, ?, ?)",
        vec![
            bind_text(&id),
            bind_text(account_id),
            bind_text(plan_id),
            bind_text(&created_at),
            bind_text(current_period_end),
            bind_text(&created_at),
            bind_text(&created_at),
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Owner,
            actor_id: Some(operator.email().as_str()),
            account_id: Some(account_id),
            action: "subscription.manual_created",
            target_type: "subscription",
            target_id: Some(&id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({ "plan_id": plan_id, "current_period_end": current_period_end }),
        },
    )
    .await?;
    Ok(id)
}

pub async fn owner_installations(db: &D1Database) -> Result<Value, ApiError> {
    let rows = all::<Value>(
        db,
        "SELECT installations.id, installations.name, installations.tenant_id, installations.deployment_id, \
         installations.status, installations.credential_hint, installations.last_lease_sequence, \
         installations.last_seen_at, installations.created_at, accounts.id AS account_id, accounts.name AS account_name, \
         leases.lease_expires_at, leases.grace_until, leases.status AS lease_status FROM installations \
         INNER JOIN accounts ON accounts.id = installations.account_id \
         LEFT JOIN leases ON leases.id = installations.current_lease_id ORDER BY installations.created_at DESC",
        vec![],
    )
    .await?;
    Ok(json!({ "installations": rows }))
}

pub async fn revoke_installation(
    db: &D1Database,
    operator: &OwnerOperator,
    installation_id: &str,
    reason: &str,
    request_id: &str,
) -> Result<(), ApiError> {
    let reason = required_text("reason", reason, 3, 500)?;
    let installation = installation_by_id(db, installation_id)
        .await?
        .ok_or_else(|| ApiError::client("installation_not_found", "Installation not found", 404))?;
    let revoked_at = now_iso()?;
    batch(
        db,
        vec![
            prepared(
                db,
                "UPDATE installations SET status = 'revoked', revoked_at = ?, revoked_reason = ?, updated_at = ? WHERE id = ?",
                vec![
                    bind_text(&revoked_at),
                    bind_text(&reason),
                    bind_text(&revoked_at),
                    bind_text(installation_id),
                ],
            )?,
            prepared(
                db,
                "UPDATE leases SET status = 'revoked', revoked_at = ?, revoked_reason = ? \
                 WHERE installation_id = ? AND status = 'active'",
                vec![
                    bind_text(&revoked_at),
                    bind_text(&reason),
                    bind_text(installation_id),
                ],
            )?,
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Owner,
            actor_id: Some(operator.email().as_str()),
            account_id: Some(&installation.account_id),
            action: "installation.revoked",
            target_type: "installation",
            target_id: Some(installation_id),
            request_id: Some(request_id),
            reason: Some(&reason),
            metadata: &json!({}),
        },
    )
    .await?;
    Ok(())
}

pub async fn owner_leases(db: &D1Database) -> Result<Value, ApiError> {
    let rows = all::<Value>(
        db,
        "SELECT leases.id, leases.sequence, leases.status, leases.catalog_version, leases.issued_at, \
         leases.refresh_after, leases.lease_expires_at, leases.grace_until, leases.revoked_at, leases.revoked_reason, \
         installations.id AS installation_id, installations.name AS installation_name, accounts.id AS account_id, \
         accounts.name AS account_name FROM leases INNER JOIN installations ON installations.id = leases.installation_id \
         INNER JOIN accounts ON accounts.id = installations.account_id ORDER BY leases.issued_at DESC LIMIT 250",
        vec![],
    )
    .await?;
    Ok(json!({ "leases": rows }))
}

pub async fn owner_audit(db: &D1Database) -> Result<Value, ApiError> {
    let rows = all::<Value>(
        db,
        "SELECT audit_events.id, audit_events.actor_type, audit_events.actor_id, audit_events.action, \
         audit_events.target_type, audit_events.target_id, audit_events.request_id, audit_events.reason, \
         audit_events.metadata_json, audit_events.created_at, accounts.name AS account_name FROM audit_events \
         LEFT JOIN accounts ON accounts.id = audit_events.account_id ORDER BY audit_events.created_at DESC LIMIT 500",
        vec![],
    )
    .await?;
    Ok(json!({ "events": rows }))
}

impl PlanPatch {
    fn changed_fields(&self) -> Vec<&'static str> {
        let candidates = [
            (self.name.is_some(), "name"),
            (self.description.is_some(), "description"),
            (self.status.is_some(), "status"),
            (self.modules.is_some(), "modules"),
            (self.features.is_some(), "features"),
            (self.limits.is_some(), "limits"),
            (self.trial_days.is_some(), "trial_days"),
            (self.sort_order.is_some(), "sort_order"),
        ];
        candidates
            .into_iter()
            .filter_map(|(changed, field)| changed.then_some(field))
            .collect()
    }
}

fn validate_plan_patch(patch: &PlanPatch) -> Result<(), ApiError> {
    if let Some(name) = &patch.name {
        required_text("name", name, 2, 100)?;
    }
    if patch
        .description
        .as_ref()
        .is_some_and(|value| value.len() > 500)
    {
        return Err(invalid("description", "Use no more than 500 characters"));
    }
    if patch
        .status
        .as_ref()
        .is_some_and(|value| !matches!(value.as_str(), "draft" | "active" | "retired"))
    {
        return Err(invalid("status", "Expected draft, active, or retired"));
    }
    for (field, values) in [("modules", &patch.modules), ("features", &patch.features)] {
        if values
            .as_ref()
            .is_some_and(|values| values.iter().any(|value| !module_key_is_valid(value)))
        {
            return Err(invalid(field, "One or more keys are invalid"));
        }
    }
    if let Some(modules) = &patch.modules {
        validate_module_dependencies(modules)?;
    }
    if patch
        .limits
        .as_ref()
        .is_some_and(|limits| limits.iter().any(|limit| !limit.is_valid()))
    {
        return Err(invalid("limits", "One or more limits are invalid"));
    }
    if patch
        .trial_days
        .is_some_and(|value| !(0..=365).contains(&value))
    {
        return Err(invalid("trial_days", "Expected 0 to 365 days"));
    }
    Ok(())
}

fn validate_module_dependencies(modules: &[String]) -> Result<(), ApiError> {
    let modules = modules.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for (module, dependency) in [
        ("sis", "academics"),
        ("academics", "hr_payroll"),
        ("attendance", "academics"),
        ("attendance", "sis"),
        ("learning", "academics"),
        ("learning", "document_registry"),
        ("learning", "hr_payroll"),
        ("learning", "sis"),
        ("student_support", "sis"),
        ("transport", "fleet"),
        ("transport", "sis"),
        ("fleet", "hr_payroll"),
        ("timetabling", "academics"),
    ] {
        if modules.contains(module) && !modules.contains(dependency) {
            return Err(ApiError::Validation {
                issues: vec![FieldIssue {
                    field: "modules",
                    detail: format!("{module} requires {dependency}"),
                }],
            });
        }
    }
    Ok(())
}

fn serialize_set(next: Option<Vec<String>>, current: String) -> Result<String, ApiError> {
    next.map_or(Ok(current), |values| {
        serde_json::to_string(&values.into_iter().collect::<BTreeSet<_>>())
            .map_err(|_| ApiError::Internal)
    })
}

fn expand_plan(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        for (storage, public) in [
            ("modules_json", "modules"),
            ("features_json", "features"),
            ("limits_json", "limits"),
        ] {
            let parsed = object
                .remove(storage)
                .and_then(|stored| stored.as_str().map(str::to_owned))
                .and_then(|stored| serde_json::from_str(&stored).ok())
                .unwrap_or_else(|| json!([]));
            object.insert(public.to_owned(), parsed);
        }
    }
    value
}

pub(crate) fn slugify(value: &str) -> String {
    let mut slug = String::new();
    let mut previous_hyphen = false;
    for character in value.to_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
            previous_hyphen = false;
        } else if !previous_hyphen && !slug.is_empty() {
            slug.push('-');
            previous_hyphen = true;
        }
        if slug.len() >= 80 {
            break;
        }
    }
    let slug = slug.trim_end_matches('-');
    if slug.is_empty() {
        "customer".to_owned()
    } else {
        slug.to_owned()
    }
}

fn invalid(field: &'static str, detail: &'static str) -> ApiError {
    ApiError::Validation {
        issues: vec![FieldIssue {
            field,
            detail: detail.to_owned(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CustomerAdministratorGrantOutcome, CustomerAdministratorGrantOutput,
        GrantCustomerAdministratorInput, PlanPatch, slugify, validate_plan_patch,
    };
    use crate::auth::AccountRole;
    use crate::domain::CanonicalEmail;

    fn empty_patch() -> PlanPatch {
        PlanPatch {
            name: None,
            description: None,
            status: None,
            modules: None,
            features: None,
            limits: None,
            trial_days: None,
            sort_order: None,
        }
    }

    #[test]
    fn customer_slug_is_bounded_and_operational() {
        assert_eq!(
            slugify(" Gamenight School & Campus "),
            "gamenight-school-campus"
        );
        assert_eq!(slugify("???"), "customer");
    }

    #[test]
    fn plan_patch_rejects_impossible_values() {
        let mut patch = empty_patch();
        patch.status = Some("published".to_owned());
        assert!(validate_plan_patch(&patch).is_err());
        patch.status = Some("active".to_owned());
        patch.trial_days = Some(366);
        assert!(validate_plan_patch(&patch).is_err());
    }

    #[test]
    fn plan_patch_requires_runtime_module_dependencies() {
        let mut patch = empty_patch();
        patch.modules = Some(vec!["academics".to_owned()]);
        assert!(validate_plan_patch(&patch).is_err());

        patch.modules = Some(vec!["academics".to_owned(), "hr_payroll".to_owned()]);
        assert!(validate_plan_patch(&patch).is_ok());

        patch.modules = Some(vec![
            "sis".to_owned(),
            "academics".to_owned(),
            "hr_payroll".to_owned(),
        ]);
        assert!(validate_plan_patch(&patch).is_ok());

        patch.modules = Some(vec!["sis".to_owned(), "hr_payroll".to_owned()]);
        assert!(validate_plan_patch(&patch).is_err());

        patch.modules = Some(vec!["timetabling".to_owned(), "academics".to_owned()]);
        assert!(validate_plan_patch(&patch).is_err());

        patch.modules = Some(vec![
            "attendance".to_owned(),
            "academics".to_owned(),
            "hr_payroll".to_owned(),
        ]);
        assert!(validate_plan_patch(&patch).is_err());

        patch.modules = Some(vec![
            "attendance".to_owned(),
            "sis".to_owned(),
            "academics".to_owned(),
            "hr_payroll".to_owned(),
        ]);
        assert!(validate_plan_patch(&patch).is_ok());

        patch.modules = Some(vec![
            "learning".to_owned(),
            "sis".to_owned(),
            "academics".to_owned(),
            "hr_payroll".to_owned(),
        ]);
        assert!(validate_plan_patch(&patch).is_err());

        patch.modules = Some(vec![
            "learning".to_owned(),
            "sis".to_owned(),
            "academics".to_owned(),
            "hr_payroll".to_owned(),
            "document_registry".to_owned(),
        ]);
        assert!(validate_plan_patch(&patch).is_ok());

        patch.modules = Some(vec!["student_support".to_owned()]);
        assert!(validate_plan_patch(&patch).is_err());

        patch.modules = Some(vec!["student_support".to_owned(), "sis".to_owned()]);
        assert!(validate_plan_patch(&patch).is_ok());

        patch.modules = Some(vec!["transport".to_owned(), "fleet".to_owned()]);
        assert!(validate_plan_patch(&patch).is_err());

        patch.modules = Some(vec![
            "transport".to_owned(),
            "fleet".to_owned(),
            "sis".to_owned(),
            "academics".to_owned(),
            "hr_payroll".to_owned(),
        ]);
        assert!(validate_plan_patch(&patch).is_ok());
    }

    #[test]
    fn customer_administrator_grant_parses_identity_once() {
        let account_id = "6f8c5f04-1aa2-4a43-93f6-9f9cd622d09a";
        let input =
            GrantCustomerAdministratorInput::parse(account_id, "  ADMINISTRATOR@School.Example ")
                .unwrap_or_else(|_| unreachable!());
        assert_eq!(input.account_id, account_id);
        assert_eq!(input.email.as_str(), "administrator@school.example");
        assert!(
            GrantCustomerAdministratorInput::parse("not-an-account", "person@example.com").is_err()
        );
        assert!(GrantCustomerAdministratorInput::parse(account_id, "not-an-email").is_err());
    }

    #[test]
    fn idempotent_customer_grant_does_not_repeat_the_access_email() {
        let email =
            CanonicalEmail::parse("administrator@example.com").unwrap_or_else(|_| unreachable!());
        let mut output = CustomerAdministratorGrantOutput {
            member_id: "member-1".to_owned(),
            email,
            role: AccountRole::Admin,
            outcome: CustomerAdministratorGrantOutcome::Created,
        };
        assert!(output.requires_access_email());
        output.outcome = CustomerAdministratorGrantOutcome::AlreadyAdministrator;
        assert!(!output.requires_access_email());
    }
}
