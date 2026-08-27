//! Provider-neutral billing orchestration with isolated payment-provider adapters.

mod stripe;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use worker::D1Database;

use crate::audit::{AuditActor, AuditEvent, write};
use crate::clock::{format, now, now_iso};
use crate::config::Config;
use crate::crypto::hash_secret;
use crate::domain::{PaymentProviderKey, required_text};
use crate::error::{ApiError, FieldIssue};
use crate::store::{all, bind_bool, bind_optional_text, bind_text, execute, first};

#[derive(Debug, Clone, Serialize)]
pub struct ProviderCapabilities {
    pub key: &'static str,
    pub display_name: &'static str,
    pub adapter_status: &'static str,
    pub checkout: bool,
    pub billing_portal: bool,
    pub recurring_subscriptions: bool,
    pub configured: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct PaymentTransactionRow {
    id: String,
    account_id: String,
    account_name: String,
    subscription_id: Option<String>,
    provider: String,
    external_payment_id: String,
    kind: String,
    status: String,
    currency: String,
    currency_exponent: i64,
    amount_minor: i64,
    settlement_currency: Option<String>,
    settlement_currency_exponent: Option<i64>,
    settlement_amount_minor: Option<i64>,
    occurred_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PaymentEventRow {
    id: String,
    provider: String,
    provider_event_id: String,
    event_type: String,
    processing_status: String,
    failure_reason: Option<String>,
    received_at: String,
    processed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AccountBillingRow {
    id: String,
    name: String,
    billing_email: String,
}

#[derive(Debug, Deserialize)]
struct PlanPriceRow {
    id: String,
    plan_id: String,
    provider: String,
    external_price_id: String,
    currency: String,
    currency_exponent: i64,
    amount_minor: i64,
    trial_days: i64,
}

#[derive(Debug, Deserialize)]
struct BillingCustomerRow {
    external_customer_id: String,
}

#[derive(Debug, Clone)]
pub(super) struct CustomerCommand {
    pub account_id: String,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub(super) struct CheckoutCommand {
    pub account_id: String,
    pub plan_id: String,
    pub plan_price_id: String,
    pub external_customer_id: String,
    pub external_price_id: String,
    pub trial_days: i64,
    pub idempotency_key: String,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BillingPortalSession {
    pub url: String,
}

#[derive(Debug)]
pub(super) enum NormalizedEvent {
    CheckoutCompleted {
        checkout_id: String,
        account_id: String,
        external_customer_id: String,
    },
    SubscriptionChanged(SubscriptionChange),
    InvoicePayment(InvoicePayment),
    Ignored,
}

#[derive(Debug)]
pub(super) struct SubscriptionChange {
    pub external_subscription_id: String,
    pub external_customer_id: String,
    pub external_price_id: String,
    pub status: &'static str,
    pub current_period_start: Option<String>,
    pub current_period_end: Option<String>,
    pub cancel_at_period_end: bool,
    pub ended_at: Option<String>,
}

#[derive(Debug)]
pub(super) struct InvoicePayment {
    pub external_subscription_id: String,
    pub external_customer_id: String,
    pub external_payment_id: String,
    pub external_price_id: Option<String>,
    pub subscription_status: &'static str,
    pub transaction_status: &'static str,
    pub currency: String,
    pub amount_minor: i64,
    pub occurred_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookResult {
    pub duplicate: bool,
    #[serde(rename = "type")]
    pub event_type: String,
}

#[derive(Debug)]
pub struct CheckoutRequest {
    pub account_id: String,
    pub plan_price_id: String,
    pub requested_by_email: String,
    pub idempotency_key: String,
}

impl CheckoutRequest {
    pub fn parse(
        account_id: &str,
        plan_price_id: &str,
        requested_by_email: &str,
        idempotency_key: &str,
    ) -> Result<Self, ApiError> {
        Ok(Self {
            account_id: parse_uuid("account_id", account_id)?,
            plan_price_id: parse_uuid("plan_price_id", plan_price_id)?,
            requested_by_email: requested_by_email.to_owned(),
            idempotency_key: required_text("idempotency_key", idempotency_key, 16, 120)?,
        })
    }
}

enum Adapter {
    Stripe(stripe::StripeAdapter),
}

impl Adapter {
    fn resolve(provider: &PaymentProviderKey, config: &Config) -> Result<Self, ApiError> {
        match provider.as_str() {
            "stripe" => Ok(Self::Stripe(stripe::StripeAdapter::from_config(config)?)),
            _ => Err(ApiError::client(
                "payment_provider_unavailable",
                "The selected payment provider is not configured",
                409,
            )),
        }
    }

    fn key(&self) -> &'static str {
        match self {
            Self::Stripe(adapter) => adapter.key(),
        }
    }

    fn signature_header(&self) -> &'static str {
        match self {
            Self::Stripe(adapter) => adapter.signature_header(),
        }
    }

    async fn create_customer(&self, command: &CustomerCommand) -> Result<String, ApiError> {
        match self {
            Self::Stripe(adapter) => adapter.create_customer(command).await,
        }
    }

    async fn create_checkout(
        &self,
        command: &CheckoutCommand,
    ) -> Result<CheckoutSession, ApiError> {
        match self {
            Self::Stripe(adapter) => adapter.create_checkout(command).await,
        }
    }

    async fn create_billing_portal(
        &self,
        external_customer_id: &str,
        return_url: &str,
    ) -> Result<BillingPortalSession, ApiError> {
        match self {
            Self::Stripe(adapter) => {
                adapter
                    .create_billing_portal(external_customer_id, return_url)
                    .await
            }
        }
    }

    fn verify_and_normalize(
        &self,
        body: &str,
        signature: &str,
        now_unix: i64,
    ) -> Result<(String, String, NormalizedEvent), ApiError> {
        match self {
            Self::Stripe(adapter) => adapter.verify_and_normalize(body, signature, now_unix),
        }
    }
}

pub fn providers(config: &Config) -> Vec<ProviderCapabilities> {
    vec![
        stripe::StripeAdapter::capabilities(config),
        planned_provider("paypal", "PayPal"),
        planned_provider("paynow", "Paynow Zimbabwe"),
        planned_provider("pesepay", "Pesepay"),
    ]
}

const fn planned_provider(key: &'static str, display_name: &'static str) -> ProviderCapabilities {
    ProviderCapabilities {
        key,
        display_name,
        adapter_status: "planned",
        checkout: false,
        billing_portal: false,
        recurring_subscriptions: false,
        configured: false,
    }
}

pub async fn owner_payment_activity(db: &D1Database, config: &Config) -> Result<Value, ApiError> {
    let transactions = all::<PaymentTransactionRow>(
        db,
        "SELECT payment_transactions.id, payment_transactions.account_id, accounts.name AS account_name, \
         payment_transactions.subscription_id, payment_transactions.provider, \
         payment_transactions.external_payment_id, payment_transactions.kind, payment_transactions.status, \
         payment_transactions.currency, payment_transactions.currency_exponent, \
         payment_transactions.amount_minor, payment_transactions.settlement_currency, \
         payment_transactions.settlement_currency_exponent, payment_transactions.settlement_amount_minor, \
         payment_transactions.occurred_at FROM payment_transactions \
         INNER JOIN accounts ON accounts.id = payment_transactions.account_id \
         ORDER BY payment_transactions.occurred_at DESC LIMIT 200",
        vec![],
    )
    .await?;
    let events = all::<PaymentEventRow>(
        db,
        "SELECT id, provider, provider_event_id, event_type, processing_status, failure_reason, \
         received_at, processed_at FROM payment_events ORDER BY received_at DESC LIMIT 200",
        vec![],
    )
    .await?;
    Ok(json!({
        "providers": providers(config),
        "transactions": transactions,
        "events": events,
    }))
}

pub fn webhook_signature_header(
    provider: &PaymentProviderKey,
    config: &Config,
) -> Result<&'static str, ApiError> {
    Ok(Adapter::resolve(provider, config)?.signature_header())
}

#[allow(clippy::too_many_lines)]
pub async fn create_checkout(
    db: &D1Database,
    input: &CheckoutRequest,
    config: &Config,
    request_id: &str,
) -> Result<CheckoutSession, ApiError> {
    let account = first::<AccountBillingRow>(
        db,
        "SELECT id, name, billing_email FROM accounts \
         WHERE id = ? AND status = 'active' AND deleted_at IS NULL",
        vec![bind_text(&input.account_id)],
    )
    .await?
    .ok_or_else(|| {
        ApiError::client(
            "account_unavailable",
            "The customer account is not active",
            409,
        )
    })?;
    let price = first::<PlanPriceRow>(
        db,
        "SELECT plan_prices.id, plan_prices.plan_id, plan_prices.provider, plan_prices.external_price_id, \
         plan_prices.currency, plan_prices.currency_exponent, plan_prices.amount_minor, \
         plans.trial_days FROM plan_prices INNER JOIN plans ON plans.id = plan_prices.plan_id \
         WHERE plan_prices.id = ? AND plan_prices.status = 'active' AND plans.status = 'active'",
        vec![bind_text(&input.plan_price_id)],
    )
    .await?
    .ok_or_else(|| {
        ApiError::client(
            "plan_price_unavailable",
            "This payment option is not available",
            409,
        )
    })?;
    let provider = PaymentProviderKey::parse(&price.provider).map_err(|_| ApiError::Internal)?;
    let adapter = Adapter::resolve(&provider, config)?;
    let external_customer_id = match first::<BillingCustomerRow>(
        db,
        "SELECT external_customer_id FROM billing_customers WHERE account_id = ? AND provider = ?",
        vec![bind_text(&account.id), bind_text(provider.as_str())],
    )
    .await?
    {
        Some(customer) => customer.external_customer_id,
        None => {
            let external_id = adapter
                .create_customer(&CustomerCommand {
                    account_id: account.id.clone(),
                    name: account.name,
                    email: account.billing_email,
                })
                .await?;
            let current = now_iso()?;
            execute(
                db,
                "INSERT INTO billing_customers (id, account_id, provider, external_customer_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                vec![
                    bind_text(&Uuid::new_v4().to_string()),
                    bind_text(&account.id),
                    bind_text(adapter.key()),
                    bind_text(&external_id),
                    bind_text(&current),
                    bind_text(&current),
                ],
            )
            .await?;
            external_id
        }
    };
    let command = CheckoutCommand {
        account_id: account.id.clone(),
        plan_id: price.plan_id.clone(),
        plan_price_id: price.id.clone(),
        external_customer_id,
        external_price_id: price.external_price_id,
        trial_days: price.trial_days,
        idempotency_key: input.idempotency_key.clone(),
        success_url: format!(
            "{}/?checkout=complete&session_id={{CHECKOUT_SESSION_ID}}",
            config.public_app_url.trim_end_matches('/')
        ),
        cancel_url: format!(
            "{}/?checkout=cancelled",
            config.public_app_url.trim_end_matches('/')
        ),
    };
    let session = adapter.create_checkout(&command).await?;
    let created_at = now_iso()?;
    execute(
        db,
        "INSERT INTO checkout_attempts (id, account_id, plan_id, plan_price_id, requested_by_email, idempotency_key, \
         provider, provider_checkout_id, quoted_currency, quoted_currency_exponent, quoted_amount_minor, \
         status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'created', ?, ?) \
         ON CONFLICT(idempotency_key) DO UPDATE SET \
         provider = excluded.provider, provider_checkout_id = excluded.provider_checkout_id, \
         updated_at = excluded.updated_at",
        vec![
            bind_text(&Uuid::new_v4().to_string()),
            bind_text(&account.id),
            bind_text(&price.plan_id),
            bind_text(&price.id),
            bind_text(&input.requested_by_email),
            bind_text(&input.idempotency_key),
            bind_text(adapter.key()),
            bind_text(&session.id),
            bind_text(&price.currency),
            crate::store::bind_i64(price.currency_exponent)?,
            crate::store::bind_i64(price.amount_minor)?,
            bind_text(&created_at),
            bind_text(&created_at),
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Customer,
            actor_id: Some(&input.requested_by_email),
            account_id: Some(&account.id),
            action: "checkout.started",
            target_type: "checkout_session",
            target_id: Some(&session.id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({
                "plan_id": price.plan_id,
                "plan_price_id": price.id,
                "provider": adapter.key(),
            }),
        },
    )
    .await?;
    Ok(session)
}

pub async fn create_billing_portal(
    db: &D1Database,
    account_id: &str,
    provider: &PaymentProviderKey,
    config: &Config,
) -> Result<BillingPortalSession, ApiError> {
    let adapter = Adapter::resolve(provider, config)?;
    let customer = first::<BillingCustomerRow>(
        db,
        "SELECT external_customer_id FROM billing_customers WHERE account_id = ? AND provider = ?",
        vec![bind_text(account_id), bind_text(provider.as_str())],
    )
    .await?
    .ok_or_else(|| {
        ApiError::client(
            "billing_unavailable",
            "No billing account exists for this provider",
            409,
        )
    })?;
    adapter
        .create_billing_portal(&customer.external_customer_id, &config.public_app_url)
        .await
}

pub async fn process_webhook(
    db: &D1Database,
    provider: &PaymentProviderKey,
    raw_body: &str,
    signature: &str,
    config: &Config,
    request_id: &str,
) -> Result<WebhookResult, ApiError> {
    let adapter = Adapter::resolve(provider, config)?;
    let (event_id, event_type, event) =
        adapter.verify_and_normalize(raw_body, signature, now().unix_timestamp())?;
    let existing = first::<Value>(
        db,
        "SELECT processing_status FROM payment_events WHERE provider = ? AND provider_event_id = ?",
        vec![bind_text(adapter.key()), bind_text(&event_id)],
    )
    .await?;
    if existing.is_some_and(|row| {
        matches!(
            row.get("processing_status").and_then(Value::as_str),
            Some("processed" | "ignored")
        )
    }) {
        return Ok(WebhookResult {
            duplicate: true,
            event_type,
        });
    }
    let received_at = now_iso()?;
    execute(
        db,
        "INSERT INTO payment_events (id, provider, provider_event_id, event_type, payload_hash, \
         processing_status, received_at) VALUES (?, ?, ?, ?, ?, 'processing', ?) \
         ON CONFLICT(provider, provider_event_id) DO UPDATE SET processing_status = 'processing', failure_reason = NULL",
        vec![
            bind_text(&Uuid::new_v4().to_string()),
            bind_text(adapter.key()),
            bind_text(&event_id),
            bind_text(&event_type),
            bind_text(&hash_secret(raw_body, None)),
            bind_text(&received_at),
        ],
    )
    .await?;
    let handled = apply_event(db, adapter.key(), &event_id, event, config, request_id).await;
    match handled {
        Ok(handled) => {
            execute(
                db,
                "UPDATE payment_events SET processing_status = ?, processed_at = ? \
                 WHERE provider = ? AND provider_event_id = ?",
                vec![
                    bind_text(if handled { "processed" } else { "ignored" }),
                    bind_text(&now_iso()?),
                    bind_text(adapter.key()),
                    bind_text(&event_id),
                ],
            )
            .await?;
        }
        Err(error) => {
            execute(
                db,
                "UPDATE payment_events SET processing_status = 'failed', failure_reason = ?, processed_at = ? \
                 WHERE provider = ? AND provider_event_id = ?",
                vec![
                    bind_text(error.code()),
                    bind_text(&now_iso()?),
                    bind_text(adapter.key()),
                    bind_text(&event_id),
                ],
            )
            .await?;
            return Err(error);
        }
    }
    Ok(WebhookResult {
        duplicate: false,
        event_type,
    })
}

async fn apply_event(
    db: &D1Database,
    provider: &str,
    event_id: &str,
    event: NormalizedEvent,
    config: &Config,
    request_id: &str,
) -> Result<bool, ApiError> {
    match event {
        NormalizedEvent::CheckoutCompleted {
            checkout_id,
            account_id,
            external_customer_id,
        } => {
            let current = now_iso()?;
            execute(
                db,
                "INSERT INTO billing_customers (id, account_id, provider, external_customer_id, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(account_id, provider) DO UPDATE SET \
                 external_customer_id = excluded.external_customer_id, updated_at = excluded.updated_at",
                vec![
                    bind_text(&Uuid::new_v4().to_string()),
                    bind_text(&account_id),
                    bind_text(provider),
                    bind_text(&external_customer_id),
                    bind_text(&current),
                    bind_text(&current),
                ],
            )
            .await?;
            execute(
                db,
                "UPDATE checkout_attempts SET status = 'completed', updated_at = ? \
                 WHERE provider = ? AND provider_checkout_id = ?",
                vec![
                    bind_text(&current),
                    bind_text(provider),
                    bind_text(&checkout_id),
                ],
            )
            .await?;
            write(
                db,
                &AuditEvent {
                    actor: AuditActor::PaymentProvider,
                    actor_id: Some(event_id),
                    account_id: Some(&account_id),
                    action: "checkout.completed",
                    target_type: "checkout_session",
                    target_id: Some(&checkout_id),
                    request_id: Some(request_id),
                    reason: None,
                    metadata: &json!({ "provider": provider }),
                },
            )
            .await?;
            Ok(true)
        }
        NormalizedEvent::SubscriptionChanged(change) => {
            sync_subscription(db, provider, event_id, change, config, request_id).await?;
            Ok(true)
        }
        NormalizedEvent::InvoicePayment(payment) => {
            let grace = if payment.subscription_status == "past_due" {
                Some(format(now() + Duration::days(config.lease_grace_days))?)
            } else {
                None
            };
            execute(
                db,
                "UPDATE subscriptions SET status = ?, grace_until = ?, updated_at = ? \
                 WHERE provider = ? AND external_subscription_id = ?",
                vec![
                    bind_text(payment.subscription_status),
                    bind_optional_text(grace.as_deref()),
                    bind_text(&now_iso()?),
                    bind_text(provider),
                    bind_text(&payment.external_subscription_id),
                ],
            )
            .await?;
            record_invoice_payment(db, provider, event_id, &payment, request_id).await?;
            Ok(true)
        }
        NormalizedEvent::Ignored => Ok(false),
    }
}

async fn record_invoice_payment(
    db: &D1Database,
    provider: &str,
    event_id: &str,
    payment: &InvoicePayment,
    request_id: &str,
) -> Result<(), ApiError> {
    let subscription = first::<Value>(
        db,
        "SELECT id, account_id, billing_currency, billing_currency_exponent FROM subscriptions \
         WHERE provider = ? AND external_subscription_id = ?",
        vec![
            bind_text(provider),
            bind_text(&payment.external_subscription_id),
        ],
    )
    .await?
    .ok_or(ApiError::Dependency)?;
    let subscription_id = value_text(&subscription, "id")?;
    let account_id = value_text(&subscription, "account_id")?;
    let billing_currency = value_text(&subscription, "billing_currency")?;
    let currency_exponent = if billing_currency == payment.currency {
        value_i64(&subscription, "billing_currency_exponent")?
    } else if let Some(external_price_id) = payment.external_price_id.as_deref() {
        first::<Value>(
            db,
            "SELECT currency_exponent FROM plan_prices WHERE provider = ? AND external_price_id = ? AND currency = ?",
            vec![
                bind_text(provider),
                bind_text(external_price_id),
                bind_text(&payment.currency),
            ],
        )
        .await?
        .and_then(|row| row.get("currency_exponent").and_then(Value::as_i64))
        .ok_or(ApiError::Dependency)?
    } else {
        return Err(ApiError::Dependency);
    };
    let exponent = u8::try_from(currency_exponent).map_err(|_| ApiError::Dependency)?;
    let money = crate::domain::Money::price(&payment.currency, exponent, payment.amount_minor)
        .map_err(|_| ApiError::Dependency)?;
    let current = now_iso()?;
    let occurred_at = payment.occurred_at.as_deref().unwrap_or(&current);
    execute(
        db,
        "INSERT INTO payment_transactions (id, account_id, subscription_id, provider, external_payment_id, \
         kind, status, currency, currency_exponent, amount_minor, occurred_at, metadata_json, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, 'charge', ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(provider, external_payment_id) DO UPDATE SET subscription_id = excluded.subscription_id, \
         status = excluded.status, currency = excluded.currency, currency_exponent = excluded.currency_exponent, \
         amount_minor = excluded.amount_minor, occurred_at = excluded.occurred_at, \
         metadata_json = excluded.metadata_json, updated_at = excluded.updated_at",
        vec![
            bind_text(&Uuid::new_v4().to_string()),
            bind_text(&account_id),
            bind_text(&subscription_id),
            bind_text(provider),
            bind_text(&payment.external_payment_id),
            bind_text(payment.transaction_status),
            bind_text(money.currency.as_str()),
            crate::store::bind_i64(i64::from(money.exponent))?,
            crate::store::bind_i64(money.amount_minor)?,
            bind_text(occurred_at),
            bind_text(&json!({
                "provider_event_id": event_id,
                "external_customer_id": payment.external_customer_id,
            }).to_string()),
            bind_text(&current),
            bind_text(&current),
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::PaymentProvider,
            actor_id: Some(event_id),
            account_id: Some(&account_id),
            action: "payment.recorded",
            target_type: "payment_transaction",
            target_id: Some(&payment.external_payment_id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({
                "provider": provider,
                "status": payment.transaction_status,
                "currency": money.currency,
                "currency_exponent": money.exponent,
                "amount_minor": money.amount_minor,
            }),
        },
    )
    .await?;
    Ok(())
}

async fn sync_subscription(
    db: &D1Database,
    provider: &str,
    event_id: &str,
    change: SubscriptionChange,
    config: &Config,
    request_id: &str,
) -> Result<(), ApiError> {
    let customer = first::<Value>(
        db,
        "SELECT account_id FROM billing_customers WHERE provider = ? AND external_customer_id = ?",
        vec![bind_text(provider), bind_text(&change.external_customer_id)],
    )
    .await?
    .and_then(|row| {
        row.get("account_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
    .ok_or(ApiError::Dependency)?;
    let price = first::<Value>(
        db,
        "SELECT id, plan_id, currency, currency_exponent, amount_minor FROM plan_prices \
         WHERE provider = ? AND external_price_id = ?",
        vec![bind_text(provider), bind_text(&change.external_price_id)],
    )
    .await?
    .ok_or(ApiError::Dependency)?;
    let plan_price_id = value_text(&price, "id")?;
    let plan_id = value_text(&price, "plan_id")?;
    let billing_currency = value_text(&price, "currency")?;
    let billing_currency_exponent = value_i64(&price, "currency_exponent")?;
    let billing_amount_minor = value_i64(&price, "amount_minor")?;
    let grace = if change.status == "past_due" {
        Some(format(now() + Duration::days(config.lease_grace_days))?)
    } else {
        None
    };
    let current = now_iso()?;
    execute(
        db,
        "INSERT INTO subscriptions (id, account_id, plan_id, plan_price_id, provider, external_customer_id, \
         external_subscription_id, status, billing_currency, billing_currency_exponent, billing_amount_minor, \
         current_period_start, current_period_end, cancel_at_period_end, grace_until, ended_at, metadata_json, \
         created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(provider, external_subscription_id) DO UPDATE SET account_id = excluded.account_id, \
         plan_id = excluded.plan_id, plan_price_id = excluded.plan_price_id, \
         external_customer_id = excluded.external_customer_id, status = excluded.status, \
         billing_currency = excluded.billing_currency, \
         billing_currency_exponent = excluded.billing_currency_exponent, \
         billing_amount_minor = excluded.billing_amount_minor, \
         current_period_start = excluded.current_period_start, current_period_end = excluded.current_period_end, \
         cancel_at_period_end = excluded.cancel_at_period_end, grace_until = excluded.grace_until, \
         ended_at = excluded.ended_at, metadata_json = excluded.metadata_json, updated_at = excluded.updated_at",
        vec![
            bind_text(&Uuid::new_v4().to_string()),
            bind_text(&customer),
            bind_text(&plan_id),
            bind_text(&plan_price_id),
            bind_text(provider),
            bind_text(&change.external_customer_id),
            bind_text(&change.external_subscription_id),
            bind_text(change.status),
            bind_text(&billing_currency),
            crate::store::bind_i64(billing_currency_exponent)?,
            crate::store::bind_i64(billing_amount_minor)?,
            bind_optional_text(change.current_period_start.as_deref()),
            bind_optional_text(change.current_period_end.as_deref()),
            bind_bool(change.cancel_at_period_end),
            bind_optional_text(grace.as_deref()),
            bind_optional_text(change.ended_at.as_deref()),
            bind_text(&json!({ "provider_event_id": event_id }).to_string()),
            bind_text(&current),
            bind_text(&current),
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::PaymentProvider,
            actor_id: Some(event_id),
            account_id: Some(&customer),
            action: "subscription.synced",
            target_type: "subscription",
            target_id: Some(&change.external_subscription_id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({
                "provider": provider,
                "status": change.status,
                "plan_id": plan_id,
                "plan_price_id": plan_price_id,
            }),
        },
    )
    .await?;
    Ok(())
}

pub(super) fn timestamp_to_iso(value: Option<&Value>) -> Result<Option<String>, ApiError> {
    value
        .and_then(Value::as_i64)
        .map(|seconds| {
            OffsetDateTime::from_unix_timestamp(seconds)
                .map_err(|_| ApiError::Dependency)
                .and_then(format)
        })
        .transpose()
}

fn parse_uuid(field: &'static str, value: &str) -> Result<String, ApiError> {
    Uuid::parse_str(value)
        .map(|value| value.to_string())
        .map_err(|_| invalid(field, "Expected a UUID identifier"))
}

fn value_text(value: &Value, field: &'static str) -> Result<String, ApiError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ApiError::Internal)
}

fn value_i64(value: &Value, field: &'static str) -> Result<i64, ApiError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(ApiError::Internal)
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
    use super::CheckoutRequest;

    #[test]
    fn checkout_references_provider_neutral_price_mapping() {
        let request = CheckoutRequest::parse(
            "120413ff-2c32-4af5-b526-b1522077cc1f",
            "2f52de02-a574-420d-a125-739f4b9f118a",
            "billing@example.com",
            "checkout-attempt-0001",
        );
        assert!(request.is_ok());
    }
}
