//! Stripe adapter implementing the provider-neutral billing contract.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde_json::Value;
use worker::wasm_bindgen::JsValue;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use super::{
    BillingPortalSession, CheckoutCommand, CheckoutSession, CustomerCommand, InvoicePayment,
    NormalizedEvent, ProviderCapabilities, SubscriptionChange, timestamp_to_iso,
};
use crate::config::Config;
use crate::crypto::{constant_time_equal, hmac_sha256_hex};
use crate::error::ApiError;

const API_ROOT: &str = "https://api.stripe.com";
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

pub(super) struct StripeAdapter {
    secret_key: String,
    webhook_secret: Option<String>,
}

impl StripeAdapter {
    pub(super) fn from_config(config: &Config) -> Result<Self, ApiError> {
        let secret_key = config.stripe_secret_key.clone().ok_or_else(|| {
            ApiError::client(
                "payment_provider_unavailable",
                "The selected payment provider is not configured",
                409,
            )
        })?;
        Ok(Self {
            secret_key,
            webhook_secret: config.stripe_webhook_secret.clone(),
        })
    }

    pub(super) fn capabilities(config: &Config) -> ProviderCapabilities {
        ProviderCapabilities {
            key: "stripe",
            display_name: "Stripe",
            adapter_status: "available",
            checkout: true,
            billing_portal: true,
            recurring_subscriptions: true,
            configured: config.stripe_secret_key.is_some(),
        }
    }

    pub(super) fn key(&self) -> &'static str {
        "stripe"
    }

    pub(super) fn signature_header(&self) -> &'static str {
        "stripe-signature"
    }

    pub(super) async fn create_customer(
        &self,
        command: &CustomerCommand,
    ) -> Result<String, ApiError> {
        let parameters = BTreeMap::from([
            ("name".to_owned(), command.name.clone()),
            ("email".to_owned(), command.email.clone()),
            (
                "metadata[account_id]".to_owned(),
                command.account_id.clone(),
            ),
        ]);
        let customer: Value = self
            .post(
                "/v1/customers",
                &parameters,
                Some(&format!("customer-{}", command.account_id)),
            )
            .await?;
        required_string(&customer, "/id").map(str::to_owned)
    }

    pub(super) async fn create_checkout(
        &self,
        command: &CheckoutCommand,
    ) -> Result<CheckoutSession, ApiError> {
        let mut parameters = BTreeMap::from([
            ("mode".to_owned(), "subscription".to_owned()),
            ("customer".to_owned(), command.external_customer_id.clone()),
            (
                "line_items[0][price]".to_owned(),
                command.external_price_id.clone(),
            ),
            ("line_items[0][quantity]".to_owned(), "1".to_owned()),
            ("success_url".to_owned(), command.success_url.clone()),
            ("cancel_url".to_owned(), command.cancel_url.clone()),
            ("client_reference_id".to_owned(), command.account_id.clone()),
            (
                "metadata[account_id]".to_owned(),
                command.account_id.clone(),
            ),
            ("metadata[plan_id]".to_owned(), command.plan_id.clone()),
            (
                "metadata[plan_price_id]".to_owned(),
                command.plan_price_id.clone(),
            ),
            (
                "subscription_data[metadata][account_id]".to_owned(),
                command.account_id.clone(),
            ),
            (
                "subscription_data[metadata][plan_id]".to_owned(),
                command.plan_id.clone(),
            ),
            (
                "subscription_data[metadata][plan_price_id]".to_owned(),
                command.plan_price_id.clone(),
            ),
            ("allow_promotion_codes".to_owned(), "true".to_owned()),
        ]);
        if command.trial_days > 0 {
            parameters.insert(
                "subscription_data[trial_period_days]".to_owned(),
                command.trial_days.to_string(),
            );
        }
        self.post(
            "/v1/checkout/sessions",
            &parameters,
            Some(&command.idempotency_key),
        )
        .await
    }

    pub(super) async fn create_billing_portal(
        &self,
        external_customer_id: &str,
        return_url: &str,
    ) -> Result<BillingPortalSession, ApiError> {
        self.post(
            "/v1/billing_portal/sessions",
            &BTreeMap::from([
                ("customer".to_owned(), external_customer_id.to_owned()),
                ("return_url".to_owned(), return_url.to_owned()),
            ]),
            None,
        )
        .await
    }

    pub(super) fn verify_and_normalize(
        &self,
        body: &str,
        signature: &str,
        now_unix: i64,
    ) -> Result<(String, String, NormalizedEvent), ApiError> {
        let webhook_secret = self
            .webhook_secret
            .as_deref()
            .ok_or(ApiError::Configuration)?;
        verify_signature(body, signature, webhook_secret, now_unix)?;
        let event: Value = serde_json::from_str(body).map_err(|_| invalid_event())?;
        let event_id = required_string(&event, "/id")?.to_owned();
        let event_type = required_string(&event, "/type")?.to_owned();
        let object = event.pointer("/data/object").ok_or_else(invalid_event)?;
        let normalized = match event_type.as_str() {
            "checkout.session.completed" => NormalizedEvent::CheckoutCompleted {
                checkout_id: required_string(object, "/id")?.to_owned(),
                account_id: object
                    .pointer("/metadata/account_id")
                    .and_then(Value::as_str)
                    .or_else(|| object.get("client_reference_id").and_then(Value::as_str))
                    .ok_or_else(invalid_event)?
                    .to_owned(),
                external_customer_id: stripe_id(object.get("customer"))
                    .ok_or_else(invalid_event)?
                    .to_owned(),
            },
            "customer.subscription.created"
            | "customer.subscription.updated"
            | "customer.subscription.deleted" => {
                NormalizedEvent::SubscriptionChanged(SubscriptionChange {
                    external_subscription_id: required_string(object, "/id")?.to_owned(),
                    external_customer_id: stripe_id(object.get("customer"))
                        .ok_or_else(invalid_event)?
                        .to_owned(),
                    external_price_id: required_string(object, "/items/data/0/price/id")?
                        .to_owned(),
                    status: map_status(
                        object
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("incomplete"),
                    ),
                    current_period_start: timestamp_to_iso(object.get("current_period_start"))?,
                    current_period_end: timestamp_to_iso(object.get("current_period_end"))?.or(
                        timestamp_to_iso(object.pointer("/items/data/0/current_period_end"))?,
                    ),
                    cancel_at_period_end: object
                        .get("cancel_at_period_end")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    ended_at: timestamp_to_iso(object.get("ended_at"))?,
                })
            }
            "invoice.paid" | "invoice.payment_failed" => {
                let subscription = stripe_id(object.get("subscription"))
                    .or_else(|| {
                        stripe_id(object.pointer("/parent/subscription_details/subscription"))
                    })
                    .ok_or_else(invalid_event)?;
                let paid = event_type == "invoice.paid";
                let amount_minor = object
                    .get(if paid { "amount_paid" } else { "amount_due" })
                    .and_then(Value::as_i64)
                    .filter(|amount| *amount >= 0)
                    .ok_or_else(invalid_event)?;
                let currency = required_string(object, "/currency")?.to_uppercase();
                let external_payment_id = stripe_id(object.get("payment_intent"))
                    .unwrap_or(required_string(object, "/id")?)
                    .to_owned();
                let external_price_id = object
                    .pointer("/lines/data/0/pricing/price_details/price")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        object
                            .pointer("/lines/data/0/price/id")
                            .and_then(Value::as_str)
                    })
                    .map(str::to_owned);
                NormalizedEvent::InvoicePayment(InvoicePayment {
                    external_subscription_id: subscription.to_owned(),
                    external_customer_id: stripe_id(object.get("customer"))
                        .ok_or_else(invalid_event)?
                        .to_owned(),
                    external_payment_id,
                    external_price_id,
                    subscription_status: if paid { "active" } else { "past_due" },
                    transaction_status: if paid { "succeeded" } else { "failed" },
                    currency,
                    amount_minor,
                    occurred_at: timestamp_to_iso(
                        object
                            .pointer("/status_transitions/paid_at")
                            .or_else(|| object.get("created")),
                    )?,
                })
            }
            _ => NormalizedEvent::Ignored,
        };
        Ok((event_id, event_type, normalized))
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        parameters: &BTreeMap<String, String>,
        idempotency_key: Option<&str>,
    ) -> Result<T, ApiError> {
        let body = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.extend_pairs(parameters);
            serializer.finish()
        };
        let headers = Headers::new();
        headers
            .set("authorization", &format!("Bearer {}", self.secret_key))
            .map_err(ApiError::from)?;
        headers
            .set("content-type", "application/x-www-form-urlencoded")
            .map_err(ApiError::from)?;
        if let Some(key) = idempotency_key {
            headers
                .set("idempotency-key", key)
                .map_err(ApiError::from)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(JsValue::from_str(&body)));
        let request =
            Request::new_with_init(&format!("{API_ROOT}{path}"), &init).map_err(ApiError::from)?;
        let mut response = Fetch::Request(request)
            .send()
            .await
            .map_err(|_| ApiError::Dependency)?;
        let status = response.status_code();
        let body = response.text().await.map_err(|_| ApiError::Dependency)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(ApiError::Dependency);
        }
        if !(200..300).contains(&status) {
            return Err(ApiError::client(
                "payment_provider_request_failed",
                "The payment provider could not complete the request",
                502,
            ));
        }
        serde_json::from_str(&body).map_err(|_| ApiError::Dependency)
    }
}

pub(super) fn verify_signature(
    body: &str,
    header: &str,
    secret: &str,
    now_unix: i64,
) -> Result<(), ApiError> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        if let Some((key, value)) = part.trim().split_once('=') {
            match key {
                "t" => timestamp = value.parse::<i64>().ok(),
                "v1" => signatures.push(value),
                _ => {}
            }
        }
    }
    let timestamp = timestamp.ok_or_else(invalid_signature)?;
    if signatures.is_empty() || now_unix.abs_diff(timestamp) > 300 {
        return Err(invalid_signature());
    }
    let expected = hmac_sha256_hex(secret, &format!("{timestamp}.{body}"))?;
    if signatures
        .into_iter()
        .any(|signature| constant_time_equal(signature, &expected))
    {
        Ok(())
    } else {
        Err(invalid_signature())
    }
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, ApiError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid_event)
}

fn stripe_id(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(value)) => Some(value.as_str()),
        Some(Value::Object(value)) => value.get("id").and_then(Value::as_str),
        _ => None,
    }
}

fn map_status(status: &str) -> &'static str {
    match status {
        "trialing" => "trialing",
        "active" => "active",
        "past_due" => "past_due",
        "unpaid" => "unpaid",
        "canceled" => "cancelled",
        "paused" => "paused",
        "incomplete_expired" => "expired",
        _ => "incomplete",
    }
}

fn invalid_event() -> ApiError {
    ApiError::client(
        "webhook_invalid",
        "The payment provider event is incomplete",
        400,
    )
}

fn invalid_signature() -> ApiError {
    ApiError::client(
        "webhook_signature_invalid",
        "The payment provider signature is invalid",
        400,
    )
}

#[cfg(test)]
mod tests {
    use super::{map_status, verify_signature};
    use crate::crypto::hmac_sha256_hex;

    #[test]
    fn stripe_signature_accepts_valid_hmac_and_rejects_replay() {
        let body = r#"{"id":"evt_1"}"#;
        let timestamp = 1_700_000_000_i64;
        let signature = match hmac_sha256_hex("whsec_test", &format!("{timestamp}.{body}")) {
            Ok(value) => value,
            Err(error) => panic!("test hmac failed: {error}"),
        };
        assert!(
            verify_signature(
                body,
                &format!("t={timestamp},v1={signature}"),
                "whsec_test",
                timestamp
            )
            .is_ok()
        );
        assert!(verify_signature(body, "t=1,v1=bad", "secret", 1_000).is_err());
    }

    #[test]
    fn stripe_statuses_map_into_core_vocabulary() {
        assert_eq!(map_status("canceled"), "cancelled");
        assert_eq!(map_status("unknown"), "incomplete");
    }
}
