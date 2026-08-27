//! Append-only audit event writer for owner, customer, installation, provider, and system actions.

use serde::Serialize;
use uuid::Uuid;
use worker::D1Database;

use crate::clock::now_iso;
use crate::error::ApiError;
use crate::store::{bind_optional_text, bind_text, execute};

#[derive(Debug, Clone, Copy)]
pub enum AuditActor {
    Customer,
    Owner,
    Installation,
    PaymentProvider,
}

impl AuditActor {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Customer => "customer",
            Self::Owner => "owner",
            Self::Installation => "installation",
            Self::PaymentProvider => "payment_provider",
        }
    }
}

#[derive(Debug)]
pub struct AuditEvent<'a, T: Serialize> {
    pub actor: AuditActor,
    pub actor_id: Option<&'a str>,
    pub account_id: Option<&'a str>,
    pub action: &'a str,
    pub target_type: &'a str,
    pub target_id: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub metadata: &'a T,
}

pub async fn write<T: Serialize>(
    db: &D1Database,
    event: &AuditEvent<'_, T>,
) -> Result<(), ApiError> {
    let metadata = safe_metadata(event.metadata)?;
    execute(
        db,
        "INSERT INTO audit_events (id, actor_type, actor_id, account_id, action, target_type, \
         target_id, request_id, reason, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            bind_text(&Uuid::new_v4().to_string()),
            bind_text(event.actor.as_str()),
            bind_optional_text(event.actor_id),
            bind_optional_text(event.account_id),
            bind_text(event.action),
            bind_text(event.target_type),
            bind_optional_text(event.target_id),
            bind_optional_text(event.request_id),
            bind_optional_text(event.reason),
            bind_text(&metadata),
            bind_text(&now_iso()?),
        ],
    )
    .await?;
    Ok(())
}

fn safe_metadata<T: Serialize>(metadata: &T) -> Result<String, ApiError> {
    let mut value = serde_json::to_value(metadata).map_err(|_| ApiError::Internal)?;
    truncate_strings(&mut value);
    serde_json::to_string(&value).map_err(|_| ApiError::Internal)
}

fn truncate_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) if text.len() > 512 => {
            text.truncate(509);
            text.push_str("...");
        }
        serde_json::Value::Array(items) => {
            for item in items {
                truncate_strings(item);
            }
        }
        serde_json::Value::Object(fields) => {
            for item in fields.values_mut() {
                truncate_strings(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::safe_metadata;

    #[test]
    fn audit_metadata_bounds_untrusted_strings() {
        let encoded = safe_metadata(&json!({ "value": "x".repeat(600) }));
        assert!(encoded.is_ok_and(|value| value.len() < 540 && value.contains("...")));
    }
}
