//! Typed Cloudflare environment configuration with safe production defaults.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::{signing_key_pair_matches, validate_public_signing_key};
use crate::domain::CanonicalEmail;
use crate::error::ApiError;
use worker::Env;

#[derive(Debug, Clone)]
pub struct Config {
    pub environment: String,
    pub customer_app_url: String,
    pub owner_app_url: String,
    pub owner_emails: BTreeSet<CanonicalEmail>,
    pub license_issuer: String,
    pub license_audience: String,
    pub signing_key_id: String,
    pub signing_private_key: Option<String>,
    pub signing_public_keys: BTreeMap<String, String>,
    pub lease_active_days: i64,
    pub lease_grace_days: i64,
    pub magic_link_minutes: i64,
    pub session_days: i64,
    pub session_pepper: Option<String>,
    pub rerout_api_key: Option<String>,
    pub stripe_secret_key: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    pub auth_from_email: Option<CanonicalEmail>,
}

impl Config {
    pub fn from_env(env: &Env) -> Result<Self, ApiError> {
        let fallback_app_url = variable(env, "PUBLIC_APP_URL", "http://localhost:8787");
        let owner_emails = secret(env, "OWNER_EMAILS")
            .or_else(|| optional_variable(env, "OWNER_EMAILS"))
            .unwrap_or_default()
            .split(',')
            .filter_map(|value| CanonicalEmail::parse(value).ok())
            .collect();
        let signing_key_id = variable(env, "LICENSE_SIGNING_KEY_ID", "development-1");
        let signing_public_key = secret(env, "LICENSE_SIGNING_PUBLIC_KEY")
            .or_else(|| optional_variable(env, "LICENSE_SIGNING_PUBLIC_KEY"));
        let previous_signing_public_keys = secret(env, "LICENSE_PREVIOUS_SIGNING_PUBLIC_KEYS_JSON")
            .or_else(|| optional_variable(env, "LICENSE_PREVIOUS_SIGNING_PUBLIC_KEYS_JSON"));
        let signing_private_key = secret(env, "LICENSE_SIGNING_PRIVATE_KEY");
        let signing_public_keys = signing_public_keys(
            &signing_key_id,
            signing_public_key.as_deref(),
            previous_signing_public_keys.as_deref(),
        )?;
        if let Some(private_key) = signing_private_key.as_deref() {
            let public_key = signing_public_keys
                .get(&signing_key_id)
                .ok_or(ApiError::Configuration)?;
            if !signing_key_pair_matches(private_key, public_key)? {
                return Err(ApiError::Configuration);
            }
        }
        Ok(Self {
            environment: variable(env, "ENVIRONMENT", "development"),
            customer_app_url: variable(env, "CUSTOMER_APP_URL", &fallback_app_url),
            owner_app_url: variable(env, "OWNER_APP_URL", &fallback_app_url),
            owner_emails,
            license_issuer: variable(env, "LICENSE_ISSUER", "campus-pilot-control-plane"),
            license_audience: variable(env, "LICENSE_AUDIENCE", "campus-pilot"),
            signing_key_id: signing_key_id.clone(),
            signing_private_key,
            signing_public_keys,
            lease_active_days: positive_i64(env, "LEASE_ACTIVE_DAYS", 30),
            lease_grace_days: positive_i64(env, "LEASE_GRACE_DAYS", 7),
            magic_link_minutes: positive_i64(env, "MAGIC_LINK_MINUTES", 15),
            session_days: positive_i64(env, "SESSION_DAYS", 7),
            session_pepper: secret(env, "SESSION_PEPPER"),
            rerout_api_key: secret(env, "REROUT_API_KEY"),
            stripe_secret_key: secret(env, "STRIPE_SECRET_KEY"),
            stripe_webhook_secret: secret(env, "STRIPE_WEBHOOK_SECRET"),
            auth_from_email: optional_variable(env, "AUTH_FROM_EMAIL")
                .map(|value| CanonicalEmail::parse(&value).map_err(|_| ApiError::Configuration))
                .transpose()?,
        })
    }

    #[must_use]
    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }
}

fn variable(env: &Env, name: &str, fallback: &str) -> String {
    optional_variable(env, name).unwrap_or_else(|| fallback.to_owned())
}

fn optional_variable(env: &Env, name: &str) -> Option<String> {
    env.var(name)
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.trim().is_empty())
}

fn secret(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.trim().is_empty())
}

fn positive_i64(env: &Env, name: &str, fallback: i64) -> i64 {
    optional_variable(env, name)
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(fallback)
}

fn signing_public_keys(
    active_key_id: &str,
    active_public_key: Option<&str>,
    previous_keys_json: Option<&str>,
) -> Result<BTreeMap<String, String>, ApiError> {
    let mut keys = previous_keys_json.map_or_else(
        || Ok(BTreeMap::new()),
        |value| {
            serde_json::from_str::<BTreeMap<String, String>>(value)
                .map_err(|_| ApiError::Configuration)
        },
    )?;
    for (key_id, public_key) in &keys {
        validate_signing_key_entry(key_id, public_key)?;
    }
    if let Some(public_key) = active_public_key {
        validate_signing_key_entry(active_key_id, public_key)?;
        match keys.get(active_key_id) {
            Some(configured) if configured != public_key => return Err(ApiError::Configuration),
            Some(_) => {}
            None => {
                keys.insert(active_key_id.to_owned(), public_key.to_owned());
            }
        }
    }
    Ok(keys)
}

fn validate_signing_key_entry(key_id: &str, public_key: &str) -> Result<(), ApiError> {
    if key_id.is_empty()
        || key_id.len() > 128
        || !key_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        || public_key.trim().is_empty()
    {
        return Err(ApiError::Configuration);
    }
    validate_public_signing_key(public_key)
}

#[cfg(test)]
mod tests {
    use super::signing_public_keys;

    const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAxbbyLLpJQoSoH8ia0Xw/lZTAUKtokEiy8l27VZND2zI=\n-----END PUBLIC KEY-----\n";
    const ROTATED_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEArVSef1/+8dsF8OsxRrBs6q6+hRI7leppr00NTz3n2NA=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn signing_keyring_exposes_active_and_previous_keys_without_conflicts() {
        let keys = signing_public_keys(
            "production-2",
            Some(ROTATED_PUBLIC_KEY),
            Some(&format!(
                r#"{{"production-1":{}}}"#,
                serde_json::to_string(PUBLIC_KEY).unwrap_or_else(|_| unreachable!())
            )),
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            keys.get("production-1").map(String::as_str),
            Some(PUBLIC_KEY)
        );
        assert_eq!(
            keys.get("production-2").map(String::as_str),
            Some(ROTATED_PUBLIC_KEY)
        );

        assert!(
            signing_public_keys(
                "production-2",
                Some(ROTATED_PUBLIC_KEY),
                Some(&format!(
                    r#"{{"production-2":{}}}"#,
                    serde_json::to_string(PUBLIC_KEY).unwrap_or_else(|_| unreachable!())
                )),
            )
            .is_err()
        );
        assert!(signing_public_keys("production-2", Some(ROTATED_PUBLIC_KEY), Some("[]")).is_err());
        assert!(signing_public_keys("invalid key", Some(ROTATED_PUBLIC_KEY), None).is_err());
        assert!(signing_public_keys("production-2", Some("not-a-key"), None).is_err());
    }
}
