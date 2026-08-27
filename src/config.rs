//! Typed Cloudflare environment configuration with safe production defaults.

use std::collections::BTreeSet;

use crate::domain::CanonicalEmail;
use crate::error::ApiError;
use worker::Env;

#[derive(Debug, Clone)]
pub struct Config {
    pub environment: String,
    pub public_app_url: String,
    pub owner_emails: BTreeSet<CanonicalEmail>,
    pub license_issuer: String,
    pub license_audience: String,
    pub signing_key_id: String,
    pub signing_private_key: Option<String>,
    pub signing_public_key: Option<String>,
    pub lease_active_days: i64,
    pub lease_grace_days: i64,
    pub magic_link_minutes: i64,
    pub session_days: i64,
    pub session_pepper: Option<String>,
    pub stripe_secret_key: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    pub resend_api_key: Option<String>,
    pub auth_from_email: Option<String>,
}

impl Config {
    pub fn from_env(env: &Env) -> Result<Self, ApiError> {
        let owner_emails = secret(env, "OWNER_EMAILS")
            .or_else(|| optional_variable(env, "OWNER_EMAILS"))
            .unwrap_or_default()
            .split(',')
            .filter_map(|value| CanonicalEmail::parse(value).ok())
            .collect();
        Ok(Self {
            environment: variable(env, "ENVIRONMENT", "development"),
            public_app_url: variable(env, "PUBLIC_APP_URL", "http://localhost:8787"),
            owner_emails,
            license_issuer: variable(env, "LICENSE_ISSUER", "campus-pilot-control-plane"),
            license_audience: variable(env, "LICENSE_AUDIENCE", "campus-pilot"),
            signing_key_id: variable(env, "LICENSE_SIGNING_KEY_ID", "development-1"),
            signing_private_key: secret(env, "LICENSE_SIGNING_PRIVATE_KEY"),
            signing_public_key: secret(env, "LICENSE_SIGNING_PUBLIC_KEY")
                .or_else(|| optional_variable(env, "LICENSE_SIGNING_PUBLIC_KEY")),
            lease_active_days: positive_i64(env, "LEASE_ACTIVE_DAYS", 30),
            lease_grace_days: positive_i64(env, "LEASE_GRACE_DAYS", 7),
            magic_link_minutes: positive_i64(env, "MAGIC_LINK_MINUTES", 15),
            session_days: positive_i64(env, "SESSION_DAYS", 7),
            session_pepper: secret(env, "SESSION_PEPPER"),
            stripe_secret_key: secret(env, "STRIPE_SECRET_KEY"),
            stripe_webhook_secret: secret(env, "STRIPE_WEBHOOK_SECRET"),
            resend_api_key: secret(env, "RESEND_API_KEY"),
            auth_from_email: secret(env, "AUTH_FROM_EMAIL")
                .or_else(|| optional_variable(env, "AUTH_FROM_EMAIL")),
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
