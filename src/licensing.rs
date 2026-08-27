//! Installation activation and monotonic Ed25519 lease issuance for entitled accounts.

use serde::{Deserialize, Serialize};
use serde_json::json;
use time::Duration;
use uuid::Uuid;
use worker::D1Database;

use crate::audit::{AuditActor, AuditEvent, write};
use crate::clock::{format, now, now_iso};
use crate::config::Config;
use crate::crypto::{hash_secret, normalize_pem, random_token, sign_jws};
use crate::domain::{
    ActivationCode, DeploymentId, EntitlementSet, InstallationCredential, LeaseClaims, TenantId,
    required_text,
};
use crate::error::ApiError;
use crate::store::{batch, bind_i64, bind_text, execute, first, prepared};

#[derive(Debug, Clone, Deserialize)]
pub struct InstallationRow {
    pub id: String,
    pub account_id: String,
    pub tenant_id: String,
    pub deployment_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
struct ActivationCodeRow {
    id: String,
    account_id: String,
}

#[derive(Debug, Deserialize)]
struct EntitlementRow {
    current_period_end: Option<String>,
    grace_until: Option<String>,
    plan_key: String,
    modules_json: String,
    features_json: String,
    limits_json: String,
}

#[derive(Debug, Deserialize)]
struct SequenceRow {
    last_lease_sequence: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuedLease {
    pub token: String,
    pub claims: LeaseClaims,
}

#[derive(Debug, Serialize)]
pub struct ActivationResult {
    pub installation_id: String,
    pub installation_token: String,
    pub lease: String,
    pub claims: LeaseClaims,
}

pub struct ActivationRequest {
    pub code: ActivationCode,
    pub tenant_id: TenantId,
    pub deployment_id: DeploymentId,
    pub name: String,
}

impl ActivationRequest {
    pub fn parse(
        code: &str,
        tenant_id: &str,
        deployment_id: &str,
        name: &str,
    ) -> Result<Self, ApiError> {
        Ok(Self {
            code: ActivationCode::parse(code)?,
            tenant_id: TenantId::parse(tenant_id)?,
            deployment_id: DeploymentId::parse(deployment_id)?,
            name: required_text("name", name, 2, 120)?,
        })
    }
}

pub async fn activate(
    db: &D1Database,
    input: ActivationRequest,
    config: &Config,
    request_id: &str,
) -> Result<ActivationResult, ApiError> {
    require_signing(config)?;
    let pepper = config
        .session_pepper
        .as_deref()
        .ok_or(ApiError::Configuration)?;
    let code_hash = hash_secret(input.code.expose(), Some(pepper));
    let current = now_iso()?;
    let Some(code) = first::<ActivationCodeRow>(
        db,
        "UPDATE activation_codes SET used_at = ? WHERE token_hash = ? AND used_at IS NULL \
         AND revoked_at IS NULL AND expires_at > ? RETURNING id, account_id",
        vec![
            bind_text(&current),
            bind_text(&code_hash),
            bind_text(&current),
        ],
    )
    .await?
    else {
        return Err(ApiError::client(
            "activation_invalid",
            "The activation code is invalid or expired",
            400,
        ));
    };
    let _activation_id = code.id;
    let installation_id = Uuid::new_v4().to_string();
    let installation_token = random_token("cpinst_")?;
    let credential_hash = hash_secret(&installation_token, Some(pepper));
    let tenant_id = input.tenant_id.as_string();
    execute(
        db,
        "INSERT INTO installations (id, account_id, tenant_id, deployment_id, name, status, \
         credential_hash, credential_hint, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)",
        vec![
            bind_text(&installation_id),
            bind_text(&code.account_id),
            bind_text(&tenant_id),
            bind_text(input.deployment_id.as_str()),
            bind_text(&input.name),
            bind_text(&credential_hash),
            bind_text(&installation_token[installation_token.len().saturating_sub(8)..]),
            bind_text(&current),
            bind_text(&current),
        ],
    )
    .await?;
    let installation = InstallationRow {
        id: installation_id.clone(),
        account_id: code.account_id.clone(),
        tenant_id,
        deployment_id: input.deployment_id.as_str().to_owned(),
        status: "active".to_owned(),
    };
    let lease = issue(db, &installation, config, request_id).await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Installation,
            actor_id: Some(&installation_id),
            account_id: Some(&code.account_id),
            action: "installation.activated",
            target_type: "installation",
            target_id: Some(&installation_id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({
                "tenant_id": installation.tenant_id,
                "deployment_id": installation.deployment_id,
            }),
        },
    )
    .await?;
    Ok(ActivationResult {
        installation_id,
        installation_token,
        lease: lease.token,
        claims: lease.claims,
    })
}

pub async fn installation_from_credential(
    db: &D1Database,
    credential: &InstallationCredential,
    config: &Config,
) -> Result<InstallationRow, ApiError> {
    let pepper = config
        .session_pepper
        .as_deref()
        .ok_or(ApiError::Configuration)?;
    let credential_hash = hash_secret(credential.expose(), Some(pepper));
    let installation = first::<InstallationRow>(
        db,
        "SELECT id, account_id, tenant_id, deployment_id, status \
         FROM installations WHERE credential_hash = ?",
        vec![bind_text(&credential_hash)],
    )
    .await?
    .ok_or_else(|| {
        ApiError::client(
            "installation_unauthorized",
            "Installation authentication failed",
            401,
        )
    })?;
    if installation.status == "active" {
        Ok(installation)
    } else {
        Err(ApiError::client(
            "installation_inactive",
            "This installation is not active",
            403,
        ))
    }
}

pub async fn installation_by_id(
    db: &D1Database,
    installation_id: &str,
) -> Result<Option<InstallationRow>, ApiError> {
    first(
        db,
        "SELECT id, account_id, tenant_id, deployment_id, status \
         FROM installations WHERE id = ?",
        vec![bind_text(installation_id)],
    )
    .await
}

pub async fn issue(
    db: &D1Database,
    installation: &InstallationRow,
    config: &Config,
    request_id: &str,
) -> Result<IssuedLease, ApiError> {
    require_signing(config)?;
    if installation.status != "active" {
        return Err(ApiError::client(
            "installation_inactive",
            "This installation is not active",
            403,
        ));
    }
    let current = now_iso()?;
    let entitlement = current_entitlement(db, &installation.account_id, &current)
        .await?
        .ok_or_else(|| {
            ApiError::client(
                "subscription_required",
                "An active subscription is required before a license can be issued",
                402,
            )
        })?;
    let sequence = first::<SequenceRow>(
        db,
        "UPDATE installations SET last_lease_sequence = last_lease_sequence + 1, \
         last_seen_at = ?, updated_at = ? WHERE id = ? AND status = 'active' \
         RETURNING last_lease_sequence",
        vec![
            bind_text(&current),
            bind_text(&current),
            bind_text(&installation.id),
        ],
    )
    .await?
    .ok_or_else(|| {
        ApiError::client(
            "installation_inactive",
            "This installation is not active",
            403,
        )
    })?
    .last_lease_sequence;
    let lease_id = Uuid::new_v4().to_string();
    let issued_at = now();
    let configured_end = issued_at + Duration::days(config.lease_active_days);
    let lease_end = entitlement
        .period_end
        .map_or(configured_end, |period_end| period_end.min(configured_end));
    if lease_end <= issued_at {
        return Err(ApiError::client(
            "subscription_expired",
            "The subscription period has ended",
            402,
        ));
    }
    let configured_grace = lease_end + Duration::days(config.lease_grace_days);
    let grace_end = entitlement
        .grace_until
        .map_or(configured_grace, |grace| grace.min(configured_grace));
    let refresh_after = issued_at + Duration::seconds((lease_end - issued_at).whole_seconds() / 2);
    let claims = LeaseClaims {
        contract_version: "cp-license/v1".to_owned(),
        iss: config.license_issuer.clone(),
        aud: config.license_audience.clone(),
        sub: installation.tenant_id.clone(),
        installation_id: installation.id.clone(),
        jti: lease_id.clone(),
        sequence,
        catalog_version: format!("plans/{}/1", entitlement.plan_key),
        iat: issued_at.unix_timestamp(),
        nbf: (issued_at - Duration::seconds(30)).unix_timestamp(),
        refresh_after: refresh_after.unix_timestamp(),
        lease_expires_at: lease_end.unix_timestamp(),
        grace_until: grace_end.unix_timestamp(),
        exp: grace_end.unix_timestamp(),
        modules: entitlement.modules.into_iter().collect(),
        features: entitlement.features.into_iter().collect(),
        limits: entitlement.limits,
        min_app_version: None,
        max_app_version: None,
    };
    let private_key = config
        .signing_private_key
        .as_deref()
        .ok_or(ApiError::Configuration)?;
    let token = sign_jws(&claims, &config.signing_key_id, private_key)?;
    let fingerprint = hash_secret(&token, None);
    let claims_json = serde_json::to_string(&claims).map_err(|_| ApiError::Internal)?;
    let issued_at_iso = format(issued_at)?;
    let refresh_after_iso = format(refresh_after)?;
    let lease_end_iso = format(lease_end)?;
    let grace_end_iso = format(grace_end)?;
    batch(
        db,
        vec![
            prepared(
                db,
                "UPDATE leases SET status = 'superseded' WHERE installation_id = ? AND status = 'active'",
                vec![bind_text(&installation.id)],
            )?,
            prepared(
                db,
                "INSERT INTO leases (id, installation_id, sequence, status, token_fingerprint, \
                 catalog_version, claims_json, issued_at, refresh_after, lease_expires_at, grace_until, \
                 token_expires_at, created_at) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    bind_text(&lease_id),
                    bind_text(&installation.id),
                    bind_i64(sequence)?,
                    bind_text(&fingerprint),
                    bind_text(&claims.catalog_version),
                    bind_text(&claims_json),
                    bind_text(&issued_at_iso),
                    bind_text(&refresh_after_iso),
                    bind_text(&lease_end_iso),
                    bind_text(&grace_end_iso),
                    bind_text(&grace_end_iso),
                    bind_text(&current),
                ],
            )?,
            prepared(
                db,
                "UPDATE installations SET current_lease_id = ?, updated_at = ? WHERE id = ?",
                vec![
                    bind_text(&lease_id),
                    bind_text(&current),
                    bind_text(&installation.id),
                ],
            )?,
        ],
    )
    .await?;
    write(
        db,
        &AuditEvent {
            actor: AuditActor::Installation,
            actor_id: Some(&installation.id),
            account_id: Some(&installation.account_id),
            action: "lease.issued",
            target_type: "lease",
            target_id: Some(&lease_id),
            request_id: Some(request_id),
            reason: None,
            metadata: &json!({
                "sequence": sequence,
                "catalog_version": claims.catalog_version,
                "module_count": claims.modules.len(),
                "feature_count": claims.features.len(),
            }),
        },
    )
    .await?;
    Ok(IssuedLease { token, claims })
}

pub fn public_keys(config: &Config) -> serde_json::Value {
    let keys = config
        .signing_public_keys
        .iter()
        .map(|(key_id, pem)| {
            json!({
                "kid": key_id,
                "alg": "EdDSA",
                "use": "sig",
                "pem": normalize_pem(pem),
                "current": key_id == &config.signing_key_id,
            })
        })
        .collect::<Vec<_>>();
    json!({ "keys": keys })
}

async fn current_entitlement(
    db: &D1Database,
    account_id: &str,
    current: &str,
) -> Result<Option<EntitlementSet>, ApiError> {
    let row = first::<EntitlementRow>(
        db,
        "SELECT subscriptions.current_period_end, subscriptions.grace_until, plans.key AS plan_key, \
         plans.modules_json, plans.features_json, plans.limits_json FROM subscriptions \
         INNER JOIN accounts ON accounts.id = subscriptions.account_id \
         INNER JOIN plans ON plans.id = subscriptions.plan_id WHERE subscriptions.account_id = ? \
         AND accounts.status = 'active' AND (subscriptions.status IN ('active', 'trialing') \
         OR (subscriptions.status = 'past_due' AND subscriptions.grace_until > ?)) \
         ORDER BY CASE subscriptions.status WHEN 'active' THEN 1 WHEN 'trialing' THEN 2 ELSE 3 END, \
         subscriptions.updated_at DESC LIMIT 1",
        vec![bind_text(account_id), bind_text(current)],
    )
    .await?;
    row.map(|row| {
        EntitlementSet::from_storage(
            row.plan_key,
            &row.modules_json,
            &row.features_json,
            &row.limits_json,
            row.current_period_end.as_deref(),
            row.grace_until.as_deref(),
        )
    })
    .transpose()
}

fn require_signing(config: &Config) -> Result<(), ApiError> {
    if config.signing_private_key.is_some()
        && config
            .signing_public_keys
            .contains_key(&config.signing_key_id)
    {
        Ok(())
    } else {
        Err(ApiError::client(
            "signing_unavailable",
            "License signing is not configured",
            503,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::config::Config;

    use super::{ActivationRequest, public_keys, require_signing};

    const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAxbbyLLpJQoSoH8ia0Xw/lZTAUKtokEiy8l27VZND2zI=\n-----END PUBLIC KEY-----\n";
    const ROTATED_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEArVSef1/+8dsF8OsxRrBs6q6+hRI7leppr00NTz3n2NA=\n-----END PUBLIC KEY-----\n";

    fn config() -> Config {
        Config {
            environment: "test".to_owned(),
            customer_app_url: "https://customer.example.test".to_owned(),
            owner_app_url: "https://owner.example.test".to_owned(),
            owner_emails: Default::default(),
            license_issuer: "campus-pilot-control-plane".to_owned(),
            license_audience: "campus-pilot".to_owned(),
            signing_key_id: "production-2".to_owned(),
            signing_private_key: Some("configured-in-secret-store".to_owned()),
            signing_public_keys: BTreeMap::from([
                ("production-1".to_owned(), PUBLIC_KEY.to_owned()),
                ("production-2".to_owned(), ROTATED_PUBLIC_KEY.to_owned()),
            ]),
            lease_active_days: 30,
            lease_grace_days: 7,
            magic_link_minutes: 15,
            session_days: 7,
            session_pepper: None,
            rerout_api_key: None,
            stripe_secret_key: None,
            stripe_webhook_secret: None,
            auth_from_email: None,
        }
    }

    #[test]
    fn activation_request_parses_all_boundary_values() {
        let parsed = ActivationRequest::parse(
            "cpact_12345678901234567890",
            "120413ff-2c32-4af5-b526-b1522077cc1f",
            "campus-prod-01",
            "Main campus",
        );
        assert!(parsed.is_ok());
    }

    #[test]
    fn public_keyring_identifies_one_current_key_and_signing_requires_it() {
        let mut config = config();
        let document = public_keys(&config);
        let keys = document["keys"]
            .as_array()
            .unwrap_or_else(|| unreachable!());
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0]["kid"], "production-1");
        assert_eq!(keys[0]["current"], false);
        assert_eq!(keys[1]["kid"], "production-2");
        assert_eq!(keys[1]["current"], true);
        assert_eq!(keys[1]["alg"], "EdDSA");
        assert!(require_signing(&config).is_ok());

        config.signing_public_keys.remove("production-2");
        assert!(require_signing(&config).is_err());
        config
            .signing_public_keys
            .insert("production-2".to_owned(), ROTATED_PUBLIC_KEY.to_owned());
        config.signing_private_key = None;
        assert!(require_signing(&config).is_err());
    }
}
