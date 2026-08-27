//! Passwordless portal authentication, proof-bearing identities, and account authorization.

use serde::{Deserialize, Serialize};
use serde_json::json;
use time::Duration;
use uuid::Uuid;
use worker::{D1Database, EmailAddress, Request, Response, SendEmail, SendEmailBuilder};

use crate::clock::{format, now, now_iso};
use crate::config::Config;
use crate::crypto::{hash_secret, random_token};
use crate::domain::CanonicalEmail;
use crate::error::ApiError;
use crate::http::{ApiResult, cookie, delete_cookie, json, redirect, set_cookie};
use crate::short_links::create_short_link;
use crate::store::{all, batch_changes, bind_text, execute, first, prepared};

pub const SESSION_COOKIE: &str = "cp_control_session";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountRole {
    Admin,
    Billing,
    Viewer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountAccess {
    pub id: String,
    pub name: String,
    pub role: AccountRole,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalIdentity {
    pub email: CanonicalEmail,
    pub is_owner: bool,
    pub accounts: Vec<AccountAccess>,
}

#[derive(Debug)]
pub struct AuthenticatedPortalUser(PortalIdentity);

impl AuthenticatedPortalUser {
    pub fn identity(&self) -> &PortalIdentity {
        &self.0
    }

    pub fn require_account(
        &self,
        account_id: &str,
        allowed: &[AccountRole],
    ) -> ApiResult<&AccountAccess> {
        self.0
            .accounts
            .iter()
            .find(|account| account.id == account_id && allowed.contains(&account.role))
            .ok_or_else(|| {
                ApiError::client("account_access_required", "Account access is required", 403)
            })
    }
}

#[derive(Debug)]
pub struct OwnerOperator(PortalIdentity);

impl OwnerOperator {
    pub fn email(&self) -> &CanonicalEmail {
        &self.0.email
    }
}

#[derive(Debug, Deserialize)]
struct SessionRow {
    email: String,
}

#[derive(Debug, Serialize)]
struct SessionView<'a> {
    authenticated: bool,
    identity: Option<&'a PortalIdentity>,
}

pub async fn resolve_identity(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<Option<PortalIdentity>> {
    let Some(token) = cookie(request, SESSION_COOKIE) else {
        return Ok(None);
    };
    let Some(pepper) = config.session_pepper.as_deref() else {
        return Ok(None);
    };
    let token_hash = hash_secret(&token, Some(pepper));
    let current = now_iso()?;
    let Some(session) = first::<SessionRow>(
        db,
        "SELECT email FROM portal_sessions WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
        vec![bind_text(&token_hash), bind_text(&current)],
    )
    .await?
    else {
        return Ok(None);
    };
    let email = CanonicalEmail::parse(&session.email).map_err(|_| ApiError::Internal)?;
    let accounts = all::<AccountAccess>(
        db,
        "SELECT accounts.id, accounts.name, account_members.role \
         FROM account_members INNER JOIN accounts ON accounts.id = account_members.account_id \
         WHERE LOWER(account_members.email) = ? AND account_members.deleted_at IS NULL \
         AND accounts.deleted_at IS NULL AND accounts.status != 'closed' ORDER BY accounts.name",
        vec![bind_text(email.as_str())],
    )
    .await?;
    Ok(Some(PortalIdentity {
        is_owner: config.owner_emails.contains(&email),
        email,
        accounts,
    }))
}

pub async fn require_user(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<AuthenticatedPortalUser> {
    resolve_identity(db, request, config)
        .await?
        .map(AuthenticatedPortalUser)
        .ok_or_else(|| ApiError::client("sign_in_required", "Sign in is required", 401))
}

pub async fn require_owner(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<OwnerOperator> {
    let identity = resolve_identity(db, request, config)
        .await?
        .ok_or_else(|| ApiError::client("sign_in_required", "Sign in is required", 401))?;
    if identity.is_owner {
        Ok(OwnerOperator(identity))
    } else {
        Err(ApiError::client(
            "owner_access_required",
            "Owner access is required",
            403,
        ))
    }
}

pub async fn session(db: &D1Database, request: &Request, config: &Config) -> ApiResult<Response> {
    let identity = resolve_identity(db, request, config).await?;
    json(&SessionView {
        authenticated: identity.is_some(),
        identity: identity.as_ref(),
    })
}

pub async fn request_magic_link(
    db: &D1Database,
    raw_email: &str,
    request_ip: &str,
    config: &Config,
    email_sender: Option<&SendEmail>,
) -> ApiResult<Response> {
    let email = CanonicalEmail::parse(raw_email)?;
    let member = first::<serde_json::Value>(
        db,
        "SELECT 1 AS allowed FROM account_members \
         INNER JOIN accounts ON accounts.id = account_members.account_id \
         WHERE LOWER(account_members.email) = ? AND account_members.deleted_at IS NULL \
         AND accounts.deleted_at IS NULL AND accounts.status != 'closed' LIMIT 1",
        vec![bind_text(email.as_str())],
    )
    .await?
    .is_some();
    let allowed = member || config.owner_emails.contains(&email);
    let mut debug_url = None;
    if allowed && let Some(pepper) = config.session_pepper.as_deref() {
        if config.is_production()
            && (email_sender.is_none()
                || config.auth_from_email.is_none()
                || config.rerout_api_key.is_none())
        {
            return Err(ApiError::Configuration);
        }
        let token = random_token("cpml_")?;
        let token_hash = hash_secret(&token, Some(pepper));
        let ip_hash = hash_secret(request_ip, Some(pepper));
        let created_at = now_iso()?;
        let expiry = now() + Duration::minutes(config.magic_link_minutes);
        let expires_at = format(expiry)?;
        let target_url = format!(
            "{}/api/auth/consume?token={}",
            config.public_app_url.trim_end_matches('/'),
            url::form_urlencoded::byte_serialize(token.as_bytes()).collect::<String>()
        );
        let delivery_url = match config.rerout_api_key.as_deref() {
            Some(api_key) => {
                create_short_link(&target_url, expiry.unix_timestamp(), api_key).await?
            }
            None if !config.is_production() => target_url,
            None => return Err(ApiError::Configuration),
        };
        execute(
                db,
                "INSERT INTO magic_links (id, email, token_hash, expires_at, requested_ip_hash, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                vec![
                    bind_text(&Uuid::new_v4().to_string()),
                    bind_text(email.as_str()),
                    bind_text(&token_hash),
                    bind_text(&expires_at),
                    bind_text(&ip_hash),
                    bind_text(&created_at),
                ],
            )
            .await?;
        if let (Some(sender), Some(from)) = (email_sender, config.auth_from_email.as_ref()) {
            send_magic_link(sender, from, &email, &delivery_url).await?;
        } else if !config.is_production() {
            debug_url = Some(delivery_url);
        }
    }
    json(&json!({ "ok": true, "debug_url": debug_url }))
}

pub async fn consume_magic_link(
    db: &D1Database,
    token: &str,
    config: &Config,
) -> ApiResult<Response> {
    let pepper = config
        .session_pepper
        .as_deref()
        .ok_or(ApiError::Configuration)?;
    let token_hash = hash_secret(token, Some(pepper));
    let consumed_at = now_iso()?;
    let session_token = random_token("cpsess_")?;
    let session_hash = hash_secret(&session_token, Some(pepper));
    let expires_at = format(now() + Duration::days(config.session_days))?;
    let max_age = config.session_days.saturating_mul(86_400);
    let mut response = redirect(config, "/")?;
    set_cookie(
        &mut response,
        SESSION_COOKIE,
        &session_token,
        max_age,
        config.is_production(),
    )?;
    let changes = batch_changes(
        db,
        vec![
            prepared(
                db,
                "UPDATE magic_links SET consumed_at = ? \
                 WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?",
                vec![
                    bind_text(&consumed_at),
                    bind_text(&token_hash),
                    bind_text(&consumed_at),
                ],
            )?,
            prepared(
                db,
                "INSERT INTO portal_sessions \
                 (id, email, token_hash, expires_at, last_seen_at, created_at) \
                 SELECT ?, email, ?, ?, ?, ? FROM magic_links \
                 WHERE token_hash = ? AND consumed_at = ? AND changes() = 1",
                vec![
                    bind_text(&Uuid::new_v4().to_string()),
                    bind_text(&session_hash),
                    bind_text(&expires_at),
                    bind_text(&consumed_at),
                    bind_text(&consumed_at),
                    bind_text(&token_hash),
                    bind_text(&consumed_at),
                ],
            )?,
        ],
    )
    .await?;
    if changes.as_slice() == [1, 1] {
        Ok(response)
    } else {
        redirect(config, "/?auth=invalid")
    }
}

pub async fn logout(db: &D1Database, request: &Request, config: &Config) -> ApiResult<Response> {
    if let (Some(token), Some(pepper)) = (
        cookie(request, SESSION_COOKIE),
        config.session_pepper.as_deref(),
    ) {
        let token_hash = hash_secret(&token, Some(pepper));
        execute(
            db,
            "UPDATE portal_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            vec![bind_text(&now_iso()?), bind_text(&token_hash)],
        )
        .await?;
    }
    let mut response = json(&json!({ "ok": true }))?;
    delete_cookie(&mut response, SESSION_COOKIE)?;
    Ok(response)
}

async fn send_magic_link(
    sender: &SendEmail,
    from: &CanonicalEmail,
    email: &CanonicalEmail,
    url: &str,
) -> ApiResult<()> {
    let content = magic_link_content(url);
    let from = EmailAddress::new("Campus Pilot", from.as_str());
    let message = SendEmailBuilder::builder_with_email_address_and_str(
        &from,
        email.as_str(),
        content.subject,
    )
    .text(&content.text)
    .html(&content.html)
    .build();
    sender
        .send_with_builder(&message)
        .await
        .map(|_| ())
        .map_err(|_| ApiError::Dependency)
}

struct MagicLinkContent {
    subject: &'static str,
    text: String,
    html: String,
}

fn magic_link_content(url: &str) -> MagicLinkContent {
    MagicLinkContent {
        subject: "Sign in to Campus Pilot licensing",
        text: format!("Sign in to Campus Pilot licensing: {url}"),
        html: format!(
            "<p>Use the link below to sign in to Campus Pilot licensing.</p><p><a href=\"{url}\">Sign in</a></p>"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountAccess, AccountRole, AuthenticatedPortalUser, PortalIdentity, magic_link_content,
    };
    use crate::domain::CanonicalEmail;

    fn test_user() -> AuthenticatedPortalUser {
        let email = match CanonicalEmail::parse("admin@example.com") {
            Ok(value) => value,
            Err(error) => panic!("test email invalid: {error}"),
        };
        AuthenticatedPortalUser(PortalIdentity {
            email,
            is_owner: false,
            accounts: vec![AccountAccess {
                id: "account-1".to_owned(),
                name: "School".to_owned(),
                role: AccountRole::Billing,
            }],
        })
    }

    #[test]
    fn account_permission_is_proven_before_use() {
        let user = test_user();
        assert!(
            user.require_account("account-1", &[AccountRole::Billing])
                .is_ok()
        );
        assert!(
            user.require_account("account-1", &[AccountRole::Admin])
                .is_err()
        );
        assert!(
            user.require_account("another", &[AccountRole::Billing])
                .is_err()
        );
    }

    #[test]
    fn magic_link_email_has_plain_text_and_html_fallbacks() {
        let content = magic_link_content("https://licensing.example.test/sign-in?token=safe");
        assert_eq!(content.subject, "Sign in to Campus Pilot licensing");
        assert!(
            content
                .text
                .contains("https://licensing.example.test/sign-in")
        );
        assert!(content.html.contains("<a href="));
    }
}
