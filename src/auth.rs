//! Separate customer and owner passwordless authentication boundaries.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::Duration;
use uuid::Uuid;
use worker::{D1Database, EmailAddress, Request, Response, SendEmail, SendEmailBuilder};

use crate::clock::{format, now, now_iso};
use crate::config::Config;
use crate::crypto::{hash_secret, random_token};
use crate::domain::{CanonicalEmail, CurrencyCode, required_text};
use crate::error::ApiError;
use crate::http::{ApiResult, cookie, delete_cookie, json, redirect, set_cookie};
use crate::operations::slugify;
use crate::short_links::create_short_link;
use crate::store::{all, batch_changes, bind_text, execute, first, prepared};

pub const CUSTOMER_SESSION_COOKIE: &str = "cp_customer_session";
pub const OWNER_SESSION_COOKIE: &str = "cp_owner_session";

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
pub struct CustomerIdentity {
    pub email: CanonicalEmail,
    pub accounts: Vec<AccountAccess>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerIdentity {
    pub email: CanonicalEmail,
}

#[derive(Debug)]
pub struct AuthenticatedPortalUser(CustomerIdentity);

impl AuthenticatedPortalUser {
    pub fn identity(&self) -> &CustomerIdentity {
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
pub struct OwnerOperator(OwnerIdentity);

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
struct CustomerSessionView<'a> {
    authenticated: bool,
    identity: Option<&'a CustomerIdentity>,
}

#[derive(Debug, Serialize)]
struct OwnerSessionView<'a> {
    authenticated: bool,
    identity: Option<&'a OwnerIdentity>,
}

#[derive(Debug)]
pub struct SignupInput {
    full_name: String,
    email: CanonicalEmail,
    school_name: String,
    country: String,
    preferred_currency: CurrencyCode,
}

impl SignupInput {
    pub fn parse(
        full_name: &str,
        email: &str,
        school_name: &str,
        country: &str,
        preferred_currency: &str,
    ) -> ApiResult<Self> {
        let country = country.trim().to_uppercase();
        if country.len() != 2
            || !country
                .chars()
                .all(|character| character.is_ascii_uppercase())
        {
            return Err(ApiError::client(
                "country_invalid",
                "Use a two-letter country code",
                400,
            ));
        }
        Ok(Self {
            full_name: required_text("full_name", full_name, 2, 120)?,
            email: CanonicalEmail::parse(email)?,
            school_name: required_text("school_name", school_name, 2, 160)?,
            country,
            preferred_currency: CurrencyCode::parse(preferred_currency)?,
        })
    }
}

#[derive(Debug, Deserialize)]
struct PendingSignupRow {
    school_name: String,
    country: String,
    preferred_currency: String,
}

#[derive(Clone, Copy)]
enum Audience {
    Customer,
    Owner,
}

impl Audience {
    const fn link_table(self) -> &'static str {
        match self {
            Self::Customer => "magic_links",
            Self::Owner => "owner_magic_links",
        }
    }

    const fn session_table(self) -> &'static str {
        match self {
            Self::Customer => "portal_sessions",
            Self::Owner => "owner_sessions",
        }
    }

    const fn cookie(self) -> &'static str {
        match self {
            Self::Customer => CUSTOMER_SESSION_COOKIE,
            Self::Owner => OWNER_SESSION_COOKIE,
        }
    }

    const fn token_prefix(self) -> &'static str {
        match self {
            Self::Customer => "cpcust_",
            Self::Owner => "cpown_",
        }
    }

    const fn consume_path(self) -> &'static str {
        match self {
            Self::Customer => "/api/customer/auth/consume",
            Self::Owner => "/api/owner/auth/consume",
        }
    }

    const fn success_path(self) -> &'static str {
        match self {
            Self::Customer => "/portal",
            Self::Owner => "/owner",
        }
    }

    const fn invalid_path(self) -> &'static str {
        match self {
            Self::Customer => "/login?auth=invalid",
            Self::Owner => "/owner/login?auth=invalid",
        }
    }

    fn app_url(self, config: &Config) -> &str {
        match self {
            Self::Customer => &config.customer_app_url,
            Self::Owner => &config.owner_app_url,
        }
    }
}

pub async fn resolve_customer_identity(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<Option<CustomerIdentity>> {
    let Some(email) = resolve_session_email(db, request, config, Audience::Customer).await? else {
        return Ok(None);
    };
    let accounts = all::<AccountAccess>(
        db,
        "SELECT accounts.id, accounts.name, account_members.role \
         FROM account_members INNER JOIN accounts ON accounts.id = account_members.account_id \
         WHERE LOWER(account_members.email) = ? AND account_members.deleted_at IS NULL \
         AND accounts.deleted_at IS NULL AND accounts.status != 'closed' ORDER BY accounts.name",
        vec![bind_text(email.as_str())],
    )
    .await?;
    Ok(Some(CustomerIdentity { email, accounts }))
}

pub async fn resolve_owner_identity(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<Option<OwnerIdentity>> {
    let Some(email) = resolve_session_email(db, request, config, Audience::Owner).await? else {
        return Ok(None);
    };
    Ok(config
        .owner_emails
        .contains(&email)
        .then_some(OwnerIdentity { email }))
}

async fn resolve_session_email(
    db: &D1Database,
    request: &Request,
    config: &Config,
    audience: Audience,
) -> ApiResult<Option<CanonicalEmail>> {
    let Some(token) = cookie(request, audience.cookie()) else {
        return Ok(None);
    };
    let Some(pepper) = config.session_pepper.as_deref() else {
        return Ok(None);
    };
    let token_hash = hash_secret(&token, Some(pepper));
    let query = format!(
        "SELECT email FROM {} WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
        audience.session_table()
    );
    let Some(session) = first::<SessionRow>(
        db,
        &query,
        vec![bind_text(&token_hash), bind_text(&now_iso()?)],
    )
    .await?
    else {
        return Ok(None);
    };
    CanonicalEmail::parse(&session.email).map(Some)
}

pub async fn require_user(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<AuthenticatedPortalUser> {
    resolve_customer_identity(db, request, config)
        .await?
        .map(AuthenticatedPortalUser)
        .ok_or_else(|| ApiError::client("sign_in_required", "Sign in is required", 401))
}

pub async fn require_owner(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<OwnerOperator> {
    resolve_owner_identity(db, request, config)
        .await?
        .map(OwnerOperator)
        .ok_or_else(|| ApiError::client("owner_access_required", "Owner access is required", 403))
}

pub async fn customer_session(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<Response> {
    let identity = resolve_customer_identity(db, request, config).await?;
    json(&CustomerSessionView {
        authenticated: identity.is_some(),
        identity: identity.as_ref(),
    })
}

pub async fn owner_session(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<Response> {
    let identity = resolve_owner_identity(db, request, config).await?;
    json(&OwnerSessionView {
        authenticated: identity.is_some(),
        identity: identity.as_ref(),
    })
}

pub async fn request_customer_magic_link(
    db: &D1Database,
    raw_email: &str,
    request_ip: &str,
    config: &Config,
    email_sender: Option<&SendEmail>,
) -> ApiResult<Response> {
    let email = CanonicalEmail::parse(raw_email)?;
    let allowed = first::<Value>(
        db,
        "SELECT 1 AS allowed FROM account_members \
         INNER JOIN accounts ON accounts.id = account_members.account_id \
         WHERE LOWER(account_members.email) = ? AND account_members.deleted_at IS NULL \
         AND accounts.deleted_at IS NULL AND accounts.status != 'closed' LIMIT 1",
        vec![bind_text(email.as_str())],
    )
    .await?
    .is_some();
    request_sign_in_link(
        db,
        email,
        allowed,
        request_ip,
        config,
        email_sender,
        Audience::Customer,
    )
    .await
}

pub async fn request_owner_magic_link(
    db: &D1Database,
    raw_email: &str,
    request_ip: &str,
    config: &Config,
    email_sender: Option<&SendEmail>,
) -> ApiResult<Response> {
    let email = CanonicalEmail::parse(raw_email)?;
    let allowed = config.owner_emails.contains(&email);
    request_sign_in_link(
        db,
        email,
        allowed,
        request_ip,
        config,
        email_sender,
        Audience::Owner,
    )
    .await
}

async fn request_sign_in_link(
    db: &D1Database,
    email: CanonicalEmail,
    allowed: bool,
    request_ip: &str,
    config: &Config,
    email_sender: Option<&SendEmail>,
    audience: Audience,
) -> ApiResult<Response> {
    let mut debug_url = None;
    if allowed {
        ensure_email_ready(config, email_sender)?;
        let pepper = config
            .session_pepper
            .as_deref()
            .ok_or(ApiError::Configuration)?;
        let token = random_token("cpml_")?;
        let token_hash = hash_secret(&token, Some(pepper));
        let ip_hash = hash_secret(request_ip, Some(pepper));
        let created_at = now_iso()?;
        let expiry = now() + Duration::minutes(config.magic_link_minutes);
        let expires_at = format(expiry)?;
        let target_url =
            auth_target_url(audience.app_url(config), audience.consume_path(), &token)?;
        let delivery_url = delivery_url(&target_url, expiry.unix_timestamp(), config).await?;
        let query = format!(
            "INSERT INTO {} (id, email, token_hash, expires_at, requested_ip_hash, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
            audience.link_table()
        );
        execute(
            db,
            &query,
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
        if config.is_production() {
            let (Some(sender), Some(from)) = (email_sender, config.auth_from_email.as_ref()) else {
                return Err(ApiError::Configuration);
            };
            let kind = match audience {
                Audience::Customer => EmailKind::CustomerSignIn,
                Audience::Owner => EmailKind::OwnerSignIn,
            };
            send_auth_email(sender, from, &email, &delivery_url, kind).await?;
        } else {
            debug_url = Some(delivery_url);
        }
    }
    json(&json!({ "ok": true, "debug_url": debug_url }))
}

pub async fn request_signup(
    db: &D1Database,
    input: SignupInput,
    request_ip: &str,
    config: &Config,
    email_sender: Option<&SendEmail>,
) -> ApiResult<Response> {
    let existing_member = first::<Value>(
        db,
        "SELECT 1 AS exists_already FROM account_members WHERE LOWER(email) = ? \
         AND deleted_at IS NULL LIMIT 1",
        vec![bind_text(input.email.as_str())],
    )
    .await?
    .is_some();
    if existing_member {
        return request_sign_in_link(
            db,
            input.email,
            true,
            request_ip,
            config,
            email_sender,
            Audience::Customer,
        )
        .await;
    }
    let mut debug_url = None;
    ensure_email_ready(config, email_sender)?;
    let pepper = config
        .session_pepper
        .as_deref()
        .ok_or(ApiError::Configuration)?;
    let token = random_token("cpreg_")?;
    let token_hash = hash_secret(&token, Some(pepper));
    let ip_hash = hash_secret(request_ip, Some(pepper));
    let timestamp = now_iso()?;
    let expiry = now() + Duration::minutes(config.magic_link_minutes);
    let expires_at = format(expiry)?;
    let target_url = auth_target_url(
        &config.customer_app_url,
        "/api/customer/auth/consume-signup",
        &token,
    )?;
    let delivery_url = delivery_url(&target_url, expiry.unix_timestamp(), config).await?;
    execute(
        db,
        "INSERT INTO pending_signups \
             (id, email, full_name, school_name, country, preferred_currency, token_hash, expires_at, \
              requested_ip_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(email) DO UPDATE SET full_name = excluded.full_name, school_name = excluded.school_name, \
              country = excluded.country, preferred_currency = excluded.preferred_currency, \
              token_hash = excluded.token_hash, expires_at = excluded.expires_at, consumed_at = NULL, \
              requested_ip_hash = excluded.requested_ip_hash, updated_at = excluded.updated_at",
            vec![
                bind_text(&Uuid::new_v4().to_string()),
                bind_text(input.email.as_str()),
                bind_text(&input.full_name),
                bind_text(&input.school_name),
                bind_text(&input.country),
                bind_text(input.preferred_currency.as_str()),
                bind_text(&token_hash),
                bind_text(&expires_at),
                bind_text(&ip_hash),
                bind_text(&timestamp),
                bind_text(&timestamp),
        ],
    )
    .await?;
    if config.is_production() {
        let (Some(sender), Some(from)) = (email_sender, config.auth_from_email.as_ref()) else {
            return Err(ApiError::Configuration);
        };
        send_auth_email(
            sender,
            from,
            &input.email,
            &delivery_url,
            EmailKind::CustomerSignup,
        )
        .await?;
    } else {
        debug_url = Some(delivery_url);
    }
    json(&json!({ "ok": true, "debug_url": debug_url }))
}

pub async fn consume_customer_magic_link(
    db: &D1Database,
    token: &str,
    config: &Config,
) -> ApiResult<Response> {
    consume_sign_in_link(db, token, config, Audience::Customer).await
}

pub async fn consume_owner_magic_link(
    db: &D1Database,
    token: &str,
    config: &Config,
) -> ApiResult<Response> {
    consume_sign_in_link(db, token, config, Audience::Owner).await
}

async fn consume_sign_in_link(
    db: &D1Database,
    token: &str,
    config: &Config,
    audience: Audience,
) -> ApiResult<Response> {
    let pepper = config
        .session_pepper
        .as_deref()
        .ok_or(ApiError::Configuration)?;
    let token_hash = hash_secret(token, Some(pepper));
    let consumed_at = now_iso()?;
    let session_token = random_token(audience.token_prefix())?;
    let session_hash = hash_secret(&session_token, Some(pepper));
    let expires_at = format(now() + Duration::days(config.session_days))?;
    let max_age = config.session_days.saturating_mul(86_400);
    let mut response = redirect(audience.app_url(config), audience.success_path())?;
    set_cookie(
        &mut response,
        audience.cookie(),
        &session_token,
        max_age,
        config.is_production(),
    )?;
    let update = format!(
        "UPDATE {} SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?",
        audience.link_table()
    );
    let insert = format!(
        "INSERT INTO {} (id, email, token_hash, expires_at, last_seen_at, created_at) \
         SELECT ?, email, ?, ?, ?, ? FROM {} WHERE token_hash = ? AND consumed_at = ?",
        audience.session_table(),
        audience.link_table()
    );
    let changes = batch_changes(
        db,
        vec![
            prepared(
                db,
                &update,
                vec![
                    bind_text(&consumed_at),
                    bind_text(&token_hash),
                    bind_text(&consumed_at),
                ],
            )?,
            prepared(
                db,
                &insert,
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
        redirect(audience.app_url(config), audience.invalid_path())
    }
}

pub async fn consume_signup(db: &D1Database, token: &str, config: &Config) -> ApiResult<Response> {
    let pepper = config
        .session_pepper
        .as_deref()
        .ok_or(ApiError::Configuration)?;
    let token_hash = hash_secret(token, Some(pepper));
    let consumed_at = now_iso()?;
    let Some(signup) = first::<PendingSignupRow>(
        db,
        "SELECT school_name, country, preferred_currency FROM pending_signups \
         WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?",
        vec![bind_text(&token_hash), bind_text(&consumed_at)],
    )
    .await?
    else {
        return redirect(&config.customer_app_url, "/login?signup=invalid");
    };
    let account_id = Uuid::new_v4().to_string();
    let account_slug = format!("{}-{}", slugify(&signup.school_name), &account_id[..8]);
    let session_token = random_token("cpcust_")?;
    let session_hash = hash_secret(&session_token, Some(pepper));
    let session_expires_at = format(now() + Duration::days(config.session_days))?;
    let max_age = config.session_days.saturating_mul(86_400);
    let metadata = json!({
        "country": signup.country,
        "preferred_currency": signup.preferred_currency,
        "source": "customer_signup"
    })
    .to_string();
    let statements = vec![
        prepared(
            db,
            "UPDATE pending_signups SET consumed_at = ?, updated_at = ? \
             WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?",
            vec![
                bind_text(&consumed_at),
                bind_text(&consumed_at),
                bind_text(&token_hash),
                bind_text(&consumed_at),
            ],
        )?,
        prepared(
            db,
            "INSERT INTO portal_users (email, full_name, verified_at, created_at, updated_at) \
             SELECT email, full_name, ?, ?, ? FROM pending_signups \
             WHERE token_hash = ? AND consumed_at = ? \
             ON CONFLICT(email) DO UPDATE SET full_name = excluded.full_name, \
              verified_at = excluded.verified_at, updated_at = excluded.updated_at",
            vec![
                bind_text(&consumed_at),
                bind_text(&consumed_at),
                bind_text(&consumed_at),
                bind_text(&token_hash),
                bind_text(&consumed_at),
            ],
        )?,
        prepared(
            db,
            "INSERT INTO accounts \
             (id, name, slug, billing_email, preferred_currency, status, metadata_json, created_at, updated_at) \
             SELECT ?, school_name, ?, email, preferred_currency, 'active', ?, ?, ? \
             FROM pending_signups WHERE token_hash = ? AND consumed_at = ?",
            vec![
                bind_text(&account_id),
                bind_text(&account_slug),
                bind_text(&metadata),
                bind_text(&consumed_at),
                bind_text(&consumed_at),
                bind_text(&token_hash),
                bind_text(&consumed_at),
            ],
        )?,
        prepared(
            db,
            "INSERT INTO account_members (id, account_id, email, role, created_at, updated_at) \
             SELECT ?, ?, email, 'admin', ?, ? FROM pending_signups \
             WHERE token_hash = ? AND consumed_at = ?",
            vec![
                bind_text(&Uuid::new_v4().to_string()),
                bind_text(&account_id),
                bind_text(&consumed_at),
                bind_text(&consumed_at),
                bind_text(&token_hash),
                bind_text(&consumed_at),
            ],
        )?,
        prepared(
            db,
            "INSERT INTO portal_sessions (id, email, token_hash, expires_at, last_seen_at, created_at) \
             SELECT ?, email, ?, ?, ?, ? FROM pending_signups \
             WHERE token_hash = ? AND consumed_at = ?",
            vec![
                bind_text(&Uuid::new_v4().to_string()),
                bind_text(&session_hash),
                bind_text(&session_expires_at),
                bind_text(&consumed_at),
                bind_text(&consumed_at),
                bind_text(&token_hash),
                bind_text(&consumed_at),
            ],
        )?,
        prepared(
            db,
            "INSERT INTO audit_events \
             (id, actor_type, actor_id, account_id, action, target_type, target_id, metadata_json, created_at) \
             SELECT ?, 'customer', email, ?, 'customer.signup_completed', 'account', ?, ?, ? \
             FROM pending_signups WHERE token_hash = ? AND consumed_at = ?",
            vec![
                bind_text(&Uuid::new_v4().to_string()),
                bind_text(&account_id),
                bind_text(&account_id),
                bind_text(&metadata),
                bind_text(&consumed_at),
                bind_text(&token_hash),
                bind_text(&consumed_at),
            ],
        )?,
    ];
    let changes = batch_changes(db, statements).await?;
    if changes.as_slice() != [1, 1, 1, 1, 1, 1] {
        return redirect(&config.customer_app_url, "/login?signup=invalid");
    }
    let mut response = redirect(&config.customer_app_url, "/portal?signup=complete")?;
    set_cookie(
        &mut response,
        CUSTOMER_SESSION_COOKIE,
        &session_token,
        max_age,
        config.is_production(),
    )?;
    Ok(response)
}

pub async fn customer_logout(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<Response> {
    logout(db, request, config, Audience::Customer).await
}

pub async fn owner_logout(
    db: &D1Database,
    request: &Request,
    config: &Config,
) -> ApiResult<Response> {
    logout(db, request, config, Audience::Owner).await
}

async fn logout(
    db: &D1Database,
    request: &Request,
    config: &Config,
    audience: Audience,
) -> ApiResult<Response> {
    if let (Some(token), Some(pepper)) = (
        cookie(request, audience.cookie()),
        config.session_pepper.as_deref(),
    ) {
        let token_hash = hash_secret(&token, Some(pepper));
        let query = format!(
            "UPDATE {} SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            audience.session_table()
        );
        execute(
            db,
            &query,
            vec![bind_text(&now_iso()?), bind_text(&token_hash)],
        )
        .await?;
    }
    let mut response = json(&json!({ "ok": true }))?;
    delete_cookie(&mut response, audience.cookie())?;
    Ok(response)
}

fn ensure_email_ready(config: &Config, email_sender: Option<&SendEmail>) -> ApiResult<()> {
    if config.is_production()
        && (email_sender.is_none()
            || config.auth_from_email.is_none()
            || config.rerout_api_key.is_none())
    {
        Err(ApiError::Configuration)
    } else {
        Ok(())
    }
}

fn auth_target_url(app_url: &str, path: &str, token: &str) -> ApiResult<String> {
    let encoded = url::form_urlencoded::byte_serialize(token.as_bytes()).collect::<String>();
    url::Url::parse(&format!(
        "{}{path}?token={encoded}",
        app_url.trim_end_matches('/')
    ))
    .map(|url| url.to_string())
    .map_err(|_| ApiError::Configuration)
}

async fn delivery_url(target_url: &str, expiry: i64, config: &Config) -> ApiResult<String> {
    match config.rerout_api_key.as_deref() {
        Some(api_key) => create_short_link(target_url, expiry, api_key).await,
        None if !config.is_production() => Ok(target_url.to_owned()),
        None => Err(ApiError::Configuration),
    }
}

#[derive(Clone, Copy)]
enum EmailKind {
    CustomerAccess,
    CustomerSignIn,
    CustomerSignup,
    OwnerSignIn,
}

async fn send_auth_email(
    sender: &SendEmail,
    from: &CanonicalEmail,
    email: &CanonicalEmail,
    url: &str,
    kind: EmailKind,
) -> ApiResult<()> {
    let content = email_content(url, kind);
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

pub(crate) async fn send_customer_access_email(
    sender: &SendEmail,
    from: &CanonicalEmail,
    email: &CanonicalEmail,
    customer_app_url: &str,
) -> ApiResult<()> {
    let url = customer_login_url(customer_app_url)?;
    send_auth_email(sender, from, email, &url, EmailKind::CustomerAccess).await
}

fn customer_login_url(customer_app_url: &str) -> ApiResult<String> {
    url::Url::parse(customer_app_url)
        .and_then(|base| base.join("/login"))
        .map(|url| url.to_string())
        .map_err(|_| ApiError::Configuration)
}

struct EmailContent {
    subject: &'static str,
    text: String,
    html: String,
}

fn email_content(url: &str, kind: EmailKind) -> EmailContent {
    match kind {
        EmailKind::CustomerAccess => EmailContent {
            subject: "Campus Pilot customer access",
            text: format!(
                "Customer administrator access is ready. Open the customer portal and request a sign-in link: {url}"
            ),
            html: format!(
                "<p>Customer administrator access is ready.</p><p><a href=\"{url}\">Open customer portal</a></p>"
            ),
        },
        EmailKind::CustomerSignIn => action_email("Sign in to Campus Pilot", "Sign in", url),
        EmailKind::CustomerSignup => {
            action_email("Confirm your Campus Pilot account", "Confirm account", url)
        }
        EmailKind::OwnerSignIn => {
            action_email("Sign in to Campus Pilot owner console", "Sign in", url)
        }
    }
}

fn action_email(subject: &'static str, action: &str, url: &str) -> EmailContent {
    EmailContent {
        subject,
        text: format!("{action}: {url}"),
        html: format!("<p><a href=\"{url}\">{action}</a></p>"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountAccess, AccountRole, AuthenticatedPortalUser, CustomerIdentity, EmailKind,
        SignupInput, customer_login_url, email_content,
    };
    use crate::domain::CanonicalEmail;

    fn test_user() -> AuthenticatedPortalUser {
        let email = match CanonicalEmail::parse("admin@example.com") {
            Ok(value) => value,
            Err(error) => panic!("test email invalid: {error}"),
        };
        AuthenticatedPortalUser(CustomerIdentity {
            email,
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
    fn owner_and_customer_emails_are_distinct() {
        let access = email_content("https://example.test/login", EmailKind::CustomerAccess);
        let customer = email_content("https://example.test/customer", EmailKind::CustomerSignIn);
        let owner = email_content("https://example.test/owner", EmailKind::OwnerSignIn);
        assert_eq!(access.subject, "Campus Pilot customer access");
        assert!(access.text.contains("request a sign-in link"));
        assert!(access.html.contains("Open customer portal"));
        assert_eq!(customer.subject, "Sign in to Campus Pilot");
        assert!(owner.subject.contains("owner console"));
        assert_ne!(customer.text, owner.text);
    }

    #[test]
    fn customer_access_email_uses_the_customer_login_surface() {
        assert_eq!(
            customer_login_url("https://customer.example.test/portal")
                .unwrap_or_else(|_| unreachable!()),
            "https://customer.example.test/login"
        );
        assert!(customer_login_url("not-a-url").is_err());
    }

    #[test]
    fn signup_parses_country_and_currency() {
        assert!(
            SignupInput::parse(
                "Ngoni Man",
                "admin@example.com",
                "Example School",
                "zw",
                "usd",
            )
            .is_ok()
        );
        assert!(
            SignupInput::parse(
                "Ngoni Man",
                "admin@example.com",
                "Example School",
                "Zimbabwe",
                "USD",
            )
            .is_err()
        );
    }
}
