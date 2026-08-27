//! Explicit HTTP route handlers for public, customer, installation, and owner control-plane APIs.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use worker::{Request, Response, RouteContext};

use crate::auth::{
    AccountRole, SignupInput, consume_customer_magic_link, consume_owner_magic_link,
    consume_signup, customer_logout, customer_session, owner_logout, owner_session,
    request_customer_magic_link, request_owner_magic_link, request_signup, require_owner,
    require_user, send_customer_access_email,
};
use crate::config::Config;
use crate::domain::{InstallationCredential, PaymentProviderKey};
use crate::error::ApiError;
use crate::http::{
    ApiResult, assert_same_origin, bearer_token, finish, json as json_response, json_body,
    json_status, request_id,
};
use crate::licensing::{
    ActivationRequest, activate, installation_by_id, installation_from_credential, issue,
    public_keys,
};
use crate::operations::{
    CreateAccountInput, CreatePlanPriceInput, CustomerAdministratorGrantOutput,
    GrantCustomerAdministratorInput, PlanPatch, create_account, create_activation_code,
    create_manual_subscription, create_plan_price, grant_customer_administrator, owner_accounts,
    owner_audit, owner_installations, owner_leases, owner_overview, owner_plans,
    revoke_installation, update_plan,
};
use crate::payments::{
    CheckoutRequest, create_billing_portal, create_checkout, owner_payment_activity,
    process_webhook, providers, webhook_signature_header,
};
use crate::store::{all, bind_text};

#[derive(Debug, Deserialize)]
struct EmailInput {
    email: String,
}

#[derive(Debug, Deserialize)]
struct SignupBody {
    full_name: String,
    email: String,
    school_name: String,
    country: String,
    preferred_currency: String,
}

#[derive(Debug, Deserialize)]
struct ActivationInput {
    activation_code: String,
    tenant_id: String,
    deployment_id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct AccountIdInput {
    account_id: String,
    provider: String,
}

#[derive(Debug, Deserialize)]
struct ActivationCodeInput {
    account_id: String,
    label: String,
}

#[derive(Debug, Deserialize)]
struct CheckoutInput {
    account_id: String,
    plan_price_id: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
struct CreatePlanPriceBody {
    plan_id: String,
    provider: String,
    currency: String,
    currency_exponent: u8,
    amount_minor: i64,
    billing_interval: String,
    external_product_id: Option<String>,
    external_price_id: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct CreateAccountBody {
    name: String,
    billing_email: String,
    member_email: String,
}

#[derive(Debug, Deserialize)]
struct GrantCustomerAdministratorBody {
    email: String,
}

#[derive(Debug, Serialize)]
struct GrantCustomerAdministratorResponse {
    #[serde(flatten)]
    grant: CustomerAdministratorGrantOutput,
    access_email: CustomerAccessEmailStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum CustomerAccessEmailStatus {
    Sent,
    Failed,
    NotRequired,
}

#[derive(Debug, Deserialize)]
struct ManualSubscriptionInput {
    account_id: String,
    plan_id: String,
    current_period_end: String,
}

#[derive(Debug, Deserialize)]
struct ReasonInput {
    reason: String,
}

pub async fn health(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = (|| -> ApiResult<Response> {
        let config = Config::from_env(&context.env)?;
        json_response(&json!({
            "status": "ok",
            "service": "campus-pilot-control-plane",
            "environment": config.environment,
            "signing_ready": config.signing_private_key.is_some(),
            "payments_ready": providers(&config).into_iter().any(|provider| provider.configured),
            "email_ready": context.env.send_email("EMAIL").is_ok()
                && config.auth_from_email.is_some()
                && (!config.is_production() || config.rerout_api_key.is_some()),
        }))
    })();
    finish(result, &id)
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PortalSurface {
    Customer,
    Owner,
    Unknown,
}

pub async fn portal_surface(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = (|| -> ApiResult<Response> {
        let config = Config::from_env(&context.env)?;
        let request_url = request.url().map_err(ApiError::from)?;
        let requested_path = request_url
            .query_pairs()
            .find_map(|(key, value)| (key == "path").then(|| value.into_owned()))
            .unwrap_or_else(|| "/".to_owned());
        let surface = classify_portal_surface(
            &request_url.origin().ascii_serialization(),
            &config.customer_app_url,
            &config.owner_app_url,
            &requested_path,
        );
        json_response(&json!({ "surface": surface }))
    })();
    finish(result, &id)
}

pub async fn keys(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let id = request_id(&request);
    let result =
        Config::from_env(&context.env).and_then(|config| json_response(&public_keys(&config)));
    finish(result, &id)
}

pub async fn customer_auth_signup(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.customer_app_url, &config)?;
        let body = json_body::<SignupBody>(&mut request).await?;
        let input = SignupInput::parse(
            &body.full_name,
            &body.email,
            &body.school_name,
            &body.country,
            &body.preferred_currency,
        )?;
        let email_sender = context.env.send_email("EMAIL").ok();
        request_signup(
            &context.d1("DB")?,
            input,
            &request_ip(&request)?,
            &config,
            email_sender.as_ref(),
        )
        .await
    }
    .await;
    finish(result, &id)
}

pub async fn customer_auth_request_link(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.customer_app_url, &config)?;
        let input = json_body::<EmailInput>(&mut request).await?;
        let email_sender = context.env.send_email("EMAIL").ok();
        request_customer_magic_link(
            &context.d1("DB")?,
            &input.email,
            &request_ip(&request)?,
            &config,
            email_sender.as_ref(),
        )
        .await
    }
    .await;
    finish(result, &id)
}

pub async fn customer_auth_consume(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        consume_customer_magic_link(&context.d1("DB")?, &query_token(&request)?, &config).await
    }
    .await;
    finish(result, &id)
}

pub async fn customer_signup_consume(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        consume_signup(&context.d1("DB")?, &query_token(&request)?, &config).await
    }
    .await;
    finish(result, &id)
}

pub async fn customer_auth_logout(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.customer_app_url, &config)?;
        customer_logout(&context.d1("DB")?, &request, &config).await
    }
    .await;
    finish(result, &id)
}

pub async fn customer_session_view(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        customer_session(&context.d1("DB")?, &request, &config).await
    }
    .await;
    finish(result, &id)
}

pub async fn owner_auth_request_link(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.owner_app_url, &config)?;
        let input = json_body::<EmailInput>(&mut request).await?;
        let email_sender = context.env.send_email("EMAIL").ok();
        request_owner_magic_link(
            &context.d1("DB")?,
            &input.email,
            &request_ip(&request)?,
            &config,
            email_sender.as_ref(),
        )
        .await
    }
    .await;
    finish(result, &id)
}

pub async fn owner_auth_consume(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        consume_owner_magic_link(&context.d1("DB")?, &query_token(&request)?, &config).await
    }
    .await;
    finish(result, &id)
}

pub async fn owner_auth_logout(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.owner_app_url, &config)?;
        owner_logout(&context.d1("DB")?, &request, &config).await
    }
    .await;
    finish(result, &id)
}

pub async fn owner_session_view(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        owner_session(&context.d1("DB")?, &request, &config).await
    }
    .await;
    finish(result, &id)
}

pub async fn plans(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let rows = all::<Value>(
            &context.d1("DB")?,
            "SELECT id, key, name, description, modules_json, features_json, limits_json, trial_days FROM plans \
             WHERE status = 'active' ORDER BY sort_order, name",
            vec![],
        )
        .await?;
        let prices = all::<Value>(
            &context.d1("DB")?,
            "SELECT id, plan_id, provider, currency, currency_exponent, amount_minor, billing_interval \
             FROM plan_prices WHERE status = 'active' ORDER BY plan_id, provider, currency",
            vec![],
        )
        .await?;
        json_response(&json!({
            "plans": rows.into_iter().map(expand_json_fields).collect::<Vec<_>>(),
            "prices": prices,
        }))
    }
    .await;
    finish(result, &id)
}

pub async fn portal_overview(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        let db = context.d1("DB")?;
        let user = require_user(&db, &request, &config).await?;
        let email = user.identity().email.as_str();
        let accounts = all::<Value>(
            &db,
            "SELECT accounts.id, accounts.name, accounts.slug, accounts.billing_email, accounts.status, \
             account_members.role, subscriptions.id AS subscription_id, subscriptions.status AS subscription_status, \
             subscriptions.provider, subscriptions.current_period_end, subscriptions.cancel_at_period_end, plans.id AS plan_id, \
             plans.name AS plan_name, plans.key AS plan_key, plans.modules_json, plans.features_json, plans.limits_json \
             FROM account_members INNER JOIN accounts ON accounts.id = account_members.account_id \
             LEFT JOIN subscriptions ON subscriptions.id = (SELECT candidate.id FROM subscriptions AS candidate \
             WHERE candidate.account_id = accounts.id ORDER BY candidate.updated_at DESC LIMIT 1) \
             LEFT JOIN plans ON plans.id = subscriptions.plan_id WHERE LOWER(account_members.email) = ? \
             AND account_members.deleted_at IS NULL AND accounts.deleted_at IS NULL ORDER BY accounts.name",
            vec![bind_text(email)],
        )
        .await?;
        let installations = all::<Value>(
            &db,
            "SELECT installations.id, installations.account_id, installations.name, installations.status, \
             installations.credential_hint, installations.last_seen_at, installations.created_at, \
             leases.lease_expires_at, leases.grace_until FROM installations \
             LEFT JOIN leases ON leases.id = installations.current_lease_id WHERE installations.account_id IN \
             (SELECT account_id FROM account_members WHERE LOWER(email) = ? AND deleted_at IS NULL) \
             ORDER BY installations.created_at DESC",
            vec![bind_text(email)],
        )
        .await?;
        json_response(&json!({
            "accounts": accounts.into_iter().map(expand_json_fields).collect::<Vec<_>>(),
            "installations": installations,
        }))
    }
    .await;
    finish(result, &id)
}

pub async fn portal_checkout(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.customer_app_url, &config)?;
        let db = context.d1("DB")?;
        let user = require_user(&db, &request, &config).await?;
        let input = json_body::<CheckoutInput>(&mut request).await?;
        user.require_account(
            &input.account_id,
            &[AccountRole::Admin, AccountRole::Billing],
        )?;
        let parsed = CheckoutRequest::parse(
            &input.account_id,
            &input.plan_price_id,
            user.identity().email.as_str(),
            &input.idempotency_key,
        )?;
        json_status(&create_checkout(&db, &parsed, &config, &id).await?, 201)
    }
    .await;
    finish(result, &id)
}

pub async fn portal_billing(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.customer_app_url, &config)?;
        let db = context.d1("DB")?;
        let user = require_user(&db, &request, &config).await?;
        let input = json_body::<AccountIdInput>(&mut request).await?;
        user.require_account(
            &input.account_id,
            &[AccountRole::Admin, AccountRole::Billing],
        )?;
        let provider = PaymentProviderKey::parse(&input.provider)?;
        json_response(&create_billing_portal(&db, &input.account_id, &provider, &config).await?)
    }
    .await;
    finish(result, &id)
}

pub async fn portal_activation_code(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.customer_app_url, &config)?;
        let db = context.d1("DB")?;
        let user = require_user(&db, &request, &config).await?;
        let input = json_body::<ActivationCodeInput>(&mut request).await?;
        json_status(
            &create_activation_code(&db, &user, &input.account_id, &input.label, &config, &id)
                .await?,
            201,
        )
    }
    .await;
    finish(result, &id)
}

pub async fn installation_activate(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        let input = json_body::<ActivationInput>(&mut request).await?;
        let parsed = ActivationRequest::parse(
            &input.activation_code,
            &input.tenant_id,
            &input.deployment_id,
            &input.name,
        )?;
        let output = activate(&context.d1("DB")?, parsed, &config, &id).await?;
        json_status(&output, 201)
    }
    .await;
    finish(result, &id)
}

pub async fn lease_renew(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        let token = bearer_token(&request).ok_or_else(|| {
            ApiError::client(
                "installation_authentication_required",
                "Installation authentication is required",
                401,
            )
        })?;
        let credential = InstallationCredential::parse(&token)?;
        let db = context.d1("DB")?;
        let installation = installation_from_credential(&db, &credential, &config).await?;
        json_response(&issue(&db, &installation, &config, &id).await?)
    }
    .await;
    finish(result, &id)
}

pub async fn portal_license(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        let db = context.d1("DB")?;
        let user = require_user(&db, &request, &config).await?;
        let installation_id = context.param("installationId").ok_or_else(|| {
            ApiError::client("installation_not_found", "Installation not found", 404)
        })?;
        let installation = installation_by_id(&db, installation_id)
            .await?
            .ok_or_else(|| {
                ApiError::client("installation_not_found", "Installation not found", 404)
            })?;
        user.require_account(&installation.account_id, &[AccountRole::Admin])?;
        let lease = issue(&db, &installation, &config, &id).await?;
        let bundle = serde_json::to_string_pretty(&json!({
            "format": "cp-license-bundle/v1",
            "key_id": config.signing_key_id,
            "lease": lease.token,
        }))
        .map_err(|_| ApiError::Internal)?;
        let mut response = Response::ok(bundle).map_err(ApiError::from)?;
        response
            .headers_mut()
            .set("content-type", "application/vnd.campus-pilot.license+json")
            .map_err(ApiError::from)?;
        response
            .headers_mut()
            .set(
                "content-disposition",
                &format!(
                    "attachment; filename=\"campus-pilot-{}.cp-license\"",
                    installation.id
                ),
            )
            .map_err(ApiError::from)?;
        Ok(response)
    }
    .await;
    finish(result, &id)
}

pub async fn payment_webhook(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        let provider_value = context.param("provider").ok_or_else(|| {
            ApiError::client(
                "payment_provider_required",
                "Payment provider is required",
                400,
            )
        })?;
        let provider = PaymentProviderKey::parse(provider_value)?;
        let signature_header = webhook_signature_header(&provider, &config)?;
        let signature = request
            .headers()
            .get(signature_header)
            .map_err(ApiError::from)?
            .ok_or_else(|| {
                ApiError::client(
                    "payment_signature_required",
                    "Payment provider signature is required",
                    400,
                )
            })?;
        let raw_body = request.text().await.map_err(ApiError::from)?;
        json_response(
            &process_webhook(
                &context.d1("DB")?,
                &provider,
                &raw_body,
                &signature,
                &config,
                &id,
            )
            .await?,
        )
    }
    .await;
    finish(result, &id)
}

pub async fn owner_overview_view(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    owner_read(request, context, OwnerRead::Overview).await
}

pub async fn owner_accounts_view(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    owner_read(request, context, OwnerRead::Accounts).await
}

pub async fn owner_plans_view(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    owner_read(request, context, OwnerRead::Plans).await
}

pub async fn owner_installations_view(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    owner_read(request, context, OwnerRead::Installations).await
}

pub async fn owner_leases_view(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    owner_read(request, context, OwnerRead::Leases).await
}

pub async fn owner_audit_view(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    owner_read(request, context, OwnerRead::Audit).await
}

pub async fn owner_create_account(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.owner_app_url, &config)?;
        let db = context.d1("DB")?;
        let operator = require_owner(&db, &request, &config).await?;
        let body = json_body::<CreateAccountBody>(&mut request).await?;
        let input = CreateAccountInput::parse(&body.name, &body.billing_email, &body.member_email)?;
        json_status(&create_account(&db, &operator, input, &id).await?, 201)
    }
    .await;
    finish(result, &id)
}

pub async fn owner_grant_customer_administrator(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.owner_app_url, &config)?;
        let db = context.d1("DB")?;
        let operator = require_owner(&db, &request, &config).await?;
        let account_id = context
            .param("accountId")
            .ok_or_else(|| ApiError::client("account_not_found", "Customer not found", 404))?;
        let body = json_body::<GrantCustomerAdministratorBody>(&mut request).await?;
        let input = GrantCustomerAdministratorInput::parse(account_id, &body.email)?;
        let grant = grant_customer_administrator(&db, &operator, input, &id).await?;
        let email_sender = context.env.send_email("EMAIL").ok();
        let access_email = match (
            grant.requires_access_email(),
            email_sender.as_ref(),
            config.auth_from_email.as_ref(),
        ) {
            (false, _, _) => CustomerAccessEmailStatus::NotRequired,
            (true, Some(sender), Some(from)) => {
                match send_customer_access_email(
                    sender,
                    from,
                    grant.email(),
                    &config.customer_app_url,
                )
                .await
                {
                    Ok(()) => CustomerAccessEmailStatus::Sent,
                    Err(_) => {
                        worker::console_error!("customer access email failed request_id={id}");
                        CustomerAccessEmailStatus::Failed
                    }
                }
            }
            (true, _, _) => CustomerAccessEmailStatus::Failed,
        };
        json_response(&GrantCustomerAdministratorResponse {
            grant,
            access_email,
        })
    }
    .await;
    finish(result, &id)
}

pub async fn owner_update_plan(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.owner_app_url, &config)?;
        let db = context.d1("DB")?;
        let operator = require_owner(&db, &request, &config).await?;
        let plan_id = context
            .param("planId")
            .ok_or_else(|| ApiError::client("plan_not_found", "Plan not found", 404))?;
        let patch = json_body::<PlanPatch>(&mut request).await?;
        update_plan(&db, &operator, plan_id, patch, &id).await?;
        json_response(&json!({ "ok": true }))
    }
    .await;
    finish(result, &id)
}

pub async fn owner_create_plan_price(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.owner_app_url, &config)?;
        let db = context.d1("DB")?;
        let operator = require_owner(&db, &request, &config).await?;
        let body = json_body::<CreatePlanPriceBody>(&mut request).await?;
        if body.status == "active"
            && !providers(&config).iter().any(|provider| {
                provider.key.eq_ignore_ascii_case(&body.provider)
                    && provider.adapter_status == "available"
                    && provider.configured
            })
        {
            return Err(ApiError::client(
                "payment_provider_unavailable",
                "Configure an available payment provider before activating this option",
                409,
            ));
        }
        let input = CreatePlanPriceInput::parse(
            &body.plan_id,
            &body.provider,
            &body.currency,
            body.currency_exponent,
            body.amount_minor,
            &body.billing_interval,
            body.external_product_id.as_deref(),
            &body.external_price_id,
            &body.status,
        )?;
        json_status(&create_plan_price(&db, &operator, input, &id).await?, 201)
    }
    .await;
    finish(result, &id)
}

pub async fn owner_payment_providers(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        let db = context.d1("DB")?;
        require_owner(&db, &request, &config).await?;
        json_response(&json!({ "providers": providers(&config) }))
    }
    .await;
    finish(result, &id)
}

pub async fn owner_payments_view(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        let db = context.d1("DB")?;
        require_owner(&db, &request, &config).await?;
        json_response(&owner_payment_activity(&db, &config).await?)
    }
    .await;
    finish(result, &id)
}

pub async fn owner_manual_subscription(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.owner_app_url, &config)?;
        let db = context.d1("DB")?;
        let operator = require_owner(&db, &request, &config).await?;
        let input = json_body::<ManualSubscriptionInput>(&mut request).await?;
        let subscription_id = create_manual_subscription(
            &db,
            &operator,
            &input.account_id,
            &input.plan_id,
            &input.current_period_end,
            &id,
        )
        .await?;
        json_status(&json!({ "id": subscription_id }), 201)
    }
    .await;
    finish(result, &id)
}

pub async fn owner_revoke_installation(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        assert_same_origin(&request, &config.owner_app_url, &config)?;
        let db = context.d1("DB")?;
        let operator = require_owner(&db, &request, &config).await?;
        let installation_id = context.param("installationId").ok_or_else(|| {
            ApiError::client("installation_not_found", "Installation not found", 404)
        })?;
        let input = json_body::<ReasonInput>(&mut request).await?;
        revoke_installation(&db, &operator, installation_id, &input.reason, &id).await?;
        json_response(&json!({ "ok": true }))
    }
    .await;
    finish(result, &id)
}

enum OwnerRead {
    Overview,
    Accounts,
    Plans,
    Installations,
    Leases,
    Audit,
}

async fn owner_read(
    request: Request,
    context: RouteContext<()>,
    query: OwnerRead,
) -> worker::Result<Response> {
    let id = request_id(&request);
    let result = async {
        let config = Config::from_env(&context.env)?;
        let db = context.d1("DB")?;
        require_owner(&db, &request, &config).await?;
        let value = match query {
            OwnerRead::Overview => owner_overview(&db).await?,
            OwnerRead::Accounts => owner_accounts(&db).await?,
            OwnerRead::Plans => owner_plans(&db).await?,
            OwnerRead::Installations => owner_installations(&db).await?,
            OwnerRead::Leases => owner_leases(&db).await?,
            OwnerRead::Audit => owner_audit(&db).await?,
        };
        json_response(&value)
    }
    .await;
    finish(result, &id)
}

fn request_ip(request: &Request) -> ApiResult<String> {
    request
        .headers()
        .get("cf-connecting-ip")
        .map_err(ApiError::from)
        .map(|value| value.unwrap_or_else(|| "unknown".to_owned()))
}

fn query_token(request: &Request) -> ApiResult<String> {
    request
        .url()
        .map_err(ApiError::from)?
        .query_pairs()
        .find_map(|(key, value)| (key == "token").then(|| value.into_owned()))
        .ok_or_else(|| ApiError::client("magic_link_invalid", "The sign-in link is invalid", 400))
}

fn classify_portal_surface(
    request_origin: &str,
    customer_app_url: &str,
    owner_app_url: &str,
    requested_path: &str,
) -> PortalSurface {
    let customer_origin = url::Url::parse(customer_app_url)
        .ok()
        .map(|url| url.origin().ascii_serialization());
    let owner_origin = url::Url::parse(owner_app_url)
        .ok()
        .map(|url| url.origin().ascii_serialization());
    match (customer_origin, owner_origin) {
        (Some(customer), Some(owner)) if customer != owner => {
            if request_origin == owner {
                PortalSurface::Owner
            } else if request_origin == customer {
                PortalSurface::Customer
            } else {
                PortalSurface::Unknown
            }
        }
        (Some(_), Some(_)) => {
            if requested_path == "/owner" || requested_path.starts_with("/owner/") {
                PortalSurface::Owner
            } else {
                PortalSurface::Customer
            }
        }
        _ => PortalSurface::Unknown,
    }
}

fn expand_json_fields(mut row: Value) -> Value {
    let Some(object) = row.as_object_mut() else {
        return row;
    };
    for (storage, public) in [
        ("modules_json", "modules"),
        ("features_json", "features"),
        ("limits_json", "limits"),
    ] {
        let parsed = object
            .remove(storage)
            .and_then(|value| value.as_str().map(str::to_owned))
            .and_then(|value| serde_json::from_str::<Value>(&value).ok())
            .filter(Value::is_array)
            .unwrap_or_else(|| json!([]));
        object.insert(public.to_owned(), parsed);
    }
    if let Some(value) = object.get_mut("cancel_at_period_end") {
        *value = Value::Bool(value.as_i64() == Some(1));
    }
    row
}

#[cfg(test)]
mod tests {
    use super::{PortalSurface, classify_portal_surface};

    #[test]
    fn shared_host_uses_path_without_combining_sessions() {
        assert_eq!(
            classify_portal_surface(
                "https://control.example.test",
                "https://control.example.test",
                "https://control.example.test",
                "/owner/login",
            ),
            PortalSurface::Owner
        );
        assert_eq!(
            classify_portal_surface(
                "https://control.example.test",
                "https://control.example.test",
                "https://control.example.test",
                "/signup",
            ),
            PortalSurface::Customer
        );
    }

    #[test]
    fn separate_hosts_override_a_misleading_path() {
        assert_eq!(
            classify_portal_surface(
                "https://account.example.test",
                "https://account.example.test",
                "https://owner.example.test",
                "/owner/login",
            ),
            PortalSurface::Customer
        );
        assert_eq!(
            classify_portal_surface(
                "https://owner.example.test",
                "https://account.example.test",
                "https://owner.example.test",
                "/signup",
            ),
            PortalSurface::Owner
        );
    }
}
