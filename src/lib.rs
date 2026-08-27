//! Cloudflare Worker entry point for Campus Pilot licensing and customer billing.

#![deny(warnings)]

mod audit;
mod auth;
mod clock;
mod config;
mod crypto;
mod domain;
mod error;
mod http;
mod licensing;
mod operations;
mod payments;
mod routes;
mod store;

use worker::{Context, Env, Request, Response, Result, Router, event};

#[event(fetch)]
async fn fetch(request: Request, env: Env, _context: Context) -> Result<Response> {
    Router::new()
        .get_async("/api/health", routes::health)
        .get_async("/api/v1/keys", routes::keys)
        .post_async("/api/auth/request-link", routes::auth_request_link)
        .get_async("/api/auth/consume", routes::auth_consume)
        .post_async("/api/auth/logout", routes::auth_logout)
        .get_async("/api/session", routes::session_view)
        .get_async("/api/catalog/plans", routes::plans)
        .get_async("/api/portal/overview", routes::portal_overview)
        .post_async("/api/portal/checkout", routes::portal_checkout)
        .post_async("/api/portal/billing", routes::portal_billing)
        .post_async(
            "/api/portal/activation-codes",
            routes::portal_activation_code,
        )
        .get_async(
            "/api/portal/installations/:installationId/license",
            routes::portal_license,
        )
        .post_async(
            "/api/v1/installations/activate",
            routes::installation_activate,
        )
        .post_async("/api/v1/leases/renew", routes::lease_renew)
        .post_async("/api/webhooks/:provider", routes::payment_webhook)
        .get_async("/api/owner/overview", routes::owner_overview_view)
        .get_async("/api/owner/accounts", routes::owner_accounts_view)
        .post_async("/api/owner/accounts", routes::owner_create_account)
        .get_async("/api/owner/plans", routes::owner_plans_view)
        .patch_async("/api/owner/plans/:planId", routes::owner_update_plan)
        .post_async("/api/owner/plan-prices", routes::owner_create_plan_price)
        .get_async(
            "/api/owner/payment-providers",
            routes::owner_payment_providers,
        )
        .get_async("/api/owner/payments", routes::owner_payments_view)
        .post_async(
            "/api/owner/subscriptions/manual",
            routes::owner_manual_subscription,
        )
        .get_async("/api/owner/installations", routes::owner_installations_view)
        .post_async(
            "/api/owner/installations/:installationId/revoke",
            routes::owner_revoke_installation,
        )
        .get_async("/api/owner/leases", routes::owner_leases_view)
        .get_async("/api/owner/audit", routes::owner_audit_view)
        .run(request, env)
        .await
}
