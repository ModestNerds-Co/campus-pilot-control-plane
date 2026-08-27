# Campus Pilot control plane

Vendor-operated licensing and billing for Campus Pilot. This is a separate deployable from school installations and never stores school operational records.

## Workspaces

- Customer portal: plans, checkout, billing, subscriptions, installations, activation codes, and offline license downloads.
- Owner portal: customers, plans, subscriptions, payment state, installations, leases, revocations, signing-key state, and audit.
- Installation API: one-time activation and authenticated lease renewal.

The canonical signed lease schema is [`contract/license-lease-v1.schema.json`](contract/license-lease-v1.schema.json).
Provider and currency boundaries are defined in [`docs/payment-architecture.md`](docs/payment-architecture.md).

## Local setup

```bash
pnpm install
pnpm db:migrate:local
pnpm dev
```

Create `.dev.vars` without committing it:

```dotenv
LICENSE_SIGNING_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
LICENSE_SIGNING_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
SESSION_PEPPER="replace-me"
OWNER_EMAILS="owner@example.com"
# Add only the adapters used in this environment, for example:
STRIPE_SECRET_KEY="sk_test_..."
STRIPE_WEBHOOK_SECRET="whsec_..."
RESEND_API_KEY="re_..."
AUTH_FROM_EMAIL="Campus Pilot <licensing@example.com>"
```

When `ENVIRONMENT=development` and email delivery is not configured, the magic-link request endpoint returns a local preview URL. Production never returns authentication tokens.
Production customer and owner sign-in requires both `RESEND_API_KEY` and `AUTH_FROM_EMAIL`; without them, the portal displays an email-delivery setup state.

## Cloudflare deployment

1. Create D1 with `pnpm wrangler d1 create campus-pilot-control-plane` and put its ID in `wrangler.jsonc`.
2. Apply migrations with `pnpm db:migrate:remote`.
3. Configure every secret through Wrangler or Secrets Store.
4. Set production `PUBLIC_APP_URL` and signing metadata as non-secret vars; keep `OWNER_EMAILS` in Worker secrets.
5. Build and deploy with `pnpm deploy`.
6. Put Cloudflare Access in front of `/owner/*` and `/api/owner/*` as defense in depth.
7. Register `/api/webhooks/{provider}` for every configured adapter and test checkout, renewal, failure, cancellation, refund, activation, lease renewal, and revocation end to end.

Plans do not contain one global price. Add provider price mappings per currency in the owner portal. The core stores explicit currency exponents and integer minor units, and keeps original, settlement, fee, and exchange-rate evidence separate.
