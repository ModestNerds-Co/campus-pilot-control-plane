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
REROUT_API_KEY="rrk_..."
# Add only the adapters used in this environment, for example:
STRIPE_SECRET_KEY="sk_test_..."
STRIPE_WEBHOOK_SECRET="whsec_..."
```

Portal magic links are sent through the native Cloudflare Email Sending binding. The sender domain must be onboarded in Cloudflare Email Service, `AUTH_FROM_EMAIL` must use that domain, and the Worker binding should restrict `allowed_sender_addresses` to the configured sender. No external email-provider API key is required.

Local Wrangler development simulates the email binding by default. When a development environment has no email binding, the magic-link request endpoint returns a local preview URL. Production never returns authentication tokens.

## Cloudflare deployment

1. Create D1 with `pnpm wrangler d1 create campus-pilot-control-plane` and put its ID in `wrangler.jsonc`.
2. Apply migrations with `pnpm db:migrate:remote`.
3. Configure every secret through Wrangler or Secrets Store.
4. Onboard the sender domain under Cloudflare Email Service, configure the `send_email` binding, and set `AUTH_FROM_EMAIL` as a non-secret var.
5. Set production `PUBLIC_APP_URL` and signing metadata as non-secret vars; keep `OWNER_EMAILS` and `REROUT_API_KEY` in Worker secrets. Production sign-in emails use expiring Rerout links so raw authentication tokens are not shown in the email.
6. Build and deploy with `pnpm deploy`.
7. Put Cloudflare Access in front of `/owner/*` and `/api/owner/*` as defense in depth.
8. Register `/api/webhooks/{provider}` for every configured adapter and test checkout, renewal, failure, cancellation, refund, activation, lease renewal, and revocation end to end.

Plans do not contain one global price. Add provider price mappings per currency in the owner portal. The core stores explicit currency exponents and integer minor units, and keeps original, settlement, fee, and exchange-rate evidence separate.
