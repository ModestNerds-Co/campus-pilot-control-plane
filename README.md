# Campus Pilot control plane

Vendor-operated licensing and billing for Campus Pilot. This is a separate deployable from school installations and never stores school operational records.

## Applications

- Customer portal: public signup and customer-only access to plans, checkout, billing, subscriptions, installations, activation codes, and offline license downloads.
- Owner console: separately authenticated access to customers, plans, subscriptions, payment state, installations, leases, revocations, signing-key state, and audit.
- Installation API: one-time activation and authenticated lease renewal.

Customer and owner identities, cookies, sessions, routes, and UI shells are separate. See [`docs/portal-architecture.md`](docs/portal-architecture.md).

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
# Optional during rotation; maps previous key IDs to public PEM values.
LICENSE_PREVIOUS_SIGNING_PUBLIC_KEYS_JSON='{"production-1":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}'
SESSION_PEPPER="replace-me"
OWNER_EMAILS="owner@example.com"
REROUT_API_KEY="rrk_..."
# Add only the adapters used in this environment, for example:
STRIPE_SECRET_KEY="sk_test_..."
STRIPE_WEBHOOK_SECRET="whsec_..."
```

Portal magic links are sent through the native Cloudflare Email Sending binding. The sender domain must be onboarded in Cloudflare Email Service, `AUTH_FROM_EMAIL` must use that domain, and the Worker binding should restrict `allowed_sender_addresses` to the configured sender. No external email-provider API key is required.

Local development returns a direct preview URL instead of sending email. Production sends only expiring Rerout links and never returns authentication tokens.

## Cloudflare deployment

1. Create D1 with `pnpm wrangler d1 create campus-pilot-control-plane` and put its ID in `wrangler.jsonc`.
2. Apply migrations with `pnpm db:migrate:remote`.
3. Configure every secret through Wrangler or Secrets Store.
4. Onboard the sender domain under Cloudflare Email Service, configure the `send_email` binding, and set `AUTH_FROM_EMAIL` as a non-secret var.
5. Set production `CUSTOMER_APP_URL`, `OWNER_APP_URL`, and signing metadata as non-secret vars; keep `OWNER_EMAILS` and `REROUT_API_KEY` in Worker secrets. `PUBLIC_APP_URL` remains a local and migration fallback only.
6. Build and deploy with `pnpm deploy`.
7. Put Cloudflare Access in front of `/owner/*` and `/api/owner/*` as defense in depth.
8. Register `/api/webhooks/{provider}` for every configured adapter and test checkout, renewal, failure, cancellation, refund, activation, lease renewal, and revocation end to end.

### Signing-key rotation

1. Generate the next Ed25519 key pair and assign a new immutable `LICENSE_SIGNING_KEY_ID`.
2. Add the next public key to every Campus Pilot trusted keyring while the old key remains active. Verify both key IDs against shared lease vectors.
3. Change the control plane's active key ID, private key, and public key together. Put the previous public key in `LICENSE_PREVIOUS_SIGNING_PUBLIC_KEYS_JSON`; never retain its private key in application configuration.
4. Confirm `/api/v1/keys` reports exactly one `current` key plus the intended previous keys, then exercise activation, online renewal, and offline import.
5. Keep the previous public key published and trusted through the maximum old lease, offline, and grace deadline. Remove it only after issued-lease evidence shows no accepted lease can still require it.

Campus authorization never fetches the key endpoint synchronously. Keyring changes are deployment configuration applied before the signer switch.

Plans do not contain one global price. Add provider price mappings per currency in the owner portal. The core stores explicit currency exponents and integer minor units, and keeps original, settlement, fee, and exchange-rate evidence separate.
