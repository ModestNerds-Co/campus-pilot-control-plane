# Campus Pilot Control Plane Rules

These rules apply to this repository.

## Product boundaries

- This service owns commercial customers, plans, subscriptions, payments, installations, signed leases, revocations, signing keys, and vendor audit.
- Never ingest or store learner, guardian, staff, health, payroll, finance, or other school operational records.
- Campus Pilot verifies leases locally. Do not add a synchronous control-plane dependency to its operational request path.
- A checkout redirect is never proof of payment. Only verified, idempotently processed payment-provider events may change subscription state.
- Read `docs/payment-architecture.md` before changing plans, pricing, payments, subscriptions, currencies, provider adapters, or revenue reporting.
- Keep billing provider-neutral and multi-currency. Store integer minor units with explicit currency exponents; never assume two decimal places or silently convert currencies.
- Never persist signing private keys, activation codes, installation credentials, magic-link tokens, session tokens, payment secrets, or webhook secrets in plaintext.

## Portals and UI

- Keep the customer portal and owner portal visibly and authoritatively separate.
- Use concise operational copy. Do not expose signing, fingerprint, schema, or migration implementation details to customers.
- Forms, confirmations, and secondary workflows use accessible right-side drawers, never centered modals.
- Never invent revenue, customer, payment, or installation data. Use honest loading, empty, error, and setup states.

## Engineering

- `/Users/modestnerd/.codex/skills/ngoni-rust/SKILL.md` is the source of truth for Rust design, implementation, review, and verification in this repository.
- D1 is authoritative for commercial state. KV may be added only as a cache.
- Every mutating endpoint must be authenticated, tenant/account scoped, origin checked where browser-driven, idempotent where externally retried, and audited.
- Verify with `pnpm typecheck`, `pnpm test`, and `pnpm build` before deployment.
- Apply D1 migrations locally and remotely through Wrangler; do not mutate the production schema with ad-hoc SQL.
- Keep secrets in Worker secrets or Secrets Store, never Wrangler vars or committed files.
