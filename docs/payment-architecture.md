# Payment architecture

This file is the source of truth for billing and currency decisions in the Campus Pilot control plane.

## Boundaries

- The billing core owns plans, price mappings, checkout attempts, subscriptions, transactions, payment-event idempotency, entitlements, and audit.
- A provider adapter owns provider authentication, API requests, webhook verification, and translation into core events.
- Provider payloads and identifiers must not shape the core schema. Adding PayPal, Paynow, Pesepay, or another provider must not require replacing Stripe-named columns.
- A redirect or browser callback never grants access. Only a verified, idempotently processed provider event or an audited owner grant may change subscription state.

## Commercial model

- A `plan` defines modules, features, limits, trial policy, and lifecycle state.
- A `plan_price` maps one plan to one provider, currency, amount, billing interval, and external provider price identifier.
- One plan can have several active price mappings, including several currencies and several providers.
- A `billing_customer` maps a Campus Pilot customer account to a provider customer identifier.
- A `subscription` snapshots the plan price, provider, billing currency, exponent, and minor-unit amount used for that contract.
- A `payment_transaction` records a charge, refund, or adjustment independently from subscription state.

## Money

Every money value uses:

```json
{
  "currency": "ZWG",
  "currency_exponent": 2,
  "amount_minor": 12550
}
```

- Currency is an uppercase three-letter ISO 4217 code.
- Amounts are signed-safe integers at the application boundary; prices and provider amounts are non-negative minor units.
- The exponent is explicit and ranges from zero to four. Code must never assume every currency has two decimal places.
- Floating-point values are never authoritative money values.
- The checkout quote, subscription billing amount, original transaction, settlement amount, and provider fee remain separate records.
- When a provider converts currency, preserve the original and settlement money, the fee money, and the provider-reported exchange rate string. Never silently convert or infer a rate.
- Refunds are separate transactions linked to the original transaction; `kind` determines direction, so amounts remain non-negative.

## Adapter contract

An adapter may expose checkout, recurring subscriptions, billing-portal access, and verified webhooks. It must normalize provider events into these core concepts:

- checkout completed;
- subscription changed;
- invoice or payment succeeded/failed;
- refund or adjustment recorded;
- event ignored.

The core then resolves accounts and price mappings, applies subscription state, stores currency-aware transactions, and writes audit events. Unknown adapters and unconfigured adapters cannot publish active checkout options.

Current registry:

- Stripe: adapter available; configuration remains secret-managed.
- PayPal: planned adapter.
- Paynow Zimbabwe: planned adapter.
- Pesepay: planned adapter.

The registry describes implementation state only. It must not claim that a provider is configured or operational until live credentials and an end-to-end webhook test have passed.

## Reporting rules

- Revenue reports group by original currency unless a settlement-currency view is explicitly selected.
- Totals from different currencies must never be added together without an explicit conversion policy and dated rate source.
- Owner screens show provider, original money, settlement money when supplied, status, and event-processing state.
- Customer screens show only available price mappings and the provider used by their subscription.
