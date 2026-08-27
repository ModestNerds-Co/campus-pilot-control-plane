# Portal architecture

Campus Pilot licensing has two separate browser applications backed by one control-plane API and one commercial database.

## Customer portal

- Canonical host: configured by `CUSTOMER_APP_URL`.
- Public routes: `/signup`, `/login`, email verification, and account recovery.
- Authenticated routes: `/portal/*` for plans, subscriptions, payments, installations, activation codes, and account members.
- Identity comes from a customer session and active `account_members` records.
- Signup verifies the email address before creating the school account and its first administrator membership.
- Customer responses never expose owner status, owner navigation, vendor-wide totals, signing internals, or other customers.

## Owner portal

- Canonical host: configured by `OWNER_APP_URL`.
- Public route: `/owner/login` for allowlisted owner email addresses.
- Authenticated routes: `/owner/*` for customers, plans, provider configuration, payments, installations, leases, and vendor audit.
- Owner authentication uses its own magic links, session table, cookie, and CSRF boundary.
- Customer sessions cannot authorize owner endpoints, even when the same email address exists in both identity stores.

## Shared control plane

- One Worker may serve both hosts, but host classification happens before portal routing.
- Customer APIs use `/api/customer/*`; owner APIs use `/api/owner/*`.
- Auth endpoints are split under `/api/customer/auth/*` and `/api/owner/auth/*`.
- Browser mutations require an allowed origin for the portal that owns the session.
- Rerout short links may hide emailed tokens, but the target token remains one-time, short-lived, hashed at rest, and scoped to one portal audience.
- Commercial records remain in D1. Campus operational records never enter this service.

## Signup lifecycle

1. A customer submits contact name, work email, school name, country, and preferred billing currency.
2. The service stores a short-lived pending signup and emails an expiring Rerout verification link.
3. Consuming the link atomically verifies the email, creates the customer identity, school account, and first `admin` membership, then creates a customer session.
4. The customer enters `/portal` in an explicit setup state until a plan and installation are configured.
5. Duplicate, expired, or consumed links return to `/login` with an operational recovery message.

Owner-created customer accounts remain supported for assisted onboarding, but they do not replace public customer signup.
