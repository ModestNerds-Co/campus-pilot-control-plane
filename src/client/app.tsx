/** Customer and owner portal navigation, screens, and drawer workflows. */

import {
  Activity,
  BadgeDollarSign,
  Building2,
  Check,
  ChevronRight,
  CircleAlert,
  CreditCard,
  Download,
  KeyRound,
  LayoutDashboard,
  Loader2,
  LogOut,
  PackageCheck,
  Plus,
  RefreshCw,
  Server,
  Settings2,
  ShieldCheck,
  Users,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";

import {
  api,
  patch,
  post,
  type HealthResponse,
  type SessionResponse,
} from "./api";
import { Drawer } from "./drawer";
import { formatMoney, parseMajorAmount } from "./money";

type Workspace = "customer" | "owner";
type OwnerPage =
  | "overview"
  | "customers"
  | "plans"
  | "payments"
  | "installations"
  | "leases"
  | "audit";

interface Plan {
  id: string;
  key: string;
  name: string;
  description: string;
  status?: string;
  modules: string[];
  features: string[];
  limits: unknown[];
  trial_days: number;
  sort_order?: number;
}

interface PlanPrice {
  id: string;
  plan_id: string;
  provider: string;
  currency: string;
  currency_exponent: number;
  amount_minor: number;
  billing_interval: "month" | "year";
  external_product_id?: string | null;
  external_price_id?: string;
  status?: string;
}

interface PortalAccount {
  id: string;
  name: string;
  billing_email: string;
  status: string;
  role: string;
  subscription_id: string | null;
  subscription_status: string | null;
  provider: string | null;
  current_period_end: string | null;
  plan_id: string | null;
  plan_name: string | null;
  modules: string[];
}

interface Installation {
  id: string;
  account_id: string;
  name: string;
  status: string;
  credential_hint: string;
  last_seen_at: string | null;
  created_at: string;
  lease_expires_at?: string | null;
  grace_until?: string | null;
  account_name?: string;
  tenant_id?: string;
  deployment_id?: string;
  lease_status?: string | null;
}

interface OwnerAccount extends PortalAccount {
  slug: string;
  plan_name: string | null;
  installation_count: number;
  created_at: string;
}

interface Lease {
  id: string;
  sequence: number;
  status: string;
  catalog_version: string;
  issued_at: string;
  lease_expires_at: string;
  grace_until: string;
  installation_name: string;
  account_name: string;
}

interface AuditEvent {
  id: string;
  actor_type: string;
  actor_id: string | null;
  action: string;
  target_type: string;
  target_id: string | null;
  reason: string | null;
  created_at: string;
  account_name: string | null;
}

interface ProviderCapability {
  key: string;
  display_name: string;
  adapter_status: "available" | "planned";
  configured: boolean;
}

interface PaymentTransaction {
  id: string;
  account_name: string;
  provider: string;
  external_payment_id: string;
  kind: string;
  status: string;
  currency: string;
  currency_exponent: number;
  amount_minor: number;
  settlement_currency: string | null;
  settlement_currency_exponent: number | null;
  settlement_amount_minor: number | null;
  occurred_at: string;
}

interface PaymentEvent {
  id: string;
  provider: string;
  provider_event_id: string;
  event_type: string;
  processing_status: string;
  failure_reason: string | null;
  received_at: string;
}

export function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [workspace, setWorkspace] = useState<Workspace>("customer");
  const [notice, setNotice] = useState<string | null>(null);

  const refreshSession = useCallback(async () => {
    setLoading(true);
    try {
      const [next, nextHealth] = await Promise.all([
        api<SessionResponse>("/api/session"),
        api<HealthResponse>("/api/health"),
      ]);
      setSession(next);
      setHealth(nextHealth);
      if (next.identity?.isOwner && next.identity.accounts.length === 0)
        setWorkspace("owner");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  if (loading)
    return (
      <CenteredState
        icon={<Loader2 className="spin" />}
        title="Loading licensing"
      />
    );
  if (!session?.authenticated || !session.identity)
    return (
      <SignIn
        emailReady={health?.email_ready === true}
        onNotice={setNotice}
        notice={notice}
      />
    );
  return (
    <PortalShell
      identity={session.identity}
      onLogout={async () => {
        await post("/api/auth/logout");
        await refreshSession();
      }}
      onWorkspaceChange={setWorkspace}
      workspace={workspace}
    >
      {workspace === "owner" && session.identity.isOwner ? (
        <OwnerPortal email={session.identity.email} />
      ) : (
        <CustomerPortal email={session.identity.email} />
      )}
    </PortalShell>
  );
}

function SignIn({
  emailReady,
  notice,
  onNotice,
}: {
  emailReady: boolean;
  notice: string | null;
  onNotice: (value: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [pending, setPending] = useState(false);
  const [debugUrl, setDebugUrl] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!emailReady) return;
    setPending(true);
    setDebugUrl(null);
    try {
      const result = await post<{ ok: boolean; debug_url?: string }>(
        "/api/auth/request-link",
        { email },
      );
      onNotice("If that email has access, a sign-in link has been sent.");
      setDebugUrl(result.debug_url ?? null);
    } catch (error) {
      onNotice(message(error));
    } finally {
      setPending(false);
    }
  };
  return (
    <main className="login-shell">
      <section className="login-brand">
        <div className="brand-mark">
          <ShieldCheck />
        </div>
        <div>
          <p className="eyebrow light">Campus Pilot</p>
          <h1>Licensing and billing</h1>
          <p>Manage subscriptions and connect Campus Pilot installations.</p>
        </div>
      </section>
      <section className="login-panel">
        <form className="login-form" onSubmit={submit}>
          <p className="eyebrow">Secure access</p>
          <h2>Sign in</h2>
          <p className="muted">
            {emailReady
              ? "We’ll email you a short-lived sign-in link."
              : "Sign-in email delivery is not configured."}
          </p>
          <label>
            Email address
            <input
              autoComplete="email"
              disabled={!emailReady}
              onChange={(event) => setEmail(event.target.value)}
              required
              type="email"
              value={email}
            />
          </label>
          <button
            className="button primary"
            disabled={pending || !emailReady}
            type="submit"
          >
            {pending ? (
              <>
                <Loader2 className="spin" />
                Sending…
              </>
            ) : (
              "Send sign-in link"
            )}
          </button>
          {notice ? (
            <p className="notice" role="status">
              {notice}
            </p>
          ) : null}
          {debugUrl ? (
            <a className="debug-link" href={debugUrl}>
              Open local sign-in link
            </a>
          ) : null}
        </form>
      </section>
    </main>
  );
}

function PortalShell({
  children,
  identity,
  onLogout,
  onWorkspaceChange,
  workspace,
}: {
  children: ReactNode;
  identity: NonNullable<SessionResponse["identity"]>;
  onLogout: () => void;
  onWorkspaceChange: (workspace: Workspace) => void;
  workspace: Workspace;
}) {
  return (
    <div className="app-shell">
      <aside className="rail">
        <div className="rail-brand">
          <span className="brand-mark small">
            <ShieldCheck />
          </span>
          <div>
            <strong>Campus Pilot</strong>
            <small>Control plane</small>
          </div>
        </div>
        <nav className="rail-nav" aria-label="Workspace">
          <button
            className={workspace === "customer" ? "active" : ""}
            onClick={() => onWorkspaceChange("customer")}
            type="button"
          >
            <Building2 />
            Customer portal
          </button>
          {identity.isOwner ? (
            <button
              className={workspace === "owner" ? "active" : ""}
              onClick={() => onWorkspaceChange("owner")}
              type="button"
            >
              <ShieldCheck />
              Owner portal
            </button>
          ) : null}
        </nav>
        <div className="rail-account">
          <div className="avatar">{initials(identity.email)}</div>
          <div>
            <strong>{identity.email}</strong>
            <small>{identity.isOwner ? "Platform owner" : "Customer"}</small>
          </div>
        </div>
        <button className="rail-signout" onClick={onLogout} type="button">
          <LogOut />
          Sign out
        </button>
      </aside>
      <main className="page">{children}</main>
    </div>
  );
}

function CustomerPortal({ email }: { email: string }) {
  const [accounts, setAccounts] = useState<PortalAccount[]>([]);
  const [installations, setInstallations] = useState<Installation[]>([]);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [prices, setPrices] = useState<PlanPrice[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drawer, setDrawer] = useState<"activation" | "plans" | null>(null);
  const [selectedAccount, setSelectedAccount] = useState<string>("");
  const [activationLabel, setActivationLabel] = useState("");
  const [activationCode, setActivationCode] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [overview, catalog] = await Promise.all([
        api<{ accounts: PortalAccount[]; installations: Installation[] }>(
          "/api/portal/overview",
        ),
        api<{ plans: Plan[]; prices: PlanPrice[] }>("/api/catalog/plans"),
      ]);
      setAccounts(overview.accounts);
      setInstallations(overview.installations);
      setPlans(catalog.plans);
      setPrices(catalog.prices);
      setSelectedAccount(
        (current) => current || overview.accounts[0]?.id || "",
      );
    } catch (loadError) {
      setError(message(loadError));
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  const createActivation = async () => {
    setPending(true);
    try {
      const response = await post<{ activation_code: string }>(
        "/api/portal/activation-codes",
        {
          account_id: selectedAccount,
          label: activationLabel,
        },
      );
      setActivationCode(response.activation_code);
    } catch (activationError) {
      setError(message(activationError));
    } finally {
      setPending(false);
    }
  };

  const checkout = async (planPriceId: string) => {
    setPending(true);
    try {
      const response = await post<{ url: string }>("/api/portal/checkout", {
        account_id: selectedAccount,
        plan_price_id: planPriceId,
        idempotency_key: `checkout-${crypto.randomUUID()}`,
      });
      window.location.assign(response.url);
    } catch (checkoutError) {
      setError(message(checkoutError));
      setPending(false);
    }
  };

  const billing = async (accountId: string, provider: string) => {
    setPending(true);
    try {
      const response = await post<{ url: string }>("/api/portal/billing", {
        account_id: accountId,
        provider,
      });
      window.location.assign(response.url);
    } catch (billingError) {
      setError(message(billingError));
      setPending(false);
    }
  };

  return (
    <div className="page-inner">
      <PageHeader
        eyebrow="Customer portal"
        title="Licensing"
        description={`Signed in as ${email}`}
        actions={
          <>
            <button
              className="button secondary"
              onClick={() => void load()}
              type="button"
            >
              <RefreshCw />
              Refresh
            </button>
            {accounts.length ? (
              <button
                className="button primary"
                onClick={() => {
                  setActivationCode(null);
                  setActivationLabel("");
                  setDrawer("activation");
                }}
                type="button"
              >
                <KeyRound />
                Connect installation
              </button>
            ) : null}
          </>
        }
      />
      {error ? (
        <ErrorBanner message={error} onDismiss={() => setError(null)} />
      ) : null}
      {loading ? (
        <ListSkeleton />
      ) : accounts.length === 0 ? (
        <EmptyState
          icon={<Building2 />}
          title="No customer account"
          description="Ask the platform owner to add this email to a customer account."
        />
      ) : (
        <>
          <section className="section-grid">
            {accounts.map((account) => (
              <article className="account-card" key={account.id}>
                <div className="card-heading">
                  <div>
                    <p className="eyebrow">Customer</p>
                    <h2>{account.name}</h2>
                  </div>
                  <Status
                    value={account.subscription_status ?? "No subscription"}
                  />
                </div>
                <dl className="fact-grid">
                  <Fact
                    label="Plan"
                    value={account.plan_name ?? "Not selected"}
                  />
                  <Fact label="Billing contact" value={account.billing_email} />
                  <Fact
                    label="Renews or ends"
                    value={formatDate(account.current_period_end)}
                  />
                  <Fact
                    label="Modules"
                    value={String(account.modules.length)}
                  />
                </dl>
                <div className="card-actions">
                  <button
                    className="button secondary"
                    disabled={
                      !account.subscription_id ||
                      !account.provider ||
                      account.provider === "manual" ||
                      pending
                    }
                    onClick={() =>
                      account.provider
                        ? void billing(account.id, account.provider)
                        : undefined
                    }
                    type="button"
                  >
                    <CreditCard />
                    Manage billing
                  </button>
                  <button
                    className="button ghost"
                    onClick={() => {
                      setSelectedAccount(account.id);
                      setDrawer("plans");
                    }}
                    type="button"
                  >
                    View plans
                    <ChevronRight />
                  </button>
                </div>
              </article>
            ))}
          </section>
          <Section title="Installations" eyebrow="Connected systems">
            {installations.length === 0 ? (
              <EmptyState
                compact
                icon={<Server />}
                title="No installations connected"
                description="Create an activation code when the Campus Pilot server is ready."
              />
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Customer</th>
                      <th>Status</th>
                      <th>Last contact</th>
                      <th>Lease ends</th>
                      <th aria-label="Actions" />
                    </tr>
                  </thead>
                  <tbody>
                    {installations.map((installation) => (
                      <tr key={installation.id}>
                        <td>
                          <strong>{installation.name}</strong>
                          <small>
                            Credential ending {installation.credential_hint}
                          </small>
                        </td>
                        <td>
                          {accounts.find(
                            (account) => account.id === installation.account_id,
                          )?.name ?? "—"}
                        </td>
                        <td>
                          <Status value={installation.status} />
                        </td>
                        <td>{formatDate(installation.last_seen_at)}</td>
                        <td>{formatDate(installation.lease_expires_at)}</td>
                        <td>
                          <a
                            className="table-action"
                            href={`/api/portal/installations/${installation.id}/license`}
                          >
                            <Download />
                            Offline license
                          </a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
        </>
      )}
      <Drawer
        open={drawer === "activation"}
        onClose={() => setDrawer(null)}
        title={
          activationCode ? "Activation code created" : "Connect installation"
        }
        description="Use this once from the Campus Pilot Administration licensing screen."
        footer={
          <>
            <button
              className="button ghost"
              onClick={() => setDrawer(null)}
              type="button"
            >
              Close
            </button>
            {!activationCode ? (
              <button
                className="button primary"
                disabled={
                  pending ||
                  !selectedAccount ||
                  activationLabel.trim().length < 2
                }
                onClick={() => void createActivation()}
                type="button"
              >
                {pending ? "Creating…" : "Create code"}
              </button>
            ) : null}
          </>
        }
      >
        {!activationCode ? (
          <div className="form-stack">
            <label>
              Customer
              <select
                onChange={(event) => setSelectedAccount(event.target.value)}
                value={selectedAccount}
              >
                {accounts.map((account) => (
                  <option key={account.id} value={account.id}>
                    {account.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Installation label
              <input
                onChange={(event) => setActivationLabel(event.target.value)}
                placeholder="Main campus server"
                value={activationLabel}
              />
            </label>
            <p className="help">
              The code expires after 24 hours and is shown only once.
            </p>
          </div>
        ) : (
          <div className="code-result">
            <p>Copy this code now. It will not be shown again.</p>
            <code>{activationCode}</code>
            <button
              className="button secondary"
              onClick={() => void navigator.clipboard.writeText(activationCode)}
              type="button"
            >
              Copy code
            </button>
          </div>
        )}
      </Drawer>
      <Drawer
        open={drawer === "plans"}
        onClose={() => setDrawer(null)}
        title="Plans"
        description="Choose a plan for this customer."
        footer={
          <button
            className="button ghost"
            onClick={() => setDrawer(null)}
            type="button"
          >
            Close
          </button>
        }
      >
        {plans.length === 0 ? (
          <EmptyState
            compact
            icon={<PackageCheck />}
            title="No plans available"
            description="No purchasable plans are configured."
          />
        ) : (
          <div className="plan-list">
            {plans.map((plan) => {
              const planPrices = prices.filter(
                (price) => price.plan_id === plan.id,
              );
              return (
                <article className="plan-card" key={plan.id}>
                  <div>
                    <p className="eyebrow">{plan.key}</p>
                    <h3>{plan.name}</h3>
                    <p>{plan.description}</p>
                  </div>
                  <ul>
                    {plan.modules.slice(0, 6).map((module) => (
                      <li key={module}>
                        <Check />
                        {humanize(module)}
                      </li>
                    ))}
                    {plan.modules.length > 6 ? (
                      <li>+ {plan.modules.length - 6} more modules</li>
                    ) : null}
                  </ul>
                  {planPrices.length ? (
                    <div className="price-options">
                      {planPrices.map((price) => (
                        <button
                          className="button primary"
                          disabled={pending}
                          key={price.id}
                          onClick={() => void checkout(price.id)}
                          type="button"
                        >
                          <span>
                            {formatMoney(
                              price.amount_minor,
                              price.currency,
                              price.currency_exponent,
                            )}
                          </span>
                          <small>
                            {humanize(price.provider)} ·{" "}
                            {price.billing_interval}
                          </small>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <p className="help">No payment options are active.</p>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </Drawer>
    </div>
  );
}

function OwnerPortal({ email }: { email: string }) {
  const [page, setPage] = useState<OwnerPage>("overview");
  return (
    <div className="owner-layout">
      <nav className="subnav" aria-label="Owner portal">
        <p className="eyebrow">Owner portal</p>
        {(
          [
            ["overview", LayoutDashboard, "Overview"],
            ["customers", Users, "Customers"],
            ["plans", BadgeDollarSign, "Plans"],
            ["payments", CreditCard, "Payments"],
            ["installations", Server, "Installations"],
            ["leases", KeyRound, "Leases"],
            ["audit", Activity, "Audit"],
          ] as const
        ).map(([key, Icon, label]) => (
          <button
            className={page === key ? "active" : ""}
            key={key}
            onClick={() => setPage(key)}
            type="button"
          >
            <Icon />
            {label}
          </button>
        ))}
      </nav>
      <div className="owner-content">
        <OwnerPageView email={email} page={page} />
      </div>
    </div>
  );
}

function OwnerPageView({ email, page }: { email: string; page: OwnerPage }) {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [drawer, setDrawer] = useState<
    "account" | "plan" | "price" | "subscription" | "revoke" | null
  >(null);
  const [selected, setSelected] = useState<any>(null);
  const [pending, setPending] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const endpoint = page === "customers" ? "accounts" : page;
    try {
      setData(await api(`/api/owner/${endpoint}`));
    } catch (loadError) {
      setError(message(loadError));
    } finally {
      setLoading(false);
    }
  }, [page]);
  useEffect(() => {
    void load();
  }, [load]);

  const title = {
    overview: "Overview",
    customers: "Customers",
    plans: "Plans",
    payments: "Payments",
    installations: "Installations",
    leases: "Leases",
    audit: "Audit",
  }[page];
  const actions =
    page === "customers" ? (
      <button
        className="button primary"
        onClick={() => setDrawer("account")}
        type="button"
      >
        <Plus />
        Add customer
      </button>
    ) : (
      <button
        className="button secondary"
        onClick={() => void load()}
        type="button"
      >
        <RefreshCw />
        Refresh
      </button>
    );
  return (
    <div className="page-inner owner-page">
      <PageHeader
        eyebrow="Platform operations"
        title={title}
        description={`Owner access · ${email}`}
        actions={actions}
      />
      {error ? (
        <ErrorBanner message={error} onDismiss={() => setError(null)} />
      ) : null}
      {loading ? (
        <ListSkeleton />
      ) : (
        renderOwnerContent(page, data, {
          editPlan: (plan) => {
            setSelected(plan);
            setDrawer("plan");
          },
          addPrice: (plan) => {
            setSelected(plan);
            setDrawer("price");
          },
          manualSubscription: (account) => {
            setSelected(account);
            setDrawer("subscription");
          },
          revoke: (installation) => {
            setSelected(installation);
            setDrawer("revoke");
          },
        })
      )}
      <AccountDrawer
        open={drawer === "account"}
        pending={pending}
        onClose={() => setDrawer(null)}
        onSubmit={async (body) =>
          runMutation(setPending, setError, async () => {
            await post("/api/owner/accounts", body);
            setDrawer(null);
            await load();
          })
        }
      />
      <PlanDrawer
        open={drawer === "plan"}
        plan={selected as Plan | null}
        pending={pending}
        onClose={() => setDrawer(null)}
        onSubmit={async (body) =>
          runMutation(setPending, setError, async () => {
            await patch(`/api/owner/plans/${selected.id}`, body);
            setDrawer(null);
            await load();
          })
        }
      />
      <PriceDrawer
        open={drawer === "price"}
        plan={selected as Plan | null}
        pending={pending}
        onClose={() => setDrawer(null)}
        onSubmit={async (body) =>
          runMutation(setPending, setError, async () => {
            await post("/api/owner/plan-prices", body);
            setDrawer(null);
            await load();
          })
        }
      />
      <ManualSubscriptionDrawer
        open={drawer === "subscription"}
        account={selected as OwnerAccount | null}
        pending={pending}
        onClose={() => setDrawer(null)}
        onSubmit={async (body) =>
          runMutation(setPending, setError, async () => {
            await post("/api/owner/subscriptions/manual", body);
            setDrawer(null);
            await load();
          })
        }
      />
      <RevokeDrawer
        installation={selected as Installation | null}
        open={drawer === "revoke"}
        pending={pending}
        onClose={() => setDrawer(null)}
        onSubmit={async (reason) =>
          runMutation(setPending, setError, async () => {
            await post(`/api/owner/installations/${selected.id}/revoke`, {
              reason,
            });
            setDrawer(null);
            await load();
          })
        }
      />
    </div>
  );
}

function renderOwnerContent(
  page: OwnerPage,
  data: any,
  actions: {
    editPlan: (plan: Plan) => void;
    addPrice: (plan: Plan) => void;
    manualSubscription: (account: OwnerAccount) => void;
    revoke: (installation: Installation) => void;
  },
) {
  if (page === "overview") {
    const counts = data?.counts ?? {};
    return (
      <>
        <div className="metric-grid">
          <Metric
            label="Customers"
            value={counts.accounts ?? 0}
            icon={<Users />}
          />
          <Metric
            label="Active subscriptions"
            value={counts.active_subscriptions ?? 0}
            icon={<BadgeDollarSign />}
          />
          <Metric
            label="Active installations"
            value={counts.active_installations ?? 0}
            icon={<Server />}
          />
          <Metric
            label="Billing attention"
            value={counts.billing_attention ?? 0}
            icon={<CircleAlert />}
          />
        </div>
        <Section title="Recent activity" eyebrow="Audit">
          <AuditTable events={data?.recent_activity ?? []} />
        </Section>
      </>
    );
  }
  if (page === "customers") {
    const rows: OwnerAccount[] = data?.accounts ?? [];
    return rows.length ? (
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Customer</th>
              <th>Subscription</th>
              <th>Plan</th>
              <th>Installations</th>
              <th>Created</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>
                  <strong>{row.name}</strong>
                  <small>{row.billing_email}</small>
                </td>
                <td>
                  <Status value={row.subscription_status ?? "none"} />
                </td>
                <td>{row.plan_name ?? "—"}</td>
                <td>{row.installation_count}</td>
                <td>{formatDate(row.created_at)}</td>
                <td>
                  <button
                    className="table-action"
                    onClick={() => actions.manualSubscription(row)}
                    type="button"
                  >
                    Grant subscription
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <EmptyState
        icon={<Users />}
        title="No customers"
        description="Add the first customer when you are ready to issue access."
      />
    );
  }
  if (page === "plans") {
    const rows: Plan[] = data?.plans ?? [];
    const prices: PlanPrice[] = data?.prices ?? [];
    return (
      <div className="section-grid">
        {rows.map((plan) => {
          const planPrices = prices.filter(
            (price) => price.plan_id === plan.id,
          );
          return (
            <article className="account-card" key={plan.id}>
              <div className="card-heading">
                <div>
                  <p className="eyebrow">{plan.key}</p>
                  <h2>{plan.name}</h2>
                </div>
                <Status value={plan.status ?? "draft"} />
              </div>
              <p className="muted">{plan.description || "No description."}</p>
              <dl className="fact-grid">
                <Fact
                  label="Payment options"
                  value={String(planPrices.length)}
                />
                <Fact label="Modules" value={String(plan.modules.length)} />
                <Fact label="Trial" value={`${plan.trial_days} days`} />
              </dl>
              {planPrices.length ? (
                <div className="price-summary">
                  {planPrices.map((price) => (
                    <span key={price.id}>
                      {formatMoney(
                        price.amount_minor,
                        price.currency,
                        price.currency_exponent,
                      )}{" "}
                      / {price.billing_interval} · {humanize(price.provider)} ·{" "}
                      {price.status}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="help">No provider prices configured.</p>
              )}
              <div className="card-actions">
                <button
                  className="button secondary"
                  onClick={() => actions.editPlan(plan)}
                  type="button"
                >
                  <Settings2 />
                  Edit plan
                </button>
                <button
                  className="button ghost"
                  onClick={() => actions.addPrice(plan)}
                  type="button"
                >
                  <Plus />
                  Add payment option
                </button>
              </div>
            </article>
          );
        })}
      </div>
    );
  }
  if (page === "payments") {
    const providers: ProviderCapability[] = data?.providers ?? [];
    const transactions: PaymentTransaction[] = data?.transactions ?? [];
    const events: PaymentEvent[] = data?.events ?? [];
    return (
      <>
        <div className="provider-grid">
          {providers.map((provider) => (
            <article className="provider-card" key={provider.key}>
              <div>
                <strong>{provider.display_name}</strong>
                <small>{provider.key}</small>
              </div>
              <Status
                value={
                  provider.adapter_status === "planned"
                    ? "planned"
                    : provider.configured
                      ? "configured"
                      : "setup required"
                }
              />
            </article>
          ))}
        </div>
        <Section eyebrow="Commercial records" title="Transactions">
          {transactions.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Customer</th>
                    <th>Provider</th>
                    <th>Amount</th>
                    <th>Settlement</th>
                    <th>Status</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {transactions.map((transaction) => (
                    <tr key={transaction.id}>
                      <td>
                        <strong>{transaction.account_name}</strong>
                        <small>{transaction.external_payment_id}</small>
                      </td>
                      <td>
                        {humanize(transaction.provider)}
                        <small>{humanize(transaction.kind)}</small>
                      </td>
                      <td>
                        {formatMoney(
                          transaction.amount_minor,
                          transaction.currency,
                          transaction.currency_exponent,
                        )}
                      </td>
                      <td>
                        {transaction.settlement_currency &&
                        transaction.settlement_currency_exponent !== null &&
                        transaction.settlement_amount_minor !== null
                          ? formatMoney(
                              transaction.settlement_amount_minor,
                              transaction.settlement_currency,
                              transaction.settlement_currency_exponent,
                            )
                          : "—"}
                      </td>
                      <td>
                        <Status value={transaction.status} />
                      </td>
                      <td>{formatDateTime(transaction.occurred_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              compact
              icon={<CreditCard />}
              title="No payment transactions"
              description="Verified provider payments and refunds will appear here."
            />
          )}
        </Section>
        <Section eyebrow="Provider delivery" title="Webhook events">
          {events.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Provider</th>
                    <th>Event</th>
                    <th>Status</th>
                    <th>Received</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr key={event.id}>
                      <td>{humanize(event.provider)}</td>
                      <td>
                        <strong>{event.event_type}</strong>
                        <small>
                          {event.failure_reason ?? event.provider_event_id}
                        </small>
                      </td>
                      <td>
                        <Status value={event.processing_status} />
                      </td>
                      <td>{formatDateTime(event.received_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              compact
              icon={<Activity />}
              title="No provider events"
              description="Verified webhook deliveries will appear here."
            />
          )}
        </Section>
      </>
    );
  }
  if (page === "installations") {
    const rows: Installation[] = data?.installations ?? [];
    return rows.length ? (
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Installation</th>
              <th>Customer</th>
              <th>Status</th>
              <th>Last contact</th>
              <th>Lease ends</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>
                  <strong>{row.name}</strong>
                  <small>{row.deployment_id}</small>
                </td>
                <td>{row.account_name}</td>
                <td>
                  <Status value={row.status} />
                </td>
                <td>{formatDate(row.last_seen_at)}</td>
                <td>{formatDate(row.lease_expires_at)}</td>
                <td>
                  {row.status === "active" ? (
                    <button
                      className="table-action danger"
                      onClick={() => actions.revoke(row)}
                      type="button"
                    >
                      Revoke
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <EmptyState
        icon={<Server />}
        title="No installations"
        description="Connected campus servers will appear here."
      />
    );
  }
  if (page === "leases") {
    const rows: Lease[] = data?.leases ?? [];
    return rows.length ? (
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Installation</th>
              <th>Customer</th>
              <th>Sequence</th>
              <th>Status</th>
              <th>Issued</th>
              <th>Active until</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.installation_name}</td>
                <td>{row.account_name}</td>
                <td>{row.sequence}</td>
                <td>
                  <Status value={row.status} />
                </td>
                <td>{formatDate(row.issued_at)}</td>
                <td>{formatDate(row.lease_expires_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <EmptyState
        icon={<KeyRound />}
        title="No leases"
        description="Issued signed leases will appear here."
      />
    );
  }
  return <AuditTable events={data?.events ?? []} />;
}

function AccountDrawer({
  open,
  pending,
  onClose,
  onSubmit,
}: {
  open: boolean;
  pending: boolean;
  onClose: () => void;
  onSubmit: (body: unknown) => void;
}) {
  const [name, setName] = useState("");
  const [billingEmail, setBillingEmail] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Add customer"
      description="Create the commercial account and its first customer administrator."
      footer={
        <>
          <button className="button ghost" onClick={onClose} type="button">
            Cancel
          </button>
          <button
            className="button primary"
            disabled={pending || !name || !billingEmail || !memberEmail}
            onClick={() =>
              onSubmit({
                name,
                billing_email: billingEmail,
                member_email: memberEmail,
              })
            }
            type="button"
          >
            {pending ? "Creating…" : "Add customer"}
          </button>
        </>
      }
    >
      <div className="form-stack">
        <label>
          Customer name
          <input
            onChange={(event) => setName(event.target.value)}
            value={name}
          />
        </label>
        <label>
          Billing email
          <input
            onChange={(event) => setBillingEmail(event.target.value)}
            type="email"
            value={billingEmail}
          />
        </label>
        <label>
          Customer administrator email
          <input
            onChange={(event) => setMemberEmail(event.target.value)}
            type="email"
            value={memberEmail}
          />
        </label>
      </div>
    </Drawer>
  );
}

function PlanDrawer({
  open,
  plan,
  pending,
  onClose,
  onSubmit,
}: {
  open: boolean;
  plan: Plan | null;
  pending: boolean;
  onClose: () => void;
  onSubmit: (body: unknown) => void;
}) {
  const [form, setForm] = useState<Record<string, string>>({});
  useEffect(() => {
    if (open && plan) {
      setForm({
        name: plan.name,
        description: plan.description,
        status: plan.status ?? "draft",
        modules: plan.modules.join(", "),
        trial_days: String(plan.trial_days),
        sort_order: String(plan.sort_order ?? 0),
      });
    }
  }, [open, plan]);
  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={`Edit ${plan?.name ?? "plan"}`}
      description="Plans define entitlements. Add provider and currency prices separately."
      footer={
        <>
          <button className="button ghost" onClick={onClose} type="button">
            Cancel
          </button>
          <button
            className="button primary"
            disabled={pending}
            onClick={() =>
              onSubmit({
                ...form,
                trial_days: Number(form.trial_days),
                sort_order: Number(form.sort_order),
                modules: form.modules
                  .split(",")
                  .map((value) => value.trim())
                  .filter(Boolean),
              })
            }
            type="button"
          >
            {pending ? "Saving…" : "Save plan"}
          </button>
        </>
      }
    >
      <div className="form-stack">
        <label>
          Name
          <input
            value={form.name ?? ""}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
          />
        </label>
        <label>
          Description
          <textarea
            value={form.description ?? ""}
            onChange={(event) =>
              setForm({ ...form, description: event.target.value })
            }
          />
        </label>
        <label>
          Status
          <select
            value={form.status ?? "draft"}
            onChange={(event) =>
              setForm({ ...form, status: event.target.value })
            }
          >
            <option value="draft">Draft</option>
            <option value="active">Active</option>
            <option value="retired">Retired</option>
          </select>
        </label>
        <label>
          Module keys
          <textarea
            value={form.modules ?? ""}
            onChange={(event) =>
              setForm({ ...form, modules: event.target.value })
            }
          />
        </label>
        <div className="form-row">
          <label>
            Trial days
            <input
              min="0"
              type="number"
              value={form.trial_days ?? "0"}
              onChange={(event) =>
                setForm({ ...form, trial_days: event.target.value })
              }
            />
          </label>
          <label>
            Sort order
            <input
              type="number"
              value={form.sort_order ?? "0"}
              onChange={(event) =>
                setForm({ ...form, sort_order: event.target.value })
              }
            />
          </label>
        </div>
      </div>
    </Drawer>
  );
}

function PriceDrawer({
  open,
  plan,
  pending,
  onClose,
  onSubmit,
}: {
  open: boolean;
  plan: Plan | null;
  pending: boolean;
  onClose: () => void;
  onSubmit: (body: unknown) => void;
}) {
  const [provider, setProvider] = useState("stripe");
  const [currency, setCurrency] = useState("USD");
  const [currencyExponent, setCurrencyExponent] = useState("2");
  const [amount, setAmount] = useState("");
  const [billingInterval, setBillingInterval] = useState("month");
  const [externalProductId, setExternalProductId] = useState("");
  const [externalPriceId, setExternalPriceId] = useState("");
  const [status, setStatus] = useState("draft");
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setProvider("stripe");
    setCurrency("USD");
    setCurrencyExponent("2");
    setAmount("");
    setBillingInterval("month");
    setExternalProductId("");
    setExternalPriceId("");
    setStatus("draft");
    setValidationError(null);
  }, [open, plan?.id]);

  const submit = () => {
    try {
      const exponent = Number(currencyExponent);
      const amountMinor = parseMajorAmount(amount, exponent);
      setValidationError(null);
      onSubmit({
        plan_id: plan?.id,
        provider: provider.trim().toLowerCase(),
        currency: currency.trim().toUpperCase(),
        currency_exponent: exponent,
        amount_minor: amountMinor,
        billing_interval: billingInterval,
        external_product_id: externalProductId.trim() || null,
        external_price_id: externalPriceId.trim(),
        status,
      });
    } catch (error) {
      setValidationError(message(error));
    }
  };

  let preview: string | null = null;
  try {
    preview = amount
      ? formatMoney(
          parseMajorAmount(amount, Number(currencyExponent)),
          currency.trim().toUpperCase(),
          Number(currencyExponent),
        )
      : null;
  } catch {
    preview = null;
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={`Add payment option${plan ? ` · ${plan.name}` : ""}`}
      description="Map this plan to a provider price in one currency."
      footer={
        <>
          <button className="button ghost" onClick={onClose} type="button">
            Cancel
          </button>
          <button
            className="button primary"
            disabled={
              pending ||
              !plan ||
              !provider.trim() ||
              currency.trim().length !== 3 ||
              !amount ||
              !externalPriceId.trim()
            }
            onClick={submit}
            type="button"
          >
            {pending ? "Adding…" : "Add payment option"}
          </button>
        </>
      }
    >
      <div className="form-stack">
        <label>
          Payment provider
          <input
            list="payment-provider-options"
            value={provider}
            onChange={(event) => setProvider(event.target.value)}
          />
          <datalist id="payment-provider-options">
            <option value="stripe" />
            <option value="paypal" />
            <option value="paynow" />
            <option value="pesepay" />
          </datalist>
        </label>
        <div className="form-row">
          <label>
            Currency code
            <input
              autoCapitalize="characters"
              maxLength={3}
              value={currency}
              onChange={(event) =>
                setCurrency(event.target.value.toUpperCase())
              }
            />
          </label>
          <label>
            Decimal places
            <input
              max="4"
              min="0"
              type="number"
              value={currencyExponent}
              onChange={(event) => setCurrencyExponent(event.target.value)}
            />
          </label>
        </div>
        <label>
          Price in major units
          <input
            inputMode="decimal"
            placeholder={Number(currencyExponent) === 0 ? "1250" : "1250.00"}
            value={amount}
            onChange={(event) => setAmount(event.target.value)}
          />
          {preview ? (
            <small className="field-preview">
              Stored and displayed as {preview}
            </small>
          ) : null}
        </label>
        <label>
          Billing interval
          <select
            value={billingInterval}
            onChange={(event) => setBillingInterval(event.target.value)}
          >
            <option value="month">Monthly</option>
            <option value="year">Yearly</option>
          </select>
        </label>
        <label>
          Provider product ID <span className="optional">Optional</span>
          <input
            value={externalProductId}
            onChange={(event) => setExternalProductId(event.target.value)}
          />
        </label>
        <label>
          Provider price ID
          <input
            required
            value={externalPriceId}
            onChange={(event) => setExternalPriceId(event.target.value)}
          />
        </label>
        <label>
          Status
          <select
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          >
            <option value="draft">Draft</option>
            <option value="active">Active</option>
            <option value="retired">Retired</option>
          </select>
        </label>
        {validationError ? (
          <p className="form-error" role="alert">
            {validationError}
          </p>
        ) : null}
        <p className="help">Set the amount and currency customers will be charged.</p>
      </div>
    </Drawer>
  );
}

function ManualSubscriptionDrawer({
  open,
  account,
  pending,
  onClose,
  onSubmit,
}: {
  open: boolean;
  account: OwnerAccount | null;
  pending: boolean;
  onClose: () => void;
  onSubmit: (body: unknown) => void;
}) {
  const [plans, setPlans] = useState<Plan[]>([]);
  const [planId, setPlanId] = useState("");
  const [end, setEnd] = useState("");
  useEffect(() => {
    if (!open) return;
    void api<{ plans: Plan[] }>("/api/owner/plans").then((result) => {
      setPlans(result.plans);
      setPlanId(result.plans[0]?.id ?? "");
    });
    const date = new Date();
    date.setFullYear(date.getFullYear() + 1);
    setEnd(date.toISOString().slice(0, 10));
  }, [open]);
  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Grant manual subscription"
      description={`Create an off-platform entitlement for ${account?.name ?? "this customer"}.`}
      footer={
        <>
          <button className="button ghost" onClick={onClose} type="button">
            Cancel
          </button>
          <button
            className="button primary"
            disabled={pending || !planId || !end}
            onClick={() =>
              onSubmit({
                account_id: account?.id,
                plan_id: planId,
                current_period_end: new Date(`${end}T23:59:59Z`).toISOString(),
              })
            }
            type="button"
          >
            {pending ? "Granting…" : "Grant subscription"}
          </button>
        </>
      }
    >
      <div className="form-stack">
        <label>
          Plan
          <select
            value={planId}
            onChange={(event) => setPlanId(event.target.value)}
          >
            {plans.map((plan) => (
              <option key={plan.id} value={plan.id}>
                {plan.name} · {plan.status}
              </option>
            ))}
          </select>
        </label>
        <label>
          End date
          <input
            type="date"
            value={end}
            onChange={(event) => setEnd(event.target.value)}
          />
        </label>
        <p className="help">
          Use this for invoice, bank transfer, cash, controlled trials, or
          another off-platform agreement. The action is audited.
        </p>
      </div>
    </Drawer>
  );
}

function RevokeDrawer({
  installation,
  open,
  pending,
  onClose,
  onSubmit,
}: {
  installation: Installation | null;
  open: boolean;
  pending: boolean;
  onClose: () => void;
  onSubmit: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Revoke installation"
      description={`${installation?.name ?? "This installation"} will stop receiving renewed leases.`}
      footer={
        <>
          <button className="button ghost" onClick={onClose} type="button">
            Keep active
          </button>
          <button
            className="button danger"
            disabled={pending || reason.trim().length < 3}
            onClick={() => onSubmit(reason)}
            type="button"
          >
            {pending ? "Revoking…" : "Revoke installation"}
          </button>
        </>
      }
    >
      <div className="form-stack">
        <label>
          Reason
          <textarea
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        <p className="help">
          The existing offline lease remains valid only until its signed
          deadline.
        </p>
      </div>
    </Drawer>
  );
}

function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}
function Section({
  children,
  eyebrow,
  title,
}: {
  children: ReactNode;
  eyebrow: string;
  title: string;
}) {
  return (
    <section className="section">
      <div className="section-heading">
        <p className="eyebrow">{eyebrow}</p>
        <h2>{title}</h2>
      </div>
      {children}
    </section>
  );
}
function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}
function Metric({
  icon,
  label,
  value,
}: {
  icon: ReactNode;
  label: string;
  value: number;
}) {
  return (
    <article className="metric">
      <span>{icon}</span>
      <div>
        <strong>{value}</strong>
        <small>{label}</small>
      </div>
    </article>
  );
}
function Status({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const tone = ["active", "trialing", "enabled", "processed"].includes(
    normalized,
  )
    ? "good"
    : ["past_due", "unpaid", "failed", "revoked", "suspended"].includes(
          normalized,
        )
      ? "bad"
      : "neutral";
  return (
    <span className={`status ${tone}`}>
      <i />
      {humanize(value)}
    </span>
  );
}
function ErrorBanner({
  message,
  onDismiss,
}: {
  message: string;
  onDismiss: () => void;
}) {
  return (
    <div className="error-banner" role="alert">
      <CircleAlert />
      <div>
        <strong>Action could not be completed</strong>
        <p>{message}</p>
      </div>
      <button aria-label="Dismiss" onClick={onDismiss} type="button">
        ×
      </button>
    </div>
  );
}
function EmptyState({
  compact = false,
  description,
  icon,
  title,
}: {
  compact?: boolean;
  description: string;
  icon: ReactNode;
  title: string;
}) {
  return (
    <div className={`empty ${compact ? "compact" : ""}`}>
      <span>{icon}</span>
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}
function CenteredState({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <main className="centered-state">
      {icon}
      <p>{title}</p>
    </main>
  );
}
function ListSkeleton() {
  return (
    <div className="skeleton-list">
      <div />
      <div />
      <div />
    </div>
  );
}
function AuditTable({ events }: { events: AuditEvent[] }) {
  return events.length ? (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Action</th>
            <th>Customer</th>
            <th>Actor</th>
            <th>Target</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>
                <strong>{humanize(event.action)}</strong>
                {event.reason ? <small>{event.reason}</small> : null}
              </td>
              <td>{event.account_name ?? "Platform"}</td>
              <td>
                {humanize(event.actor_type)}
                <small>{event.actor_id ?? "—"}</small>
              </td>
              <td>{humanize(event.target_type)}</td>
              <td>{formatDateTime(event.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <EmptyState
      icon={<Activity />}
      title="No audit events"
      description="No account, payment, or license activity recorded."
    />
  );
}

async function runMutation(
  setPending: (value: boolean) => void,
  setError: (value: string | null) => void,
  action: () => Promise<void>,
) {
  setPending(true);
  setError(null);
  try {
    await action();
  } catch (error) {
    setError(message(error));
  } finally {
    setPending(false);
  }
}
function message(error: unknown) {
  return error instanceof Error
    ? error.message
    : "The action could not be completed";
}
function initials(email: string) {
  return (
    email
      .split("@")[0]
      .split(/[._-]/)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase())
      .join("") || "CP"
  );
}
function humanize(value: string) {
  return value
    .replaceAll(/[._]/g, " ")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}
function formatDate(value?: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(
    new Date(value),
  );
}
function formatDateTime(value?: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}
