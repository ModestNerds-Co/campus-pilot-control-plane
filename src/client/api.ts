/** Shared typed fetch helpers for the control-plane portals. */

export interface SessionResponse {
  authenticated: boolean;
  identity: {
    email: string;
    isOwner: boolean;
    accounts: Array<{ id: string; name: string; role: "admin" | "billing" | "viewer" }>;
  } | null;
}

export interface HealthResponse {
  email_ready: boolean;
  environment: string;
  payments_ready: boolean;
  service: string;
  signing_ready: boolean;
  status: string;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: {
      ...(init?.body ? { "content-type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  const payload = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) throw new Error(payload.error ?? `Request failed with status ${response.status}`);
  return payload;
}

export function post<T>(path: string, body?: unknown): Promise<T> {
  return api<T>(path, { method: "POST", body: JSON.stringify(body ?? {}) });
}

export function patch<T>(path: string, body: unknown): Promise<T> {
  return api<T>(path, { method: "PATCH", body: JSON.stringify(body) });
}
