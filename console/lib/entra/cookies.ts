import "server-only";

import { entraConfig, tenantConfig } from "./config";
import type { Session } from "./flow";
import { MAX_CHUNKS, chunk, cookieName, joinChunks, seal, unseal } from "./seal";

// HUMAN REVIEW REQUIRED (AGENTS.md): token handling. The session's tokens live only in this
// encrypted, httpOnly, Secure, SameSite=Strict cookie (chunked); nothing else in the console ever
// reads them but serviceHeaders. The sign-in transaction has its own cookie, Lax because the
// callback is a top-level navigation from Entra, and is deleted on its first use.

export const SESSION_COOKIE = "__Host-muistamo_session";
export const TXN_COOKIE = "__Host-muistamo_oidc";

// The subset of Next's request and response cookie APIs these helpers use.
export type CookieStore = {
  get(name: string): { value: string } | undefined;
  set(name: string, value: string, options: Record<string, unknown>): unknown;
  delete(name: string): unknown;
};

const base = { httpOnly: true, secure: true, path: "/" } as const;

function isSession(v: Record<string, unknown>): boolean {
  return (
    typeof v.sid === "string" &&
    typeof v.tenant === "string" &&
    typeof v.cid === "string" &&
    typeof v.person === "string" &&
    v.person.startsWith("entra:") &&
    typeof v.name === "string" &&
    typeof v.at === "string" &&
    typeof v.atExp === "number" &&
    typeof v.rt === "string" &&
    typeof v.ends === "number"
  );
}

// The session, or null: missing, tampered, expired, or for a tenant (or client app) this console
// no longer has configured. A removed tenant or a rotated app takes effect at once.
export async function readSession(store: CookieStore): Promise<Session | null> {
  const sealed = joinChunks(SESSION_COOKIE, (name) => store.get(name)?.value);
  const claims = await unseal(entraConfig().keys, "session", sealed);
  if (!claims || !isSession(claims)) return null;
  // Only the session's own fields: never the cookie's JWT claims (exp, iat, iss, pur).
  const c = claims as unknown as Session;
  const s: Session = {
    sid: c.sid,
    tenant: c.tenant,
    cid: c.cid,
    person: c.person,
    name: c.name,
    at: c.at,
    atExp: c.atExp,
    rt: c.rt,
    ends: c.ends,
  };
  const t = tenantConfig(s.tenant);
  if (!t || t.clientId !== s.cid || s.ends <= Date.now()) return null;
  return s;
}

export async function writeSession(store: CookieStore, session: Session): Promise<boolean> {
  const sealed = await seal(entraConfig().keys, "session", session as unknown as Record<string, unknown>, session.ends);
  const parts = chunk(sealed);
  if (!parts) return false; // too large for cookies: refuse rather than truncate
  const maxAge = Math.max(0, Math.floor((session.ends - Date.now()) / 1000));
  parts.forEach((part, i) => store.set(cookieName(SESSION_COOKIE, i), part, { ...base, sameSite: "strict", maxAge }));
  // Every write replaces every part: a browser may hold more parts of an older, larger session.
  for (let i = parts.length; i <= MAX_CHUNKS; i++) remove(store, cookieName(SESSION_COOKIE, i), "strict");
  return true;
}

// Browsers ignore a Set-Cookie for a __Host- name unless it is Secure with Path=/, a deletion
// included: Next's delete() sends neither, so a removal is an expired set with the same attributes.
function remove(store: CookieStore, name: string, sameSite: "strict" | "lax"): void {
  store.set(name, "", { ...base, sameSite, maxAge: 0, expires: new Date(0) });
}

export function clearSession(store: CookieStore): void {
  // Unconditionally: on a response store nothing is known yet, but the browser holds the parts.
  for (let i = 0; i <= MAX_CHUNKS; i++) remove(store, cookieName(SESSION_COOKIE, i), "strict");
}

export function writeTransaction(store: CookieStore, sealed: string): void {
  store.set(TXN_COOKIE, sealed, { ...base, sameSite: "lax", maxAge: 600 });
}

export function clearTransaction(store: CookieStore): void {
  remove(store, TXN_COOKIE, "lax");
}
