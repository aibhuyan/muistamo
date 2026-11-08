import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { connection } from "next/server";

import { mode, tenantConfig } from "./entra/config";
import { controlPlaneToken } from "./entra/controlplane";
import { readSession } from "./entra/cookies";

// Who is signed in, in one of two exclusive modes (never both; lib/entra/config.ts):
// - Development sign-in: the person picks any tenant and identity, exactly like the services'
//   X-Muistamo-Tenant/X-Muistamo-Actor development headers it is turned into, so the cookie needs
//   no signature: it grants nothing the headers do not. Only with
//   MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN=true.
// - Entra sign-in (MUISTAMO_CONSOLE_TENANTS): OpenID Connect against the tenant's directory; the
//   person's tokens stay in an encrypted cookie that only serviceHeaders reads (lib/entra).
// Without either there is no session at all and the console makes no service calls.

export const SESSION_COOKIE = "muistamo_dev_session";

// What pages may know about the signed-in person. Never a token.
export type Session = { tenant: string; person: string; name?: string };

const TENANT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// Printable ASCII only: the person travels in an HTTP header, which cannot carry anything else.
const PERSON = /^[!#-;=?A-~]+@[!#-;=?A-~]+$/;

let warned = false;

export function devLoginEnabled(): boolean {
  const enabled = mode() === "dev";
  if (enabled && !warned) {
    warned = true;
    // The services warn when they trust development headers; so does the console.
    console.warn(
      JSON.stringify({ level: "WARN", msg: "INSECURE: development sign-in is enabled; anyone can claim any tenant and person" }),
    );
  }
  return enabled;
}

export function entraEnabled(): boolean {
  return mode() === "entra";
}

// Strict: anything but exactly {tenant, person} in the expected shapes is no session.
export function parseSession(raw: string | undefined): Session | null {
  if (!raw) return null;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== "person" || keys[1] !== "tenant") return null;
  const { tenant, person } = value as Record<string, unknown>;
  return validSession(tenant, person);
}

export function validSession(tenant: unknown, person: unknown): Session | null {
  if (typeof tenant !== "string" || typeof person !== "string") return null;
  const t = tenant.trim().toLowerCase();
  const p = person.trim();
  if (!TENANT.test(t) || p.length > 254 || !PERSON.test(p)) return null;
  return { tenant: t, person: p };
}

export async function getSession(): Promise<Session | null> {
  // Always at request time: the mode must never be read once at build time and baked into a page.
  await connection();
  if (entraEnabled()) {
    const s = await readSession(await cookies());
    // An access token past its expiry (the proxy could not renew it) is no session: fail closed.
    if (!s || s.atExp <= Date.now()) return null;
    return { tenant: s.tenant, person: s.person, name: s.name };
  }
  if (!devLoginEnabled()) return null;
  const store = await cookies();
  return parseSession(store.get(SESSION_COOKIE)?.value);
}

// For pages and Server Actions: the session, or a redirect to sign in (which itself refuses when
// no sign-in is configured).
export async function requireSession(): Promise<Session> {
  const session = await getSession();
  if (!session) redirect("/sign-in");
  return session;
}

export async function startSession(session: Session): Promise<void> {
  if (!devLoginEnabled()) throw new Error("development sign-in is disabled");
  const store = await cookies();
  store.set(SESSION_COOKIE, JSON.stringify(session), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 8 * 60 * 60,
  });
}

export async function endSession(): Promise<void> {
  const store = await cookies();
  store.delete(SESSION_COOKIE);
}

export class NotAvailable extends Error {}

// The only place a session becomes service credentials. In Entra mode only the person's bearer
// token is sent, never the development headers; it is read here, from the encrypted cookie, and
// must belong to the same session the page was given. Each service gets only its own token: the
// knowledge service the blueprint's, the control plane its own API app's
// (docs/control-plane-console-plan.md).
export async function serviceHeaders(
  session: Session,
  service: "knowledge" | "control-plane" = "knowledge",
): Promise<Record<string, string>> {
  if (entraEnabled()) {
    const s = await readSession(await cookies());
    if (!s || s.person !== session.person || s.tenant !== session.tenant || s.atExp <= Date.now()) {
      throw new Error("no current Entra session");
    }
    if (service === "knowledge") return { Authorization: `Bearer ${s.at}` };
    const t = tenantConfig(s.tenant);
    if (!t?.controlPlaneScope) throw new NotAvailable("the control plane is not set up for Entra sign-in here");
    return { Authorization: `Bearer ${await controlPlaneToken(t, s)}` };
  }
  if (!devLoginEnabled()) throw new Error("no sign-in is configured");
  return { "X-Muistamo-Tenant": session.tenant, "X-Muistamo-Actor": session.person };
}
