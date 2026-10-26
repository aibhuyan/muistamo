import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { connection } from "next/server";

// Development-only sign-in. The signed-in person picks any tenant and identity, exactly like the
// services' X-Muistamo-Tenant/X-Muistamo-Actor development headers it is turned into, so the
// cookie needs no signature: it grants nothing the headers do not. Real sign-in (Entra) replaces
// this module. Without MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN=true there is no session at all and the
// console makes no service calls.

export const SESSION_COOKIE = "muistamo_dev_session";

export type Session = { tenant: string; person: string };

const TENANT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PERSON = /^[^\s@<>"]+@[^\s@<>"]+$/;

export function devLoginEnabled(): boolean {
  return process.env.MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN === "true";
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
  // Always at request time: the flag must never be read once at build time and baked into a page.
  await connection();
  if (!devLoginEnabled()) return null;
  const store = await cookies();
  return parseSession(store.get(SESSION_COOKIE)?.value);
}

// For pages and Server Actions: the session, or a redirect to sign in (which itself refuses when
// development sign-in is off).
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

// The only place a session becomes service credentials.
export function serviceHeaders(session: Session): Record<string, string> {
  if (!devLoginEnabled()) throw new Error("development sign-in is disabled");
  return { "X-Muistamo-Tenant": session.tenant, "X-Muistamo-Actor": session.person };
}
