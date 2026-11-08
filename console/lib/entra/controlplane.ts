import "server-only";

import { decodeJwt } from "jose";
import * as oidc from "openid-client";

import { SignInError } from "./claims";
import type { TenantConfig } from "./config";
import { REFRESH_BEFORE_MS, type Session, oidcConfig } from "./flow";

// HUMAN REVIEW REQUIRED (AGENTS.md): token handling (docs/control-plane-console-plan.md). The
// control plane accepts only tokens for its own API app, never the blueprint token the knowledge
// service receives. The console asks Entra for one with the session's refresh token and keeps it
// in this process's memory only, per session, never in the cookie and never sent anywhere but
// the control plane.

export const CONTROL_PLANE_SCOPE = "Registry.Console";

const tokens = new Map<string, { at: string; exp: number }>();
const inFlight = new Map<string, Promise<string>>();
const MAX_TOKENS = 10_000;

// The control-plane API app named by the tenant's scope (api://<app>/Registry.Console).
export function controlPlaneApp(scope: string): string | null {
  const m = /^api:\/\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/Registry\.Console$/.exec(scope);
  return m ? m[1] : null;
}

// Same person and directory, issued to this console, for the control-plane API app, with its scope.
export function checkControlPlaneToken(t: TenantConfig, oid: string, token: string): number {
  const app = t.controlPlaneScope ? controlPlaneApp(t.controlPlaneScope) : null;
  if (!app) throw new SignInError("this tenant has no control-plane scope");
  let claims: Record<string, unknown>;
  try {
    claims = decodeJwt(token) as Record<string, unknown>;
  } catch {
    throw new SignInError("the control-plane token is not a token");
  }
  const scopes = typeof claims.scp === "string" ? claims.scp.split(" ") : [];
  if (
    claims.oid !== oid ||
    claims.tid !== t.directory ||
    claims.azp !== t.clientId ||
    claims.aud !== app ||
    claims.ver !== "2.0" ||
    !scopes.includes(CONTROL_PLANE_SCOPE) ||
    typeof claims.exp !== "number"
  ) {
    throw new SignInError("the control-plane token is not this console's token for this person");
  }
  return claims.exp * 1000;
}

// The session's control-plane token, from memory, or asked for again when missing or about to
// expire. One request per session at a time.
export async function controlPlaneToken(t: TenantConfig, session: Session): Promise<string> {
  const kept = tokens.get(session.sid);
  if (kept && kept.exp - Date.now() > REFRESH_BEFORE_MS) return kept.at;
  let pending = inFlight.get(session.sid);
  if (!pending) {
    pending = (async () => {
      if (!t.controlPlaneScope) throw new SignInError("this tenant has no control-plane scope");
      const config = await oidcConfig(t);
      const answer = await oidc.refreshTokenGrant(config, session.rt, { scope: t.controlPlaneScope });
      const exp = checkControlPlaneToken(t, session.person.slice("entra:".length), answer.access_token);
      if (tokens.size >= MAX_TOKENS) tokens.clear(); // bounded: start again rather than grow
      tokens.set(session.sid, { at: answer.access_token, exp });
      return answer.access_token;
    })().finally(() => inFlight.delete(session.sid));
    inFlight.set(session.sid, pending);
  }
  return pending;
}

// Signed out: the session's control-plane token is forgotten in this process.
export function forgetControlPlaneToken(sid: string): void {
  tokens.delete(sid);
}
