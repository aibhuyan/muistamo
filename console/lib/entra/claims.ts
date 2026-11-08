import "server-only";

import { decodeJwt } from "jose";

import { KNOWLEDGE_SCOPE, type TenantConfig } from "./config";

// HUMAN REVIEW REQUIRED (AGENTS.md): who a sign-in is. The ID token (validated by openid-client:
// signature or TLS, issuer, audience, nonce, expiry) names the person; it must come from exactly
// the tenant's configured directory, for this console's own app, and from a member of that
// directory (guests are refused in release 1). The access token, which the console never
// verifies itself (the services do), is cross-checked so a mismatch fails here, with a clear
// message, rather than as a 401 later.

export class SignInError extends Error {
  override name = "SignInError";
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type SignedIn = { oid: string; person: string; name: string };

function refuse(message: string): never {
  throw new SignInError(message);
}

export function issuerOf(t: TenantConfig): string {
  return `https://login.microsoftonline.com/${t.directory}/v2.0`;
}

export function checkIdToken(t: TenantConfig, claims: Record<string, unknown>): SignedIn {
  if (claims.iss !== issuerOf(t)) refuse("the sign-in came from another directory");
  if (claims.tid !== t.directory) refuse("the sign-in came from another directory");
  const aud = claims.aud;
  if (!(aud === t.clientId || (Array.isArray(aud) && aud.length === 1 && aud[0] === t.clientId))) {
    refuse("the sign-in was for another app");
  }
  const oid = claims.oid;
  if (typeof oid !== "string" || !UUID.test(oid)) refuse("the sign-in names no user");
  // acct is 0 for a member of the directory and 1 for a guest. It must be configured as an
  // optional ID-token claim (operator step); without it nobody is admitted.
  if (claims.acct !== 0) refuse("only members of your organisation's directory can use the console");
  const name =
    typeof claims.name === "string" && claims.name.trim()
      ? claims.name.trim().slice(0, 100)
      : typeof claims.preferred_username === "string"
        ? claims.preferred_username.slice(0, 100)
        : oid;
  return { oid, person: `entra:${oid}`, name };
}

// The access token the console will send: same person and directory, issued to this console
// (azp), for the blueprint, with the knowledge scope, v2.0.
export function checkAccessToken(t: TenantConfig, oid: string, token: string): number {
  let claims: Record<string, unknown>;
  try {
    claims = decodeJwt(token) as Record<string, unknown>;
  } catch {
    refuse("the access token is not a token");
  }
  if (claims.oid !== oid || claims.tid !== t.directory) refuse("the access token is for another person");
  if (claims.azp !== t.clientId) refuse("the access token was issued to another app");
  if (claims.aud !== t.audience) refuse("the access token is for another resource");
  if (claims.ver !== "2.0") refuse("the access token is not a v2.0 token");
  const scopes = typeof claims.scp === "string" ? claims.scp.split(" ") : [];
  if (!scopes.includes(KNOWLEDGE_SCOPE)) refuse("the access token lacks the knowledge scope");
  if (typeof claims.exp !== "number") refuse("the access token has no expiry");
  return claims.exp * 1000;
}
