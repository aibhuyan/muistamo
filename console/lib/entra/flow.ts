import "server-only";

import { request as httpsRequest } from "node:https";

import * as oidc from "openid-client";

import { checkAccessToken, checkIdToken, issuerOf, SignInError } from "./claims";
import { type EntraConfig, entraConfig, type TenantConfig } from "./config";
import { seal, unseal } from "./seal";

// HUMAN REVIEW REQUIRED (AGENTS.md): token handling. OpenID Connect authorization code flow with
// PKCE (S256), state and nonce, against exactly the tenant's own Entra directory (tenant-specific
// v2.0 discovery, never /common). openid-client validates the ID token; claims.ts decides who it
// is. The transaction (state, nonce, verifier, tenant) lives in its own sealed cookie for ten
// minutes and is used once.

export const TXN_TTL_MS = 10 * 60 * 1000;
export const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
export const REFRESH_BEFORE_MS = 5 * 60 * 1000;

export type Session = {
  sid: string;
  tenant: string;
  cid: string;
  person: string;
  name: string;
  at: string;
  atExp: number;
  rt: string;
  ends: number; // absolute end of the session (ms), never extended by a refresh
};

const configs = new Map<string, Promise<oidc.Configuration>>();

// Test use only: a fetch that connects to the e2e fake while still verifying the real hostname
// against the fake's throwaway CA (deploy/dev/e2e). Allowed only for a loopback console.
function e2eFetch(fake: NonNullable<EntraConfig["e2eMicrosoft"]>): oidc.CustomFetch {
  const [host, port] = [fake.address.slice(0, fake.address.lastIndexOf(":")), fake.address.slice(fake.address.lastIndexOf(":") + 1)];
  return (url, options) =>
    new Promise((resolve, reject) => {
      const target = new URL(url);
      const headers = new Headers(options.headers);
      const body = options.body ? Buffer.from(typeof options.body === "string" ? options.body : String(options.body)) : null;
      if (body) headers.set("content-length", String(body.length));
      const req = httpsRequest(
        {
          host,
          port: Number(port),
          servername: target.hostname,
          ca: fake.ca,
          method: options.method,
          path: target.pathname + target.search,
          headers: { ...Object.fromEntries(headers), host: target.hostname },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            const out = new Headers();
            for (const [k, v] of Object.entries(res.headers)) if (typeof v === "string") out.set(k, v);
            resolve(new Response(Buffer.concat(chunks), { status: res.statusCode ?? 500, headers: out }));
          });
        },
      );
      req.on("error", reject);
      if (body) req.write(body);
      req.end();
    });
}

export function oidcConfig(t: TenantConfig): Promise<oidc.Configuration> {
  let found = configs.get(t.tenant);
  if (!found) {
    const config = entraConfig();
    const options: oidc.DiscoveryRequestOptions = {};
    if (config.e2eMicrosoft) options[oidc.customFetch] = e2eFetch(config.e2eMicrosoft);
    found = oidc
      .discovery(new URL(issuerOf(t)), t.clientId, undefined, oidc.ClientSecretPost(t.clientSecret), options)
      .then((c) => {
        if (config.e2eMicrosoft) c[oidc.customFetch] = options[oidc.customFetch]!;
        return c;
      });
    // A failed discovery is not kept: the next sign-in tries again.
    found.catch(() => configs.delete(t.tenant));
    configs.set(t.tenant, found);
  }
  return found;
}

export function redirectUri(): string {
  return new URL("/auth/callback", entraConfig().publicUrl).toString();
}

function scopes(t: TenantConfig): string {
  return `openid profile offline_access ${t.scope}`;
}

// The authorization URL and the sealed transaction to keep in its own cookie.
export async function startSignIn(t: TenantConfig): Promise<{ url: URL; txn: string }> {
  const config = await oidcConfig(t);
  const verifier = oidc.randomPKCECodeVerifier();
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri(),
    response_type: "code",
    response_mode: "query",
    scope: scopes(t),
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });
  const txn = await seal(
    entraConfig().keys,
    "txn",
    { state, nonce, verifier, tenant: t.tenant, cid: t.clientId },
    Date.now() + TXN_TTL_MS,
  );
  return { url, txn };
}

export async function readTransaction(sealed: string | undefined): Promise<Record<string, unknown> | null> {
  return unseal(entraConfig().keys, "txn", sealed);
}

// Redeem the code and decide who signed in. callbackUrl is the public URL the browser was sent to.
export async function finishSignIn(t: TenantConfig, txn: Record<string, unknown>, callbackUrl: URL): Promise<Session> {
  if (txn.tenant !== t.tenant || txn.cid !== t.clientId) throw new SignInError("the sign-in started elsewhere");
  const config = await oidcConfig(t);
  const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
    pkceCodeVerifier: String(txn.verifier),
    expectedState: String(txn.state),
    expectedNonce: String(txn.nonce),
    idTokenExpected: true,
  });
  const claims = tokens.claims();
  if (!claims) throw new SignInError("no ID token");
  const who = checkIdToken(t, claims as Record<string, unknown>);
  if (!tokens.refresh_token) throw new SignInError("no refresh token (offline_access)");
  const atExp = checkAccessToken(t, who.oid, tokens.access_token);
  return {
    sid: oidc.randomState(),
    tenant: t.tenant,
    cid: t.clientId,
    person: who.person,
    name: who.name,
    at: tokens.access_token,
    atExp,
    rt: tokens.refresh_token,
    ends: Date.now() + SESSION_TTL_MS,
  };
}

// A new access token for the same person; the absolute expiry is never extended.
export async function refreshSession(t: TenantConfig, session: Session): Promise<Session> {
  const config = await oidcConfig(t);
  const tokens = await oidc.refreshTokenGrant(config, session.rt, { scope: scopes(t) });
  const oid = session.person.slice("entra:".length);
  const atExp = checkAccessToken(t, oid, tokens.access_token);
  return { ...session, at: tokens.access_token, atExp, rt: tokens.refresh_token ?? session.rt };
}

export async function endSessionUrl(t: TenantConfig): Promise<URL> {
  const config = await oidcConfig(t);
  return oidc.buildEndSessionUrl(config, {
    client_id: t.clientId,
    post_logout_redirect_uri: new URL("/sign-in", entraConfig().publicUrl).toString(),
  });
}

// Whether a refresh failure means the grant is gone (sign in again) rather than a passing error.
export function grantRevoked(error: unknown): boolean {
  if (error instanceof SignInError) return true;
  const code = (error as { error?: unknown })?.error;
  return code === "invalid_grant" || code === "interaction_required" || code === "invalid_client";
}
