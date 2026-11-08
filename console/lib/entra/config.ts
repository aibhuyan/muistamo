import "server-only";

import { readFileSync } from "node:fs";

// HUMAN REVIEW REQUIRED (AGENTS.md): token handling and sign-in configuration
// (docs/console-entra-signin-plan.md). Everything here fails closed: a configuration that is not
// exactly right is refused at startup (instrumentation.ts) and again on every use.

export type TenantConfig = {
  tenant: string; // the Muistamo tenant
  name: string; // shown on the sign-in page
  directory: string; // the customer's Entra directory (tenant) id
  clientId: string; // the console's own app registration in that directory
  audience: string; // the blueprint app the knowledge service accepts tokens for
  scope: string; // the full delegated scope, e.g. api://<blueprint>/Knowledge.Read
  // The control plane's own API app scope, api://<api app>/Registry.Console; without it the
  // console makes no control-plane call under Entra sign-in.
  controlPlaneScope?: string;
  clientSecret: string;
};

export type SessionKey = { id: string; key: Uint8Array };

export type Mode = "dev" | "entra" | "none";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY_ID = /^[A-Za-z0-9_-]{1,32}$/;
export const KNOWLEDGE_SCOPE = "Knowledge.Read";

export class ConfigError extends Error {}

function fail(message: string): never {
  throw new ConfigError(message);
}

// Which sign-in this console runs: development headers, Entra, or none. Never both.
export function mode(env: NodeJS.ProcessEnv = process.env): Mode {
  const dev = env.MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN === "true";
  const entra = Boolean(env.MUISTAMO_CONSOLE_TENANTS);
  if (dev && entra) fail("development sign-in and Entra sign-in are both configured; choose one");
  return dev ? "dev" : entra ? "entra" : "none";
}

function uuid(value: unknown, what: string): string {
  if (typeof value !== "string" || !UUID.test(value)) fail(`${what} must be a lower-case UUID`);
  return value;
}

function text(value: unknown, what: string, max = 200): string {
  if (typeof value !== "string" || value.trim() === "" || value.length > max || /[\u0000-\u001f]/.test(value)) {
    fail(`${what} must be a short printable string`);
  }
  return value;
}

export function parseTenants(raw: string, readSecret: (path: string) => string): TenantConfig[] {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    fail("the tenants file is not JSON");
  }
  if (typeof doc !== "object" || doc === null || !Array.isArray((doc as { tenants?: unknown }).tenants)) {
    fail('the tenants file must be {"tenants": [...]}');
  }
  const list = (doc as { tenants: unknown[] }).tenants;
  if (list.length === 0) fail("the tenants file names no tenant");
  const seen = { tenant: new Set<string>(), directory: new Set<string>() };
  const allowed = ["tenant", "name", "directory", "clientId", "audience", "scope", "controlPlaneScope", "secretFile"];
  return list.map((entry, i) => {
    if (typeof entry !== "object" || entry === null) fail(`tenant ${i} is not an object`);
    const e = entry as Record<string, unknown>;
    const extra = Object.keys(e).filter((k) => !allowed.includes(k));
    if (extra.length > 0) fail(`tenant ${i} has unknown fields: ${extra.join(", ")}`);
    const tenant = uuid(e.tenant, `tenant ${i} tenant`);
    const directory = uuid(e.directory, `tenant ${i} directory`);
    const clientId = uuid(e.clientId, `tenant ${i} clientId`);
    const audience = uuid(e.audience, `tenant ${i} audience`);
    // One directory for two tenants would let a person of one sign into the other.
    if (seen.tenant.has(tenant)) fail(`tenant ${tenant} appears twice`);
    if (seen.directory.has(directory)) fail(`directory ${directory} appears twice`);
    seen.tenant.add(tenant);
    seen.directory.add(directory);
    if (clientId === audience) fail(`tenant ${i}: the console's client id must not be the blueprint's`);
    const scope = text(e.scope, `tenant ${i} scope`, 300);
    if (!scope.endsWith(`/${KNOWLEDGE_SCOPE}`) || /\s/.test(scope)) {
      fail(`tenant ${i} scope must be the blueprint's full ${KNOWLEDGE_SCOPE} scope`);
    }
    let controlPlaneScope: string | undefined;
    if (e.controlPlaneScope !== undefined) {
      controlPlaneScope = text(e.controlPlaneScope, `tenant ${i} controlPlaneScope`, 300);
      const app = /^api:\/\/([0-9a-f-]{36})\/Registry\.Console$/.exec(controlPlaneScope)?.[1];
      // Never the blueprint: the control plane must not accept what the knowledge service gets.
      if (!app || !UUID.test(app) || app === audience || app === clientId) {
        fail(`tenant ${i} controlPlaneScope must be api://<control-plane API app>/Registry.Console`);
      }
    }
    const secretFile = text(e.secretFile, `tenant ${i} secretFile`, 1000);
    let clientSecret: string;
    try {
      clientSecret = readSecret(secretFile).trim();
    } catch {
      fail(`tenant ${i}: the client secret file cannot be read`);
    }
    if (clientSecret.length < 16) fail(`tenant ${i}: the client secret file is empty or too short`);
    return {
      tenant,
      name: text(e.name, `tenant ${i} name`),
      directory,
      clientId,
      audience,
      scope,
      ...(controlPlaneScope ? { controlPlaneScope } : {}),
      clientSecret,
    };
  });
}

// "id:base64url32[,id:base64url32...]": the first seals, all open (rotation).
export function parseSessionKeys(raw: string | undefined): SessionKey[] {
  if (!raw) fail("MUISTAMO_CONSOLE_SESSION_KEY is not set");
  const keys = raw.split(",").map((part) => {
    const [id, value, ...rest] = part.trim().split(":");
    if (rest.length > 0 || !id || !KEY_ID.test(id) || !value) fail("a session key must be id:base64url");
    const key = Buffer.from(value, "base64url");
    if (key.length !== 32 || key.toString("base64url") !== value) fail(`session key ${id} must be 32 bytes, base64url`);
    return { id, key: new Uint8Array(key) };
  });
  if (new Set(keys.map((k) => k.id)).size !== keys.length) fail("session key ids must be unique");
  return keys;
}

// The console's own public origin: https, or a loopback address for the end-to-end run only.
export function parsePublicUrl(raw: string | undefined): URL {
  if (!raw) fail("MUISTAMO_CONSOLE_PUBLIC_URL is not set");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    fail("MUISTAMO_CONSOLE_PUBLIC_URL is not a URL");
  }
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    fail("MUISTAMO_CONSOLE_PUBLIC_URL must be https");
  }
  if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) {
    fail("MUISTAMO_CONSOLE_PUBLIC_URL must be an origin only");
  }
  return url;
}

export function isLoopback(url: URL): boolean {
  return url.hostname === "127.0.0.1" || url.hostname === "localhost";
}

export type EntraConfig = {
  tenants: TenantConfig[];
  keys: SessionKey[];
  publicUrl: URL;
  // Test use only: reach a fake of Microsoft's endpoints (deploy/dev/e2e), never in a deployment.
  e2eMicrosoft: { address: string; ca: string } | null;
};

export function loadEntraConfig(env: NodeJS.ProcessEnv = process.env): EntraConfig {
  const path = env.MUISTAMO_CONSOLE_TENANTS;
  if (!path) fail("MUISTAMO_CONSOLE_TENANTS is not set");
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    fail("the tenants file cannot be read");
  }
  const tenants = parseTenants(raw, (p) => readFileSync(p, "utf8"));
  const keys = parseSessionKeys(env.MUISTAMO_CONSOLE_SESSION_KEY);
  const publicUrl = parsePublicUrl(env.MUISTAMO_CONSOLE_PUBLIC_URL);
  let e2eMicrosoft: EntraConfig["e2eMicrosoft"] = null;
  const address = env.MUISTAMO_CONSOLE_INSECURE_E2E_MICROSOFT_ADDR;
  if (address) {
    // Only on a loopback console: a deployment has an https public URL and can never use it.
    if (!isLoopback(publicUrl) || publicUrl.protocol !== "http:") {
      fail("the e2e Microsoft fake is allowed only for a loopback console");
    }
    const caFile = env.MUISTAMO_CONSOLE_INSECURE_E2E_MICROSOFT_CA;
    if (!caFile) fail("MUISTAMO_CONSOLE_INSECURE_E2E_MICROSOFT_CA is required with the e2e fake");
    e2eMicrosoft = { address, ca: readFileSync(caFile, "utf8") };
  }
  return { tenants, keys, publicUrl, e2eMicrosoft };
}

let cached: EntraConfig | null = null;

// The configuration, loaded once per process; throws (fail closed) if it is not valid.
export function entraConfig(): EntraConfig {
  if (!cached) cached = loadEntraConfig();
  return cached;
}

export function tenantConfig(tenant: string): TenantConfig | null {
  return entraConfig().tenants.find((t) => t.tenant === tenant) ?? null;
}

// Tests only.
export function resetEntraConfig(): void {
  cached = null;
}
