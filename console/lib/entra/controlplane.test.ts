import { beforeEach, describe, expect, test, vi } from "vitest";

const refreshTokenGrant = vi.fn();
vi.mock("openid-client", async () => ({ ...(await vi.importActual("openid-client")), refreshTokenGrant: (...a: unknown[]) => refreshTokenGrant(...a) }));
vi.mock("./flow", async () => ({ ...(await vi.importActual("./flow")), oidcConfig: async () => ({}) }));

const { checkControlPlaneToken, controlPlaneApp, controlPlaneToken, forgetControlPlaneToken } = await import("./controlplane");
const { SignInError } = await import("./claims");
const { parseTenants } = await import("./config");

const API = "a9a9a9a9-0000-4000-8000-0000000a9a9a";
const t = {
  tenant: "11111111-2222-4333-8444-555555555555",
  name: "Acme",
  directory: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  clientId: "c0c0c0c0-0000-4000-8000-0000000c0501",
  audience: "b1b1b1b1-0000-4000-8000-00000000b1b1",
  scope: "api://b1b1b1b1-0000-4000-8000-00000000b1b1/Knowledge.Read",
  controlPlaneScope: `api://${API}/Registry.Console`,
  clientSecret: "obviously-fake-console-secret",
};
const OID = "0d0d0d0d-0000-4000-8000-00000000000a";

function token(over: Record<string, unknown> = {}): string {
  const part = (v: object) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const claims = {
    oid: OID,
    tid: t.directory,
    azp: t.clientId,
    aud: API,
    ver: "2.0",
    scp: "Registry.Console",
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...over,
  };
  return `${part({ alg: "RS256" })}.${part(claims)}.obviously-fake`;
}

const session = { sid: "s1", tenant: t.tenant, cid: t.clientId, person: `entra:${OID}`, name: "Ada", at: "kt", atExp: 0, rt: "obviously-fake-rt", ends: 0 };

beforeEach(() => {
  refreshTokenGrant.mockReset();
  forgetControlPlaneToken("s1");
});

describe("the control-plane token", () => {
  test("is this console's token for this person, for the control plane's own API app", () => {
    expect(controlPlaneApp(t.controlPlaneScope)).toBe(API);
    expect(checkControlPlaneToken(t, OID, token())).toBeGreaterThan(Date.now());
  });

  test.each([
    ["the blueprint's token", { aud: t.audience, scp: "Knowledge.Read" }],
    ["another audience", { aud: "00000003-0000-0000-c000-000000000000" }],
    ["another scope", { scp: "Knowledge.Read" }],
    ["another app (an assistant)", { azp: "55555555-5555-4555-8555-555555555555" }],
    ["another person", { oid: "0d0d0d0d-0000-4000-8000-00000000000b" }],
    ["another directory", { tid: "dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee" }],
    ["version 1.0", { ver: "1.0" }],
  ])("refuses %s", (_name, over) => {
    expect(() => checkControlPlaneToken(t, OID, token(over))).toThrow(SignInError);
  });

  test("is asked for with the refresh token, for exactly its scope, and kept in memory only", async () => {
    refreshTokenGrant.mockResolvedValue({ access_token: token() });
    const first = await controlPlaneToken(t, session);
    expect(refreshTokenGrant).toHaveBeenCalledWith({}, "obviously-fake-rt", { scope: t.controlPlaneScope });
    expect(await controlPlaneToken(t, session)).toBe(first);
    expect(refreshTokenGrant).toHaveBeenCalledTimes(1);
    forgetControlPlaneToken("s1");
    await controlPlaneToken(t, session);
    expect(refreshTokenGrant).toHaveBeenCalledTimes(2);
  });

  test("one close to expiry is asked for again; a wrong one is never kept", async () => {
    refreshTokenGrant.mockResolvedValueOnce({ access_token: token({ exp: Math.floor(Date.now() / 1000) + 60 }) });
    await controlPlaneToken(t, session);
    refreshTokenGrant.mockResolvedValueOnce({ access_token: token({ aud: t.audience }) });
    await expect(controlPlaneToken(t, session)).rejects.toThrow(SignInError);
    refreshTokenGrant.mockResolvedValueOnce({ access_token: token() });
    await controlPlaneToken(t, session);
    expect(refreshTokenGrant).toHaveBeenCalledTimes(3);
  });
});

describe("the tenants file", () => {
  const entry = (controlPlaneScope: string) =>
    JSON.stringify({ tenants: [{ ...t, clientSecret: undefined, secretFile: "s", controlPlaneScope }] });
  test.each([
    ["the blueprint's scope", `api://${t.audience}/Registry.Console`],
    ["the console's own app", `api://${t.clientId}/Registry.Console`],
    ["another scope", `api://${API}/Knowledge.Read`],
    ["not an api:// scope", `https://example.invalid/Registry.Console`],
  ])("refuses a controlPlaneScope naming %s", (_name, scope) => {
    expect(() => parseTenants(entry(scope), () => "obviously-fake-console-secret")).toThrow();
  });

  test("accepts the control plane's own API app", () => {
    expect(parseTenants(entry(t.controlPlaneScope), () => "obviously-fake-console-secret")[0].controlPlaneScope).toBe(
      t.controlPlaneScope,
    );
  });
});
