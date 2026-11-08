import { describe, expect, test } from "vitest";

import { SignInError, checkAccessToken, checkIdToken } from "./claims";
import type { TenantConfig } from "./config";

const t: TenantConfig = {
  tenant: "11111111-2222-4333-8444-555555555555",
  name: "Acme",
  directory: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  clientId: "c0c0c0c0-0000-4000-8000-0000000c0501",
  audience: "b1b1b1b1-0000-4000-8000-00000000b1b1",
  scope: "api://b1b1b1b1-0000-4000-8000-00000000b1b1/Knowledge.Read",
  clientSecret: "obviously-fake-console-secret",
};
const OID = "0d0d0d0d-0000-4000-8000-00000000000a";

const id = (over: Record<string, unknown> = {}) => ({
  iss: `https://login.microsoftonline.com/${t.directory}/v2.0`,
  tid: t.directory,
  aud: t.clientId,
  oid: OID,
  acct: 0,
  name: "Ada Reviewer",
  ...over,
});

// An unsigned JWT-shaped token: the console only reads its claims; the services verify it.
function token(over: Record<string, unknown> = {}): string {
  const part = (v: object) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const claims = {
    oid: OID,
    tid: t.directory,
    azp: t.clientId,
    aud: t.audience,
    ver: "2.0",
    scp: "openid Knowledge.Read",
    exp: 2_000_000_000,
    ...over,
  };
  return `${part({ alg: "RS256" })}.${part(claims)}.obviously-fake`;
}

describe("the ID token", () => {
  test("names the person by object id", () => {
    expect(checkIdToken(t, id())).toEqual({ oid: OID, person: `entra:${OID}`, name: "Ada Reviewer" });
  });

  test.each([
    ["another issuer", { iss: "https://login.microsoftonline.com/common/v2.0" }],
    ["another directory", { tid: "dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee" }],
    ["another app", { aud: t.audience }],
    ["two audiences", { aud: [t.clientId, t.audience] }],
    ["no user", { oid: undefined }],
    ["a non-canonical user", { oid: OID.toUpperCase() }],
    ["a guest", { acct: 1 }],
    // Fail closed: without the optional claim nobody is known to be a member.
    ["no membership claim", { acct: undefined }],
  ])("refuses %s", (_name, over) => {
    expect(() => checkIdToken(t, id(over))).toThrow(SignInError);
  });
});

describe("the access token", () => {
  test("is the same person's, for this console, the blueprint and the scope", () => {
    expect(checkAccessToken(t, OID, token())).toBe(2_000_000_000_000);
  });

  test.each([
    ["another person", { oid: "0d0d0d0d-0000-4000-8000-00000000000b" }],
    ["another directory", { tid: "dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee" }],
    ["another app (an assistant)", { azp: "55555555-5555-4555-8555-555555555555" }],
    ["another resource", { aud: "00000003-0000-0000-c000-000000000000" }],
    ["version 1.0", { ver: "1.0" }],
    ["no knowledge scope", { scp: "openid User.Read" }],
    ["a scope as a substring", { scp: "Knowledge.ReadAll" }],
    ["no expiry", { exp: undefined }],
  ])("refuses %s", (_name, over) => {
    expect(() => checkAccessToken(t, OID, token(over))).toThrow(SignInError);
  });

  test("refuses a value that is not a token", () => {
    expect(() => checkAccessToken(t, OID, "not-a-token")).toThrow(SignInError);
  });
});
