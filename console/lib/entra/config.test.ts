import { describe, expect, test } from "vitest";

import { ConfigError, mode, parsePublicUrl, parseSessionKeys, parseTenants } from "./config";

const T = "11111111-2222-4333-8444-555555555555";
const D = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const C = "c0c0c0c0-0000-4000-8000-0000000c0501";
const A = "b1b1b1b1-0000-4000-8000-00000000b1b1";

const entry = (over: Record<string, unknown> = {}) => ({
  tenant: T,
  name: "Acme",
  directory: D,
  clientId: C,
  audience: A,
  scope: `api://${A}/Knowledge.Read`,
  secretFile: "secret",
  ...over,
});
const secret = () => "obviously-fake-console-secret";
const file = (...tenants: unknown[]) => JSON.stringify({ tenants });

describe("tenants file", () => {
  test("a valid tenant is read, with its secret from its own file", () => {
    expect(parseTenants(file(entry()), secret)).toEqual([
      { tenant: T, name: "Acme", directory: D, clientId: C, audience: A, scope: `api://${A}/Knowledge.Read`, clientSecret: secret() },
    ]);
  });

  test.each([
    ["not JSON", "{", secret],
    ["no tenants", file(), secret],
    ["an upper-case directory id", file(entry({ directory: D.toUpperCase() })), secret],
    ["a non-UUID directory", file(entry({ directory: "contoso.onmicrosoft.com" })), secret],
    ["an unknown field", file(entry({ authority: "https://login.microsoftonline.com/common" })), secret],
    ["the same tenant twice", file(entry(), entry({ directory: "dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee" })), secret],
    // One directory for two tenants would let a person of one sign into the other.
    ["the same directory twice", file(entry(), entry({ tenant: "22222222-2222-4333-8444-555555555555" })), secret],
    ["the console id equal to the blueprint's", file(entry({ clientId: A })), secret],
    ["another scope", file(entry({ scope: `api://${A}/Knowledge.ReadWrite` })), secret],
    ["two scopes", file(entry({ scope: `openid api://${A}/Knowledge.Read` })), secret],
    ["an unreadable secret", file(entry()), () => { throw new Error("ENOENT"); }],
    ["an empty secret", file(entry()), () => "  \n"],
  ])("refuses %s", (_name, raw, read) => {
    expect(() => parseTenants(raw as string, read as (p: string) => string)).toThrow(ConfigError);
  });
});

describe("session keys", () => {
  const key = Buffer.alloc(32, 7).toString("base64url");
  test("the first key seals; every listed key opens", () => {
    const keys = parseSessionKeys(`k2:${key},k1:${Buffer.alloc(32, 1).toString("base64url")}`);
    expect(keys.map((k) => k.id)).toEqual(["k2", "k1"]);
    expect(keys[0].key.length).toBe(32);
  });
  test.each([
    ["unset", undefined],
    ["no id", key],
    ["short", `k1:${Buffer.alloc(16).toString("base64url")}`],
    ["not base64url", `k1:${Buffer.alloc(32).toString("base64")}+`],
    ["a duplicate id", `k1:${key},k1:${key}`],
    ["a bad id", `k 1:${key}`],
  ])("refuses %s", (_name, raw) => {
    expect(() => parseSessionKeys(raw)).toThrow(ConfigError);
  });
});

describe("public URL", () => {
  test("https, or loopback http for the end-to-end run", () => {
    expect(parsePublicUrl("https://console.example.invalid").origin).toBe("https://console.example.invalid");
    expect(parsePublicUrl("http://127.0.0.1:3000").origin).toBe("http://127.0.0.1:3000");
  });
  test.each(["http://console.example.invalid", "https://console.example.invalid/path", "ftp://x", "not a url", undefined])(
    "refuses %s",
    (raw) => {
      expect(() => parsePublicUrl(raw)).toThrow(ConfigError);
    },
  );
});

describe("mode", () => {
  test("development, Entra or none; never both", () => {
    expect(mode({ MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN: "true" } as unknown as NodeJS.ProcessEnv)).toBe("dev");
    expect(mode({ MUISTAMO_CONSOLE_TENANTS: "/etc/tenants.json" } as unknown as NodeJS.ProcessEnv)).toBe("entra");
    expect(mode({} as unknown as NodeJS.ProcessEnv)).toBe("none");
    expect(() =>
      mode({ MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN: "true", MUISTAMO_CONSOLE_TENANTS: "/etc/t.json" } as unknown as NodeJS.ProcessEnv),
    ).toThrow(ConfigError);
  });
});
