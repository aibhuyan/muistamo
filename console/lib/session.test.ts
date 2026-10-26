import { beforeEach, describe, expect, test, vi } from "vitest";

import { Redirect, TENANT, connection, cookieJar, cookies, reset, signInAs } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({ redirect: (await import("@/test/next")).redirect }));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));

const { SESSION_COOKIE, getSession, parseSession, requireSession, serviceHeaders, startSession } = await import(
  "./session"
);

beforeEach(reset);

describe("parseSession", () => {
  test("accepts exactly a tenant and a person", () => {
    expect(parseSession(JSON.stringify({ tenant: TENANT, person: "r@example.invalid" }))).toEqual({
      tenant: TENANT,
      person: "r@example.invalid",
    });
  });

  test.each([
    ["missing", undefined],
    ["not JSON", "{tenant"],
    ["an array", "[]"],
    ["null", "null"],
    ["a non-UUID tenant", JSON.stringify({ tenant: "acme", person: "r@example.invalid" })],
    ["a person without @", JSON.stringify({ tenant: TENANT, person: "root" })],
    ["a person with spaces", JSON.stringify({ tenant: TENANT, person: "a b@example.invalid" })],
    ["a person that cannot travel in a header", JSON.stringify({ tenant: TENANT, person: "名@example.invalid" })],
    ["a non-string person", JSON.stringify({ tenant: TENANT, person: 7 })],
    ["an extra key", JSON.stringify({ tenant: TENANT, person: "r@example.invalid", admin: true })],
    ["a missing key", JSON.stringify({ tenant: TENANT })],
  ])("rejects %s", (_name, raw) => {
    expect(parseSession(raw)).toBeNull();
  });
});

describe("without the development sign-in flag", () => {
  beforeEach(() => {
    vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "");
    signInAs("r@example.invalid");
  });

  test("a valid cookie is no session, and the cookie is not even read", async () => {
    expect(await getSession()).toBeNull();
    expect(cookies).not.toHaveBeenCalled();
  });

  test("the flag is read at request time, never at build time", async () => {
    await getSession();
    expect(connection).toHaveBeenCalled();
  });

  test("any value but true is off", async () => {
    vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "TRUE");
    expect(await getSession()).toBeNull();
  });

  test("pages are sent to sign-in", async () => {
    await expect(requireSession()).rejects.toEqual(new Redirect("/sign-in"));
  });

  test("no session can be started", async () => {
    cookieJar.clear();
    await expect(startSession({ tenant: TENANT, person: "r@example.invalid" })).rejects.toThrow();
    expect(cookieJar.size).toBe(0);
  });

  test("no service headers are produced", () => {
    expect(() => serviceHeaders({ tenant: TENANT, person: "r@example.invalid" })).toThrow();
  });
});

describe("with the development sign-in flag", () => {
  test("the cookie is the session", async () => {
    signInAs("r@example.invalid");
    expect(await getSession()).toEqual({ tenant: TENANT, person: "r@example.invalid" });
  });

  test("a tampered cookie is no session", async () => {
    cookieJar.set(SESSION_COOKIE, { value: JSON.stringify({ tenant: TENANT, person: "x", role: "admin" }) });
    expect(await getSession()).toBeNull();
    await expect(requireSession()).rejects.toEqual(new Redirect("/sign-in"));
  });

  test("the session cookie is httpOnly and SameSite=Lax", async () => {
    await startSession({ tenant: TENANT, person: "r@example.invalid" });
    expect(cookieJar.get(SESSION_COOKIE)?.options).toMatchObject({ httpOnly: true, sameSite: "lax", path: "/" });
  });

  test("service headers carry exactly the session's tenant and person", () => {
    expect(serviceHeaders({ tenant: TENANT, person: "r@example.invalid" })).toEqual({
      "X-Muistamo-Tenant": TENANT,
      "X-Muistamo-Actor": "r@example.invalid",
    });
  });
});
