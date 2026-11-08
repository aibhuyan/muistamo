import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { beforeEach, describe, expect, test, vi } from "vitest";

import { cookieJar, reset } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));

const { resetEntraConfig } = await import("@/lib/entra/config");
const { TXN_COOKIE } = await import("@/lib/entra/cookies");
const { seal } = await import("@/lib/entra/seal");
const { GET: start, POST: startPost } = await import("./start/route");
const { GET: callback } = await import("./callback/route");
const { register } = await import("@/instrumentation");
const { NextRequest } = await import("next/server");

const TENANT = "11111111-2222-4333-8444-555555555555";
const KEY = { id: "k1", key: new Uint8Array(32).fill(9) };

function configure(over: Record<string, string> = {}, tenants = 1) {
  const dir = mkdtempSync(join(tmpdir(), "console-auth-"));
  writeFileSync(join(dir, "secret"), "obviously-fake-console-secret");
  writeFileSync(
    join(dir, "tenants.json"),
    JSON.stringify({
      tenants: [
        {
          tenant: TENANT,
          name: "Acme",
          directory: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
          clientId: "c0c0c0c0-0000-4000-8000-0000000c0501",
          audience: "b1b1b1b1-0000-4000-8000-00000000b1b1",
          scope: "api://b1b1b1b1-0000-4000-8000-00000000b1b1/Knowledge.Read",
          secretFile: join(dir, "secret"),
        },
        ...(tenants > 1
          ? [
              {
                tenant: "22222222-2222-4333-8444-555555555555",
                name: "Globex",
                directory: "dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                clientId: "c0c0c0c0-0000-4000-8000-0000000c0502",
                audience: "b1b1b1b1-0000-4000-8000-00000000b1b1",
                scope: "api://b1b1b1b1-0000-4000-8000-00000000b1b1/Knowledge.Read",
                secretFile: join(dir, "secret"),
              },
            ]
          : []),
      ],
    }),
  );
  vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "");
  vi.stubEnv("MUISTAMO_CONSOLE_TENANTS", join(dir, "tenants.json"));
  vi.stubEnv("MUISTAMO_CONSOLE_SESSION_KEY", `k1:${Buffer.from(KEY.key).toString("base64url")}`);
  vi.stubEnv("MUISTAMO_CONSOLE_PUBLIC_URL", "https://console.example.invalid");
  writeFileSync(join(dir, "ca.pem"), "obviously-fake-ca");
  for (const [k, v] of Object.entries(over)) vi.stubEnv(k, v === "CA_FILE" ? join(dir, "ca.pem") : v);
  resetEntraConfig();
}

beforeEach(() => {
  reset();
  configure();
});

describe("sign-in routes", () => {
  test("without Entra configured they do not exist", async () => {
    vi.stubEnv("MUISTAMO_CONSOLE_TENANTS", "");
    resetEntraConfig();
    expect((await start()).status).toBe(404);
    expect((await callback(new NextRequest("https://console.example.invalid/auth/callback"))).status).toBe(404);
  });

  test("a GET (a link on another site) never starts a sign-in", async () => {
    const res = await start();
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("https://console.example.invalid/sign-in");
    expect(cookieJar.has(TXN_COOKIE)).toBe(false);
  });

  const post = (headers: Record<string, string>, organisation?: string) => {
    const body = new FormData();
    if (organisation !== undefined) body.set("organisation", organisation);
    return new NextRequest("https://console.example.invalid/auth/start", { method: "POST", headers, body });
  };

  test.each([
    ["a cross-site post", { "sec-fetch-site": "cross-site" }],
    ["another origin", { origin: "https://evil.example.invalid" }],
    ["no origin at all", {}],
  ])("%s is refused", async (_name, headers) => {
    const res = await startPost(post(headers as Record<string, string>));
    expect(res.status).toBe(403);
    expect(cookieJar.has(TXN_COOKIE)).toBe(false);
  });

  test("an organisation that is not configured goes back to sign-in, never to an authority it names", async () => {
    configure({}, 2);
    const res = await startPost(post({ "sec-fetch-site": "same-origin" }, "https://login.microsoftonline.com/common"));
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("https://console.example.invalid/sign-in?unknown=1");
    expect(cookieJar.has(TXN_COOKIE)).toBe(false);
  });

  test("a callback without its transaction is refused", async () => {
    const res = await callback(new NextRequest("https://console.example.invalid/auth/callback?code=c&state=s"));
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain("code=");
  });

  test("a transaction is used once: the callback deletes it, success or not", async () => {
    cookieJar.set(TXN_COOKIE, { value: await seal([KEY], "txn", { state: "s", nonce: "n", verifier: "v", tenant: "99999999-2222-4333-8444-555555555555", cid: "x" }, Date.now() + 60_000) });
    const res = await callback(new NextRequest("https://console.example.invalid/auth/callback?code=c&state=s"));
    expect(res.status).toBe(400); // its tenant is not configured
    // Removed with the attributes a __Host- cookie needs, or browsers would ignore the removal.
    expect(cookieJar.get(TXN_COOKIE)).toMatchObject({ value: "", options: { secure: true, path: "/", maxAge: 0 } });
  });

  test("a session cookie presented as the transaction is refused", async () => {
    cookieJar.set(TXN_COOKIE, { value: await seal([KEY], "session", { tenant: TENANT }, Date.now() + 60_000) });
    const res = await callback(new NextRequest("https://console.example.invalid/auth/callback?code=c&state=s"));
    expect(res.status).toBe(400);
  });
});

describe("startup", () => {
  test.each([
    ["dev and Entra together", { MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN: "true" }],
    ["no session key", { MUISTAMO_CONSOLE_SESSION_KEY: "" }],
    ["a public URL that is not https", { MUISTAMO_CONSOLE_PUBLIC_URL: "http://console.example.invalid" }],
    // With its CA given, so only the loopback rule can refuse it.
    [
      "the e2e fake on a real deployment",
      { MUISTAMO_CONSOLE_INSECURE_E2E_MICROSOFT_ADDR: "127.0.0.1:4443", MUISTAMO_CONSOLE_INSECURE_E2E_MICROSOFT_CA: "CA_FILE" },
    ],
    ["a missing tenants file", { MUISTAMO_CONSOLE_TENANTS: "/nonexistent/tenants.json" }],
  ])("refuses to start with %s", async (_name, over) => {
    configure(over);
    vi.stubEnv("NEXT_RUNTIME", "nodejs");
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await register();
    expect(exit).toHaveBeenCalledWith(1);
    expect(error.mock.calls[0][0]).not.toContain("obviously-fake-console-secret");
    exit.mockRestore();
    error.mockRestore();
  });

  test("the e2e fake is accepted only for a loopback console", async () => {
    configure({
      MUISTAMO_CONSOLE_PUBLIC_URL: "http://127.0.0.1:3000",
      MUISTAMO_CONSOLE_INSECURE_E2E_MICROSOFT_ADDR: "127.0.0.1:4443",
      MUISTAMO_CONSOLE_INSECURE_E2E_MICROSOFT_CA: "CA_FILE",
    });
    vi.stubEnv("NEXT_RUNTIME", "nodejs");
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await register();
    expect(exit).not.toHaveBeenCalled();
    expect(warn.mock.calls[0][0]).toContain("INSECURE");
    exit.mockRestore();
    warn.mockRestore();
  });

  test("starts with a valid configuration", async () => {
    vi.stubEnv("NEXT_RUNTIME", "nodejs");
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    await register();
    expect(exit).not.toHaveBeenCalled();
    exit.mockRestore();
  });
});
