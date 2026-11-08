import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { Redirect, cookieJar, jsonResponse, reset } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({ redirect: (await import("@/test/next")).redirect }));
vi.mock("next/server", async () => ({ ...(await vi.importActual("next/server")), connection: (await import("@/test/next")).connection }));
vi.mock("next/cache", async () => ({ revalidatePath: (await import("@/test/next")).revalidatePath }));

const refresh = vi.fn();
vi.mock("./flow", async () => ({ ...(await vi.importActual("./flow")), refreshSession: (...a: unknown[]) => refresh(...a) }));

const { resetEntraConfig } = await import("./config");
const { SESSION_COOKIE, readSession, writeSession } = await import("./cookies");
const { getSession, requireSession, serviceHeaders } = await import("@/lib/session");
const { default: MyKnowledgePage } = await import("@/app/my-knowledge/page");
const { proxy } = await import("@/proxy");
const { NextRequest } = await import("next/server");

const TENANT = "11111111-2222-4333-8444-555555555555";
const CLIENT = "c0c0c0c0-0000-4000-8000-0000000c0501";
const AT = "obviously-fake-access-token-value";
const RT = "obviously-fake-refresh-token-value";

function configure(clientId = CLIENT) {
  const dir = mkdtempSync(join(tmpdir(), "console-entra-"));
  writeFileSync(join(dir, "secret"), "obviously-fake-console-secret");
  writeFileSync(
    join(dir, "tenants.json"),
    JSON.stringify({
      tenants: [
        {
          tenant: TENANT,
          name: "Acme",
          directory: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
          clientId,
          audience: "b1b1b1b1-0000-4000-8000-00000000b1b1",
          scope: "api://b1b1b1b1-0000-4000-8000-00000000b1b1/Knowledge.Read",
          secretFile: join(dir, "secret"),
        },
      ],
    }),
  );
  vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "");
  vi.stubEnv("MUISTAMO_CONSOLE_TENANTS", join(dir, "tenants.json"));
  vi.stubEnv("MUISTAMO_CONSOLE_SESSION_KEY", `k1:${Buffer.alloc(32, 9).toString("base64url")}`);
  vi.stubEnv("MUISTAMO_CONSOLE_PUBLIC_URL", "https://console.example.invalid");
  resetEntraConfig();
}

const session = (over: Record<string, unknown> = {}) => ({
  sid: "s1",
  tenant: TENANT,
  cid: CLIENT,
  person: "entra:0d0d0d0d-0000-4000-8000-00000000000a",
  name: "Ada Reviewer",
  at: AT,
  atExp: Date.now() + 30 * 60_000,
  rt: RT,
  ends: Date.now() + 8 * 3600_000,
  ...over,
});

// The test cookie jar as Next's cookie store.
const store = {
  get: (n: string) => (cookieJar.has(n) ? { value: cookieJar.get(n)!.value } : undefined),
  set: (n: string, v: string, o: Record<string, unknown>) => void cookieJar.set(n, { value: v, options: o }),
  delete: (n: string) => void cookieJar.delete(n),
};

beforeEach(() => {
  reset();
  configure();
  refresh.mockReset();
});

describe("the Entra session", () => {
  test("is read from the sealed cookie; pages get no token", async () => {
    await writeSession(store, session());
    expect(await getSession()).toEqual({ tenant: TENANT, person: session().person, name: "Ada Reviewer" });
    const cookie = [...cookieJar.entries()].find(([n]) => n.startsWith(SESSION_COOKIE));
    expect(cookie?.[1].options).toMatchObject({ httpOnly: true, secure: true, sameSite: "strict", path: "/" });
    expect(cookie?.[0]).toMatch(/^__Host-/);
    expect(cookie?.[1].value).not.toContain(AT); // encrypted
  });

  test.each([
    ["an expired session", { ends: Date.now() - 1000 }],
    ["an expired access token", { atExp: Date.now() - 1000 }],
  ])("%s is no session", async (_n, over) => {
    await writeSession(store, session(over as Record<string, unknown>));
    expect(await getSession()).toBeNull();
    await expect(requireSession()).rejects.toEqual(new Redirect("/sign-in"));
  });

  test("a rotated console app, or a tenant no longer configured, ends the session at once", async () => {
    await writeSession(store, session());
    configure("c0c0c0c0-0000-4000-8000-0000000c0599");
    expect(await readSession(store)).toBeNull();
  });

  test("only the bearer token is sent, never development headers", async () => {
    await writeSession(store, session());
    const headers = await serviceHeaders({ tenant: TENANT, person: session().person });
    expect(headers).toEqual({ Authorization: `Bearer ${AT}` });
    // Another person's page session never gets this cookie's token.
    await expect(serviceHeaders({ tenant: TENANT, person: "entra:someone-else" })).rejects.toThrow();
  });

  test("no token ever reaches the rendered page", async () => {
    await writeSession(store, session());
    const fetch = vi.fn(async () =>
      jsonResponse(200, {
        items: [
          {
            id: "e-1",
            key: "k",
            type: "fact",
            title: "t",
            body: "b",
            dataClass: "internal",
            contributor: session().person,
            createdAt: "2026-11-08T10:00:00Z",
            private: false,
          },
        ],
      }),
    );
    vi.stubGlobal("fetch", fetch);
    const html = renderToStaticMarkup(await MyKnowledgePage());
    expect(html).toContain("My knowledge");
    expect(html).not.toContain(AT);
    expect(html).not.toContain(RT);
    const sent = (fetch.mock.calls[0] as unknown as [string, RequestInit])[1].headers as Record<string, string>;
    expect(sent.Authorization).toBe(`Bearer ${AT}`);
    expect(Object.keys(sent).some((h) => h.startsWith("X-Muistamo"))).toBe(false);
  });
});

describe("the proxy", () => {
  async function requestWith(s: Record<string, unknown>) {
    await writeSession(store, session(s));
    const cookieHeader = [...cookieJar.entries()].map(([n, c]) => `${n}=${c.value}`).join("; ");
    cookieJar.clear();
    return new NextRequest("https://console.example.invalid/my-knowledge", { headers: { cookie: cookieHeader } });
  }

  test("leaves a fresh session alone", async () => {
    const res = await proxy(await requestWith({}));
    expect(refresh).not.toHaveBeenCalled();
    expect(res.status).toBe(200);
  });

  test("renews a token about to expire, for this render and the browser, keeping the absolute expiry", async () => {
    const ends = Date.now() + 3600_000;
    refresh.mockImplementation(async (_t, s) => ({ ...s, at: "obviously-fake-renewed-token", atExp: Date.now() + 3600_000 }));
    const req = await requestWith({ atExp: Date.now() + 60_000, ends });
    const res = await proxy(req);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(res.headers.get("set-cookie")).toContain(`${SESSION_COOKIE}.0=`);
    const renewed = await readSession(req.cookies as never);
    expect(renewed?.at).toBe("obviously-fake-renewed-token");
    expect(renewed?.ends).toBe(ends);
  });

  test("a revoked grant ends the session", async () => {
    refresh.mockRejectedValue(Object.assign(new Error("refused"), { error: "invalid_grant" }));
    const req = await requestWith({ atExp: Date.now() + 60_000 });
    const res = await proxy(req);
    expect(res.status).toBe(200);
    expect(await readSession(req.cookies as never)).toBeNull();
    expect(res.headers.get("set-cookie")).toMatch(new RegExp(`${SESSION_COOKIE.replace("-", "\\-")}\\.0=;`));
  });

  test("any other failure refuses the request once the token is nearly gone", async () => {
    refresh.mockRejectedValue(new TypeError("fetch failed"));
    expect((await proxy(await requestWith({ atExp: Date.now() + 10_000 }))).status).toBe(503);
    // With time left it carries on and renews at the next request.
    expect((await proxy(await requestWith({ atExp: Date.now() + 120_000 }))).status).toBe(200);
  });

  test("every __Host- cookie it sends, a removal included, is Secure with Path=/", async () => {
    refresh.mockRejectedValue(Object.assign(new Error("refused"), { error: "invalid_grant" }));
    const res = await proxy(await requestWith({ atExp: Date.now() + 60_000 }));
    const sent = res.headers.getSetCookie().filter((c) => c.startsWith("__Host-"));
    expect(sent.length).toBe(4);
    for (const cookie of sent) {
      expect(cookie).toMatch(/; Secure/i);
      expect(cookie).toMatch(/; Path=\/(;|$)/);
      expect(cookie).not.toMatch(/; Domain=/i);
    }
  });
});
