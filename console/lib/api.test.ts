import { beforeEach, expect, test, vi } from "vitest";

import { TENANT, jsonResponse, reset } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({ redirect: (await import("@/test/next")).redirect }));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));

const { api } = await import("./api");

const session = { tenant: TENANT, person: "r@example.invalid" };

beforeEach(reset);

test("calls the service as the session's person, and only that", async () => {
  const fetch = vi.fn(async () => jsonResponse(200, { items: [] }));
  vi.stubGlobal("fetch", fetch);

  expect(await api.reviewerProposals(session)).toEqual({ ok: true, data: { items: [] } });

  expect(fetch).toHaveBeenCalledWith("http://knowledge.test/v1/knowledge/proposals?role=reviewer", {
    method: "GET",
    headers: { "X-Muistamo-Tenant": TENANT, "X-Muistamo-Actor": "r@example.invalid", Accept: "application/json" },
    body: undefined,
    cache: "no-store",
    redirect: "manual",
  });
});

test("a redirect is not followed, so identity headers never reach another origin", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 302, statusText: "Found", headers: { location: "http://elsewhere.test/" } })));

  expect(await api.leaverReviews(session)).toEqual({ ok: false, problem: { title: "Found", status: 302 } });
});

test("a failed call is logged with its cause and who made it", async () => {
  const error = vi.spyOn(console, "error").mockImplementation(() => {});
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new TypeError("fetch failed");
    }),
  );

  await api.leaverReviews(session);
  const logged = JSON.parse(error.mock.calls[0][0] as string);
  expect(logged).toMatchObject({ level: "ERROR", service: "knowledge", tenant: TENANT, person: "r@example.invalid" });
  expect(logged.error).toContain("fetch failed");
  error.mockRestore();
});

test("sends a decision body to the control plane", async () => {
  const fetch = vi.fn(async () => jsonResponse(200, {}));
  vi.stubGlobal("fetch", fetch);

  await api.decideCatalogueRequest(session, "a/b", { decision: "approve", reason: "fine" });

  const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
  expect(url).toBe("http://control-plane.test/v1/catalogue/requests/a%2Fb/decision");
  expect(init.method).toBe("POST");
  expect(init.body).toBe(JSON.stringify({ decision: "approve", reason: "fine" }));
  expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
});

test("without the development sign-in flag no call is made", async () => {
  vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "");
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);

  await expect(api.reviewerProposals(session)).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
});

test("an unset service URL is an error, not a guess", async () => {
  vi.stubEnv("MUISTAMO_KNOWLEDGE_URL", "");
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);

  await expect(api.leaverReviews(session)).rejects.toThrow(/MUISTAMO_KNOWLEDGE_URL/);
  expect(fetch).not.toHaveBeenCalled();
});

test("a refusal is returned in the service's own words", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      jsonResponse(403, { title: "Forbidden", status: 403, detail: "you cannot approve your own proposal" }),
    ),
  );

  expect(await api.decideProposal(session, "p", { decision: "approve", reason: "mine" })).toEqual({
    ok: false,
    problem: { title: "Forbidden", status: 403, detail: "you cannot approve your own proposal" },
  });
});

test("the HTTP status wins over a status claimed in the body", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(409, { title: "Conflict", status: 200 })));

  const result = await api.leaverReview(session, "r");
  expect(result).toEqual({ ok: false, problem: { title: "Conflict", status: 409 } });
});

test("a non-problem error body falls back to the status line", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>", { status: 502, statusText: "Bad Gateway" })));

  expect(await api.leaverReviews(session)).toEqual({ ok: false, problem: { title: "Bad Gateway", status: 502 } });
});

test("an unreachable service is reported, not hidden", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new TypeError("fetch failed");
    }),
  );

  const result = await api.pendingCatalogueRequests(session);
  expect(result).toEqual({ ok: false, problem: { title: "The control-plane service is unreachable", status: 503 } });
});
