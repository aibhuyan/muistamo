import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, test, vi } from "vitest";

import { Redirect, jsonResponse, reset, signInAs } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({ redirect: (await import("@/test/next")).redirect }));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));

const { default: AgentsPage } = await import("./agents/page");
const { default: AgentPage } = await import("./agents/[name]/page");
const { default: TemplatesPage } = await import("./templates/page");
const { default: TemplatePage } = await import("./templates/[name]/page");

beforeEach(reset);

const PERSON = "person-a@example.invalid";
const HR_ID = "HR-77031";

const instance = {
  revision: 3,
  createdAt: "2026-11-03T07:30:00Z",
  updatedAt: "2026-11-11T16:03:00Z",
  document: {
    apiVersion: "muistamo.dev/v1",
    kind: "AgentInstance",
    // The HR lifecycle labels every agent it makes with the person's HR id.
    metadata: { name: "analyst-intern-hr-20418", owner: PERSON, labels: { "muistamo.dev/hr-person-id": HR_ID } },
    spec: {
      templateRef: { name: "analyst-intern", version: "3" },
      binding: { type: "user", ref: PERSON },
      sponsor: PERSON,
      delegate: PERSON,
      personalLayerRef: `personal/${PERSON}`,
      identityRef: "entra:9f0c0c0c-0000-4000-8000-00000000a9e1",
      state: "suspended",
      costCentre: "CC-4410",
    },
  },
};

const template = {
  version: 3,
  createdAt: "2026-11-01T09:00:00Z",
  createdBy: `dev:${PERSON}`,
  document: {
    apiVersion: "muistamo.dev/v1",
    kind: "AgentTemplate",
    metadata: { name: "analyst-intern" },
    spec: {
      purpose: "Support interns",
      riskTier: "high",
      modelAlias: "reasoning-default",
      knowledgePacks: [{ name: "client-onboarding" }, { name: "hr-handbook", version: "v4" }],
      tools: ["email.draft"],
      dataClasses: ["internal"],
      assignment: { hrJobCodes: ["INTERN"] },
      budget: { perInstanceMonthlyEUR: 20 },
    },
  },
};

const params = (name: string) => ({ params: Promise.resolve({ name }) });

// The template page also reads the links and action policies: here, none.
const noPolicies = (url: string) => (url.endsWith("/v1/links") || url.endsWith("/v1/action-policies") ? { items: [] } : undefined);
const query = (q: Record<string, string>) => ({ searchParams: Promise.resolve(q) });

const pages: [string, () => Promise<unknown>][] = [
  ["agents", () => AgentsPage(query({}))],
  ["an agent", () => AgentPage(params("analyst-intern-hr-20418"))],
  ["templates", () => TemplatesPage(query({}))],
  ["a template", () => TemplatePage(params("analyst-intern"))],
];

test.each(pages)("the %s page without a session goes to sign-in and calls no service", async (_name, render) => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(render()).rejects.toEqual(new Redirect("/sign-in"));
  expect(fetch).not.toHaveBeenCalled();
});

test.each(pages)("the %s page shows the control plane's refusal instead of the data", async (_name, render) => {
  signInAs("r@example.invalid");
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      jsonResponse(403, { title: "Forbidden", status: 403, detail: "only console administrators can read agents" }),
    ),
  );
  const html = renderToStaticMarkup((await render()) as React.ReactElement);
  expect(html).toContain('role="alert"');
  expect(html).toContain("403 Forbidden");
  expect(html).toContain("only console administrators can read agents");
  expect(html).not.toContain("analyst-intern");
});

test("the agents list asks for one page and links each agent by its encoded name", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn(async () => jsonResponse(200, { items: [instance], nextCursor: "YW5hbHlzdA" }));
  vi.stubGlobal("fetch", fetch);
  const html = renderToStaticMarkup(await AgentsPage(query({})));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/instances?limit=50");
  expect(html).toContain('href="/agents/analyst-intern-hr-20418"');
  expect(html).toContain('<span class="pill pill-stop">Suspended</span>');
  expect(html).toContain("A person");
  expect(html).toContain("CC-4410");
  expect(html).toContain('href="/agents?cursor=YW5hbHlzdA"');
  expect(html).not.toContain("First page");
});

test("the next page passes the service's cursor back, encoded once", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn(async () => jsonResponse(200, { items: [] }));
  vi.stubGlobal("fetch", fetch);
  const html = renderToStaticMarkup(await TemplatesPage(query({ cursor: "a+b/c" })));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/templates?limit=50&cursor=a%2Bb%2Fc");
  expect(html).toContain("No more templates.");
  expect(html).toContain('href="/templates">First page');
  expect(html).not.toContain("Next page");
});

// A person's identifier is not shown on these pages until it is decided how
// (docs/console-management-plan.md), even though the record carries it.
test("agent and template pages never show a person's identifier", async () => {
  signInAs("r@example.invalid");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) =>
      jsonResponse(
        200,
        noPolicies(url) ??
          (url.includes("/instances/") ? instance : url.includes("/templates/") ? template : { items: [url.includes("/instances") ? instance : template] }),
      ),
    ),
  );
  for (const page of [
    await AgentsPage(query({})),
    await AgentPage(params("analyst-intern-hr-20418")),
    await TemplatesPage(query({})),
    await TemplatePage(params("analyst-intern")),
  ]) {
    const html = renderToStaticMarkup(page as React.ReactElement);
    expect(html).not.toContain(PERSON);
    expect(html).not.toContain(HR_ID);
    expect(html).not.toContain("hr-person-id");
    expect(html).toContain("analyst-intern");
  }
});

test("a template page shows its scope as the template states it", async () => {
  signInAs("r@example.invalid");
  vi.stubGlobal("fetch", vi.fn(async (url: string) => jsonResponse(200, noPolicies(url) ?? template)));
  const html = renderToStaticMarkup(await TemplatePage(params("analyst-intern")));
  expect(html).toContain("Support interns");
  expect(html).toContain("No action policy names this template");
  expect(html).toContain('<span class="pill pill-stop">High</span>');
  expect(html).toContain("client-onboarding");
  expect(html).toContain("hr-handbook");
  expect(html).toContain("v4");
  expect(html).toContain("email.draft");
  expect(html).toContain("INTERN");
  expect(html).toContain("20 EUR a month");
});

test("a name from the address is fetched once-encoded", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn(async () => jsonResponse(404, { title: "Not Found", status: 404 }));
  vi.stubGlobal("fetch", fetch);
  vi.spyOn(console, "warn").mockImplementation(() => {});
  renderToStaticMarkup(await AgentPage(params("a%2Fb")));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/instances/a%2Fb");
});
