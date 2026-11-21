import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, test, vi } from "vitest";

import { Redirect, jsonResponse, reset, signInAs } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({ redirect: (await import("@/test/next")).redirect }));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));

const { default: PoliciesPage } = await import("./policies/page");
const { default: LinkPage } = await import("./policies/links/[name]/page");
const { default: ActionPolicyPage } = await import("./policies/actions/[name]/page");
const { default: TemplatePage } = await import("./templates/[name]/page");

beforeEach(reset);

// Who last changed a document is an actor identity, an email for a development caller: never shown.
const CHANGED_BY = "operator@example.invalid";

const record = <T,>(document: T) => ({ revision: 2, createdAt: "2026-11-01T09:00:00Z", updatedAt: "2026-11-02T09:00:00Z", updatedBy: CHANGED_BY, document });

const link = (name: string, from: Record<string, string>, to: Record<string, string>, extra: Record<string, unknown> = {}) =>
  record({
    apiVersion: "muistamo.dev/v1",
    kind: "AgentLink",
    metadata: { name },
    spec: { from, to, allowedSkills: ["get-quotes"], dataClasses: ["internal"], ...extra },
  });

const policy = (name: string, appliesTo: Record<string, string>, spec: Record<string, unknown> = {}) =>
  record({
    apiVersion: "muistamo.dev/v1",
    kind: "ActionPolicy",
    metadata: { name },
    spec: { appliesTo, rules: [{ action: "crm.update", effect: "deny" }], ...spec },
  });

const links = [
  link("intern-to-market", { template: "analyst-intern" }, { template: "market-data" }, { rateLimit: "60/min" }),
  link("desk-to-intern", { template: "desk" }, { template: "analyst-intern" }),
  link("se-clone-to-tax", { clone: "analyst-se" }, { template: "tax" }),
];
const policies = [
  policy("intern-actions", { template: "analyst-intern" }, {
    default: "deny",
    mode: "monitor",
    rules: [
      { action: "sharepoint.read", effect: "allow" },
      { action: "email.send", effect: "monitor", when: ["recipients.allInternal"], unless: ["draft.flagged"] },
      { action: "crm.update", effect: "deny" },
    ],
  }),
  policy("se-actions", { clone: "analyst-se" }, { rules: [{ action: "email.send", effect: "monitor" }] }),
  policy("desk-actions", { template: "desk" }),
];

const template = {
  version: 4,
  createdAt: "2026-11-01T09:00:00Z",
  document: { apiVersion: "muistamo.dev/v1", kind: "AgentTemplate", metadata: { name: "analyst-intern" }, spec: { purpose: "Support interns", modelAlias: "general" } },
};

const answer = (url: string) => {
  const path = new URL(url).pathname;
  if (path === "/v1/links") return { items: links };
  if (path === "/v1/action-policies") return { items: policies };
  if (path.startsWith("/v1/links/")) return links.find((l) => path.endsWith("/" + l.document.metadata.name));
  if (path.startsWith("/v1/action-policies/")) return policies.find((p) => path.endsWith("/" + p.document.metadata.name));
  if (path.startsWith("/v1/templates/")) return template;
};

const serve = () => {
  const fetch = vi.fn(async (url: string) => jsonResponse(200, answer(url)));
  vi.stubGlobal("fetch", fetch);
  return fetch;
};

const params = (name: string) => ({ params: Promise.resolve({ name }) });
const render = async (page: Promise<unknown>) => renderToStaticMarkup((await page) as React.ReactElement);

const pages: [string, () => Promise<unknown>][] = [
  ["policies", () => PoliciesPage()],
  ["a link", () => LinkPage(params("intern-to-market"))],
  ["an action policy", () => ActionPolicyPage(params("intern-actions"))],
];

test.each(pages)("the %s page without a session goes to sign-in and calls no service", async (_name, page) => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(page()).rejects.toEqual(new Redirect("/sign-in"));
  expect(fetch).not.toHaveBeenCalled();
});

test.each(pages)("the %s page shows the control plane's refusal instead of policies", async (_name, page) => {
  signInAs("r@example.invalid");
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(403, { title: "Forbidden", status: 403, detail: "only console administrators can read policies" })));
  const html = await render(page());
  expect(html).toContain("only console administrators can read policies");
  expect(html).not.toContain("intern-to-market");
  expect(html).not.toContain("crm.update");
});

test("the policies page lists links and action policies, says nothing is blocked, and never who changed them", async () => {
  signInAs("r@example.invalid");
  const fetch = serve();
  const html = await render(PoliciesPage());
  const urls = fetch.mock.calls.map((c) => (c as unknown as [string])[0]).sort();
  expect(urls).toEqual(["http://control-plane.test/v1/action-policies", "http://control-plane.test/v1/links"]);
  // Honest coverage: nothing in release 1 checks live calls or actions against these rules.
  expect(html).toContain("Release 1 does not check live calls or actions against these rules.");
  expect(html).toContain("nothing is blocked yet");
  expect(html).not.toMatch(/observes|are evaluated|monitored/i);
  for (const name of ["intern-to-market", "desk-to-intern", "se-clone-to-tax"]) expect(html).toContain(`href="/policies/links/${name}"`);
  for (const name of ["intern-actions", "se-actions", "desk-actions"]) expect(html).toContain(`href="/policies/actions/${name}"`);
  // Templates are linked; a clone is named, not linked (the console has no clone page).
  expect(html).toContain('href="/templates/market-data"');
  expect(html).toContain("analyst-se");
  expect(html).not.toContain('href="/templates/analyst-se"');
  expect(html).not.toContain(CHANGED_BY);
});

test("an empty tenant says what having no link or policy means", async () => {
  signInAs("r@example.invalid");
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(200, { items: [] })));
  const html = await render(PoliciesPage());
  expect(html).toContain("No agent links. Every call from one agent to another is denied.");
  expect(html).toContain("No action policies. Every tool action is denied by default.");
});

test("a link page shows the link in full, with the rate limit as stored and not evaluated", async () => {
  signInAs("r@example.invalid");
  const fetch = serve();
  const html = await render(LinkPage(params("intern-to-market")));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/links/intern-to-market");
  expect(html).toContain('href="/templates/analyst-intern"');
  expect(html).toContain('href="/templates/market-data"');
  expect(html).toContain("get-quotes");
  expect(html).toContain("The calling person");
  expect(html).toContain("allowed only as a direct call");
  expect(html).toContain("60/min (stored, not yet evaluated)");
  expect(html).toContain("nothing is blocked yet");
  expect(html).not.toContain(CHANGED_BY);
});

test("an action policy page lists its rules in order with their conditions", async () => {
  signInAs("r@example.invalid");
  serve();
  const html = await render(ActionPolicyPage(params("intern-actions")));
  expect(html).toContain('href="/templates/analyst-intern"');
  expect(html.indexOf("sharepoint.read")).toBeLessThan(html.indexOf("email.send"));
  expect(html.indexOf("email.send")).toBeLessThan(html.indexOf("crm.update"));
  expect(html).toContain("recipients.allInternal");
  expect(html).toContain("draft.flagged");
  expect(html).toContain("Allow and flag");
  expect(html).toContain("Deny overrides allow");
  expect(html).toContain("denials are only reported");
  expect(html).toContain("nothing is blocked yet");
  expect(html).not.toContain(CHANGED_BY);
});

test("a clone's action policy says it can only narrow its template's", async () => {
  signInAs("r@example.invalid");
  serve();
  const html = await render(ActionPolicyPage(params("se-actions")));
  expect(html).toContain("can only narrow it");
  // A clone's monitor rule flags what the template allows; it never allows anything itself.
  expect(html).toContain("Flag if allowed");
  expect(html).not.toContain("Allow and flag");
  expect(html).not.toContain("Actions no rule allows");
  expect(html).not.toContain('href="/templates/analyst-se"');
});

test("a template page lists the policy and links that name it, and only those", async () => {
  signInAs("r@example.invalid");
  serve();
  const html = await render(TemplatePage(params("analyst-intern")));
  expect(html).toContain('href="/policies/actions/intern-actions"');
  expect(html).toContain('href="/policies/links/intern-to-market"');
  expect(html).toContain('href="/policies/links/desk-to-intern"');
  // Another template's policy, and a clone's link and policy, are not this template's.
  expect(html).not.toContain("desk-actions");
  expect(html).not.toContain("se-clone-to-tax");
  expect(html).not.toContain("se-actions");
  expect(html).toContain('href="/policies"');
  expect(html).not.toContain(CHANGED_BY);
});

test("a template page still shows the template when the policies are refused", async () => {
  signInAs("r@example.invalid");
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) =>
      url.includes("/v1/templates/") ? jsonResponse(200, template) : jsonResponse(503, { title: "Service Unavailable", status: 503 }),
    ),
  );
  const html = await render(TemplatePage(params("analyst-intern")));
  expect(html).toContain("Support interns");
  expect(html).toContain("The links could not be read: Service Unavailable.");
});

test("a name from the address is fetched once-encoded", async () => {
  signInAs("r@example.invalid");
  vi.spyOn(console, "warn").mockImplementation(() => {});
  const fetch = vi.fn(async () => jsonResponse(404, { title: "Not Found", status: 404 }));
  vi.stubGlobal("fetch", fetch);
  await render(LinkPage(params("a%2Fb")));
  await render(ActionPolicyPage(params("a%2Fb")));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/links/a%2Fb");
  expect((fetch.mock.calls[1] as unknown as [string])[0]).toBe("http://control-plane.test/v1/action-policies/a%2Fb");
});
