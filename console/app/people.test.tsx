import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, test, vi } from "vitest";

import { Redirect, jsonResponse, reset, signInAs } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({ redirect: (await import("@/test/next")).redirect }));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));

const { default: PeoplePage } = await import("./people/page");
const { default: PersonPage } = await import("./people/[id]/page");
const { personHref } = await import("./workforce");

beforeEach(reset);

const EMAIL = "person-a@example.invalid";

// An HR event as the control plane returns it. The extra fields are not in the contract: if the
// service ever sent them, the pages must still not show them.
const receipt = (eventId: string, extra: Record<string, unknown> = {}) => ({
  eventId,
  type: "leaver",
  personId: "HR-77031",
  occurredAt: "2026-11-11T16:00:00Z",
  receivedAt: "2026-11-11T16:02:00Z",
  generation: 2,
  decision: "accepted",
  dispatchState: "dispatched",
  setupCompleted: true,
  identityMode: "simulated",
  payload: { person: { email: EMAIL, jobCode: "ANALYST_INTERN" } },
  ...extra,
});

const person = {
  personId: "HR-77031",
  receipts: [receipt("ev-2"), receipt("ev-1", { type: "joiner", decision: "ignored", dispatchState: "ignored", setupCompleted: false })],
  receiptsTruncated: false,
  agents: [
    {
      name: "analyst-intern-hr-77031",
      templateName: "analyst-intern",
      templateVersion: "3",
      state: "suspended",
      updatedAt: "2026-11-11T16:03:00Z",
      binding: { type: "user", ref: EMAIL },
    },
  ],
};

const query = (q: Record<string, string>) => ({ searchParams: Promise.resolve(q) });
const params = (id: string) => ({ params: Promise.resolve({ id }) });

test.each([
  ["the HR feed", () => PeoplePage(query({}))],
  ["a person", () => PersonPage(params("HR-77031"))],
])("%s without a session goes to sign-in and calls no service", async (_name, render) => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(render()).rejects.toEqual(new Redirect("/sign-in"));
  expect(fetch).not.toHaveBeenCalled();
});

test.each([
  ["the HR feed", () => PeoplePage(query({}))],
  ["a person", () => PersonPage(params("HR-77031"))],
])("%s shows the control plane's refusal instead of people", async (_name, render) => {
  signInAs("r@example.invalid");
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => jsonResponse(403, { title: "Forbidden", status: 403, detail: "only console administrators can read people and HR events" })),
  );
  const html = renderToStaticMarkup((await render()) as React.ReactElement);
  expect(html).toContain("only console administrators can read people and HR events");
  expect(html).not.toContain("HR-77031");
});

test("the feed lists HR events newest first, links each person, and pages on", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn(async () =>
    jsonResponse(200, {
      items: [receipt("ev-2"), receipt("ev-1", { decision: "ignored", dispatchState: "ignored", personId: "HR 1/2" })],
      nextCursor: "abc",
    }),
  );
  vi.stubGlobal("fetch", fetch);
  const html = renderToStaticMarkup(await PeoplePage(query({ cursor: "YQ" })));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/hr/receipts?limit=50&cursor=YQ");
  expect(html).toContain('href="/people/HR-77031"');
  // An id the console cannot address is shown, not linked.
  expect(html).toContain("HR 1/2");
  expect(html).not.toContain('href="/people/HR%201');
  expect(html.match(/href="\/people\//g)).toHaveLength(1);
  expect(html.indexOf("ev-2")).toBeLessThan(html.indexOf("ev-1"));
  // An ignored event is listed, not hidden.
  expect(html).toContain("Ignored");
  expect(html).toContain('href="/people?cursor=abc"');
  // Nothing from the payload.
  expect(html).not.toContain(EMAIL);
  expect(html).not.toContain("ANALYST_INTERN");
});

test("a person's page lists their agents and HR events, and no email", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn(async () => jsonResponse(200, person));
  vi.stubGlobal("fetch", fetch);
  const html = renderToStaticMarkup(await PersonPage(params("HR-77031")));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/people/HR-77031");
  expect(html).toContain('href="/agents/analyst-intern-hr-77031"');
  expect(html).toContain("Suspended");
  expect(html).toContain("ev-1");
  expect(html).toContain("ev-2");
  // HR details: released for the accepted leaver, not applicable to the ignored joiner.
  expect(html).toContain("Released");
  expect(html).toContain("Not applicable");
  expect(html).not.toMatch(/finished/i);
  expect(html).not.toContain(EMAIL);
  expect(html).not.toContain("@example");
  expect(html).not.toContain("ANALYST_INTERN");
  expect(html).not.toContain("Only the 100 most recent");
});

test("a person's page says when it lists only the latest events, and when there are none", async () => {
  signInAs("r@example.invalid");
  const hundred = Array.from({ length: 100 }, (_, i) => receipt(`ev-${i}`));
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(200, { ...person, receipts: hundred, receiptsTruncated: true, agents: [] })));
  let html = renderToStaticMarkup(await PersonPage(params("HR-77031")));
  expect(html).toContain("Only the 100 most recent HR events are listed.");
  expect(html).toContain("No agent carries this HR id.");
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(200, { ...person, receipts: [] })));
  html = renderToStaticMarkup(await PersonPage(params("HR-77031")));
  expect(html).toContain("No HR events have been received for this id.");
});

test("a person id is escaped in the service call", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn(async () => jsonResponse(200, person));
  vi.stubGlobal("fetch", fetch);
  await PersonPage(params("a.b_c-1"));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/people/a.b_c-1");
});

test("an HR id the console cannot address is explained, and no service is called", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const html = renderToStaticMarkup(await PersonPage(params("HR%2F1")));
  expect(html).toContain("This HR id cannot be opened here");
  expect(fetch).not.toHaveBeenCalled();
});

test("only ids the control plane admits from the console are linked", () => {
  expect(personHref("HR-77031")).toBe("/people/HR-77031");
  expect(personHref("a.person_2-x")).toBe("/people/a.person_2-x");
  expect(personHref("a".repeat(200))).toBeDefined();
  for (const bad of ["", "-HR", "HR 1", "HR/1", "HR%1", "HR+1", "a@corp", "a".repeat(201), "é1"]) {
    expect(personHref(bad), bad).toBeUndefined();
  }
});
