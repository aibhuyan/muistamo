import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, test, vi } from "vitest";

import { jsonResponse, reset, signInAs } from "@/test/next";

let pathname = "/";
vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({
  redirect: (await import("@/test/next")).redirect,
  usePathname: () => pathname,
}));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));
vi.mock("./globals.css", () => ({}));

const { Nav, navGroups, isCurrent } = await import("./nav");
const { Pill, day, decided, label, when } = await import("./entry");
const { DecisionForm } = await import("./decision-form");
const { default: Home } = await import("./page");
const { default: RootLayout } = await import("./layout");
const { default: LeaverReviewPage } = await import("./leaver-reviews/[id]/page");

beforeEach(() => {
  reset();
  pathname = "/";
});

test("a navigation link is current on its page and the pages beneath it", () => {
  expect(isCurrent("/", "/")).toBe(true);
  expect(isCurrent("/proposals", "/")).toBe(false);
  expect(isCurrent("/proposals", "/proposals")).toBe(true);
  expect(isCurrent("/proposals/p-1", "/proposals")).toBe(true);
  // A longer path that merely starts with the same letters is another page.
  expect(isCurrent("/proposals-archive", "/proposals")).toBe(false);
  expect(isCurrent("/catalogue", "/proposals")).toBe(false);
});

test("the navigation marks exactly one link as the current page", () => {
  pathname = "/leaver-reviews/leaver-t-P-77%3A01a1";
  const html = renderToStaticMarkup(<Nav />);
  expect(html.match(/aria-current="page"/g)).toHaveLength(1);
  expect(html).toMatch(/aria-current="page"[^>]*href="\/leaver-reviews"|href="\/leaver-reviews"[^>]*aria-current="page"/);
});

test("every navigation link leads to a page the console has", () => {
  const hrefs = navGroups({ administrator: true, auditor: true }).flatMap((g) => g.items.map((i) => i.href));
  expect(hrefs.length).toBeGreaterThan(0);
  for (const href of hrefs) {
    const page = fileURLToPath(new URL(`.${href === "/" ? "" : href}/page.tsx`, import.meta.url));
    expect(existsSync(page), `${href} has no page`).toBe(true);
  }
});

test("the Workforce links are shown to administrators only", () => {
  const hrefs = (administrator: boolean, auditor = false) =>
    navGroups({ administrator, auditor }).flatMap((g) => g.items.map((i) => i.href));
  expect(hrefs(false)).not.toContain("/agents");
  expect(hrefs(false)).not.toContain("/templates");
  expect(hrefs(true)).toEqual(expect.arrayContaining(["/agents", "/templates", "/people", "/policies"]));
  expect(hrefs(false)).not.toContain("/people");
  expect(hrefs(false, true)).not.toContain("/people");
  expect(hrefs(false, true)).not.toContain("/policies");
  // Each role brings its own group, and only its own.
  expect(hrefs(true)).not.toContain("/evidence");
  expect(hrefs(false, true)).toContain("/evidence");
  expect(hrefs(false, true)).not.toContain("/agents");
  pathname = "/agents/analyst-intern-hr-20418";
  const html = renderToStaticMarkup(<Nav roles={{ administrator: true, auditor: false }} />);
  expect(html).toMatch(/aria-current="page"[^>]*href="\/agents"|href="\/agents"[^>]*aria-current="page"/);
});

const access = (administrator: boolean, auditor = false) =>
  vi.fn(async () => jsonResponse(200, { administrator, auditor, catalogueApprover: false, gatewayAdministrator: false }));

test("signed out there is no navigation; signed in there is a way to sign out", async () => {
  vi.stubGlobal("fetch", access(true));
  const out = renderToStaticMarkup(await RootLayout({ children: <p>content</p> }));
  expect(out).not.toContain("<nav");
  expect(out).not.toContain("Sign out");
  expect(out).toContain("content");

  signInAs("r@example.invalid");
  const signedIn = renderToStaticMarkup(await RootLayout({ children: <p>content</p> }));
  expect(signedIn).toContain("<nav");
  expect(signedIn).toContain("r@example.invalid");
  expect(signedIn).toMatch(/<form[^>]*class="who"[\s\S]*<button type="submit" class="quiet">Sign out<\/button>/);
});

test("the layout asks the control plane which links to show, and hides them when it cannot say", async () => {
  signInAs("r@example.invalid");
  const fetch = access(true);
  vi.stubGlobal("fetch", fetch);
  expect(renderToStaticMarkup(await RootLayout({ children: null }))).toContain('href="/agents"');
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/console/access");
  vi.stubGlobal("fetch", access(false));
  expect(renderToStaticMarkup(await RootLayout({ children: null }))).not.toContain('href="/agents"');
  vi.stubGlobal("fetch", access(false, true));
  const auditor = renderToStaticMarkup(await RootLayout({ children: null }));
  expect(auditor).toContain('href="/evidence"');
  expect(auditor).not.toContain('href="/agents"');
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(500, { title: "Internal Server Error", status: 500 })));
  const failed = renderToStaticMarkup(await RootLayout({ children: null }));
  expect(failed).not.toContain('href="/agents"');
  expect(failed).toContain('href="/proposals"');
});

test("moments are written in UTC, the same for every reader", () => {
  expect(when("2026-11-07T10:00:00Z")).toBe("7 Nov 2026, 10:00 UTC");
  // An offset timestamp is still shown in UTC, on the UTC date.
  expect(when("2026-12-31T23:30:00-02:00")).toBe("1 Jan 2027, 01:30 UTC");
  expect(day("2026-11-25T10:00:00Z")).toBe("25 Nov 2026");
  expect(when(undefined)).toBe("");
  expect(when("not a date")).toBe("");
});

test("a status is respelt, never renamed, and an unknown one is shown neutrally", () => {
  expect(label("in-review")).toBe("In review");
  expect(label("checks-failed")).toBe("Checks failed");
  expect(decided("approve")).toBe("Approved");
  expect(decided("reject")).toBe("Rejected");
  expect(decided("escalate")).toBe("Escalate");
  expect(renderToStaticMarkup(<Pill value="in-review" />)).toBe('<span class="pill pill-wait">In review</span>');
  expect(renderToStaticMarkup(<Pill value="checks-failed" />)).toBe('<span class="pill pill-stop">Checks failed</span>');
  expect(renderToStaticMarkup(<Pill value="something-new" />)).toBe('<span class="pill">Something new</span>');
});

test("a form's button looks like what it does", () => {
  const action = async () => ({});
  const button = (tone?: "primary" | "quiet" | "danger") =>
    renderToStaticMarkup(
      <DecisionForm action={action} submit="Go" tone={tone}>
        <span />
      </DecisionForm>,
    ).match(/<button[^>]*>/)![0];
  expect(button()).toBe('<button type="submit">');
  expect(button("quiet")).toBe('<button type="submit" class="quiet">');
  expect(button("danger")).toBe('<button type="submit" class="danger">');
});

const proposal = (id: string, status: string, createdAt: string) => ({
  id,
  pack: "tax",
  contributor: "dev:a@example.invalid",
  summary: id,
  status,
  entries: [],
  checks: [],
  createdAt,
});

const review = (id: string, status: string, deadline: string) => ({
  id,
  person: "dev:a@example.invalid",
  status,
  deciderKind: "manager",
  deadline,
  kept: false,
  entryCount: 1,
  openedAt: "2026-10-26T10:00:00Z",
});

const request = (id: string, riskTier: string) => ({
  id,
  template: "t",
  version: 1,
  requestedBy: "dev:a@example.invalid",
  riskTier,
  neededApprovals: riskTier === "high" ? 2 : 1,
  state: "pending",
  approvals: [],
  createdAt: "2026-11-13T10:00:00Z",
});

test("home counts what waits and says what is due first", async () => {
  signInAs("r@example.invalid");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/proposals")) {
        return jsonResponse(200, {
          items: [
            proposal("p-1", "in-review", "2026-11-12T09:00:00Z"),
            // Earliest as a moment (22:00 UTC on the 9th) but not as text: sorting the strings
            // would pick the next line and say 10 Nov.
            proposal("p-2", "in-review", "2026-11-10T01:00:00+03:00"),
            proposal("p-0", "in-review", "2026-11-10T00:30:00Z"),
            proposal("p-3", "approved", "2026-11-01T09:00:00Z"),
          ],
        });
      }
      if (url.includes("/leaver-reviews")) {
        return jsonResponse(200, {
          items: [
            review("r-1", "open", "2026-12-02T10:00:00Z"),
            review("r-2", "open", "2026-11-28T09:00:00Z"),
            review("r-3", "closed", "2026-09-30T09:00:00Z"),
          ],
        });
      }
      return jsonResponse(200, { items: [request("c-1", "high"), request("c-2", "medium")] });
    }),
  );
  const html = renderToStaticMarkup(await Home());
  expect(html).toContain('<span class="queue-count">3</span>');
  // The oldest waiting proposal, not the oldest of all.
  expect(html).toContain("The oldest was created on 9 Nov 2026.");
  // Open reviews only, and the nearest deadline.
  expect(html).toContain('<span class="queue-count">2</span>');
  expect(html).toContain("The next deadline is 28 Nov 2026. Without a decision the entries are purged at the deadline.");
  expect(html).toContain("1 high risk, needing two approvers.");
});

test("home never turns an unread inbox into a number of items, nor calls every failure a refusal", async () => {
  signInAs("r@example.invalid");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/proposals")) return jsonResponse(200, { items: [] });
      if (url.includes("/leaver-reviews")) throw new Error("connection refused");
      return jsonResponse(403, { title: "Forbidden", status: 403, detail: "not an approver" });
    }),
  );
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  const html = renderToStaticMarkup(await Home());
  expect(html).toContain('<span class="queue-count">0</span>');
  expect(html).toContain("Nothing is waiting.");
  // The service's refusal and the console's own "unreachable" both show a status, never a count.
  expect(html).toContain('<span class="queue-count refused">403</span>');
  expect(html).toContain('<span class="queue-count refused">503</span>');
  expect(html.match(/This inbox could not be read\. Open it to see why\./g)).toHaveLength(2);
  expect(html).not.toContain("refused this inbox");
  expect(html).not.toContain("None is high risk.");
});

test("in a leaver review only the checkbox and title choose an entry; its body is not a label", async () => {
  signInAs("m@example.invalid");
  const entry = { id: "e-1", key: "k", type: "fact", title: "A title", body: "the body text", dataClass: "internal", contributor: "dev:a@example.invalid", createdAt: "2026-11-07T10:00:00Z" };
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(200, { ...review("r-1", "open", "2026-11-28T09:00:00Z"), entries: [entry] })));
  const html = renderToStaticMarkup(await LeaverReviewPage({ params: Promise.resolve({ id: "r-1" }) }));
  const label = html.match(/<label class="check">[\s\S]*?<\/label>/)![0];
  expect(label).toContain('name="entryIds" value="e-1"');
  expect(label).toContain("A title");
  expect(label).not.toContain("the body text");
  expect(html).toContain("the body text");
});
