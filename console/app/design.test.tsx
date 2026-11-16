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

const { Nav, NAV_GROUPS, isCurrent } = await import("./nav");
const { Pill, day, decided, label, when } = await import("./entry");
const { default: Home } = await import("./page");

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

test("the navigation lists only screens the console has", () => {
  const hrefs = NAV_GROUPS.flatMap((g) => g.items.map((i) => i.href));
  expect(hrefs).toEqual(["/", "/proposals", "/leaver-reviews", "/catalogue", "/my-knowledge"]);
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

test("home counts what waits and never turns a refusal into a number of items", async () => {
  signInAs("r@example.invalid");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/proposals")) {
        return jsonResponse(200, {
          items: [
            proposal("p-1", "in-review", "2026-11-12T09:00:00Z"),
            proposal("p-2", "in-review", "2026-11-09T09:00:00Z"),
            proposal("p-3", "approved", "2026-11-01T09:00:00Z"),
          ],
        });
      }
      if (url.includes("/leaver-reviews")) return jsonResponse(200, { items: [] });
      return jsonResponse(403, { title: "Forbidden", status: 403, detail: "not an approver" });
    }),
  );
  const html = renderToStaticMarkup(await Home());
  expect(html).toContain('<span class="queue-count">2</span>');
  // The oldest waiting proposal, not the oldest of all.
  expect(html).toContain("The oldest was created on 9 Nov 2026.");
  expect(html).toContain('<span class="queue-count">0</span>');
  expect(html).toContain("Nothing is waiting.");
  expect(html).toContain('<span class="queue-count refused">403</span>');
  expect(html).toContain("The service refused this inbox. Open it to read why.");
  expect(html).not.toContain("None is high risk.");
});
