import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { Redirect, jsonResponse, reset, signInAs } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({ redirect: (await import("@/test/next")).redirect }));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));
vi.mock("next/cache", async () => ({ revalidatePath: (await import("@/test/next")).revalidatePath }));

const { default: Home } = await import("./page");
const { default: ProposalsPage } = await import("./proposals/page");
const { default: ProposalPage } = await import("./proposals/[id]/page");
const { default: LeaverReviewsPage } = await import("./leaver-reviews/page");
const { default: LeaverReviewPage } = await import("./leaver-reviews/[id]/page");
const { default: CataloguePage } = await import("./catalogue/page");

const params = (id: string) => ({ params: Promise.resolve({ id }) });

const pages: [string, () => Promise<unknown>][] = [
  ["home", () => Home()],
  ["proposals", () => ProposalsPage()],
  ["a proposal", () => ProposalPage(params("p-1"))],
  ["leaver reviews", () => LeaverReviewsPage()],
  ["a leaver review", () => LeaverReviewPage(params("r-1"))],
  ["catalogue", () => CataloguePage()],
];

beforeEach(reset);

describe.each(pages)("the %s page", (_name, render) => {
  test("without a session goes to sign-in and calls no service", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(render()).rejects.toEqual(new Redirect("/sign-in"));
    expect(fetch).not.toHaveBeenCalled();
  });

  test("without the development flag ignores a valid cookie", async () => {
    signInAs("r@example.invalid");
    vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "");
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(render()).rejects.toEqual(new Redirect("/sign-in"));
    expect(fetch).not.toHaveBeenCalled();
  });
});

const review = {
  id: "leaver-t-P-77:01a1",
  person: "dev:a@example.invalid",
  status: "open",
  deciderKind: "manager",
  deadline: "2026-11-25T10:00:00Z",
  kept: false,
  entryCount: 1,
  openedAt: "2026-10-26T10:00:00Z",
};

test("the leaver list links to each review by its encoded id", async () => {
  signInAs("m@example.invalid");
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(200, { items: [review] })));
  const html = renderToStaticMarkup(await LeaverReviewsPage());
  expect(html).toContain('href="/leaver-reviews/leaver-t-P-77%3A01a1"');
});

test("a leaver review is fetched by its decoded id, encoded once for the service", async () => {
  signInAs("m@example.invalid");
  const fetch = vi.fn(async () => jsonResponse(200, { ...review, entries: [] }));
  vi.stubGlobal("fetch", fetch);
  renderToStaticMarkup(await LeaverReviewPage(params("leaver-t-P-77%3A01a1")));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe(
    "http://knowledge.test/v1/knowledge/leaver-reviews/leaver-t-P-77%3A01a1",
  );
});

test("a page shows the service's refusal instead of the data", async () => {
  signInAs("r@example.invalid");
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => jsonResponse(403, { title: "Forbidden", status: 403, detail: "only its decider reads a review" })),
  );
  const html = renderToStaticMarkup(await LeaverReviewPage(params("r-1")));
  expect(html).toContain("403 Forbidden");
  expect(html).toContain("only its decider reads a review");
  expect(html).not.toContain("<form");
});
