import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, test, vi } from "vitest";

import { Redirect, jsonResponse, reset, signInAs } from "@/test/next";

class NotFound extends Error {}

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({
  redirect: (await import("@/test/next")).redirect,
  notFound: () => {
    throw new NotFound("not found");
  },
}));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));

const { default: EvidencePage } = await import("./evidence/page");
const { default: EvidenceEventPage } = await import("./evidence/[seq]/page");
const { afterParam } = await import("./workforce");

beforeEach(reset);

const event = (seq: number, extra: Record<string, unknown> = {}) => ({
  tenant: "11111111-2222-4333-8444-555555555555",
  seq,
  occurredAt: "2026-11-11T16:02:00Z",
  actor: "hris:11111111-2222-4333-8444-555555555555",
  action: "hr.event.received",
  subject: { kind: "HRPerson", name: "HR-77031" },
  before: null,
  after: { type: "leaver", person: { email: "person-a@example.invalid" } },
  requestId: "req-1",
  prevHash: "a".repeat(64),
  hash: "b".repeat(64),
  keyId: "c".repeat(32),
  signature: "c2lnbmF0dXJl",
  ...extra,
});

const query = (q: Record<string, string>) => ({ searchParams: Promise.resolve(q) });
const params = (seq: string) => ({ params: Promise.resolve({ seq }) });

test.each([
  ["the evidence log", () => EvidencePage(query({}))],
  ["an event", () => EvidenceEventPage(params("7"))],
])("%s without a session goes to sign-in and calls no service", async (_name, render) => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(render()).rejects.toEqual(new Redirect("/sign-in"));
  expect(fetch).not.toHaveBeenCalled();
});

test.each([
  ["the evidence log", () => EvidencePage(query({}))],
  ["an event", () => EvidenceEventPage(params("7"))],
])("%s shows the control plane's refusal instead of the chain", async (_name, render) => {
  signInAs("r@example.invalid");
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => jsonResponse(403, { title: "Forbidden", status: 403, detail: "only console auditors can read the evidence log" })),
  );
  const html = renderToStaticMarkup((await render()) as React.ReactElement);
  expect(html).toContain("only console auditors can read the evidence log");
  expect(html).not.toContain("hr.event.received");
});

test("the log reads the chain in order, links each event and pages on", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn(async () => jsonResponse(200, { items: [event(41), event(42)], nextAfterSeq: 90 }));
  vi.stubGlobal("fetch", fetch);
  const html = renderToStaticMarkup(await EvidencePage(query({ after: "40" })));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/events?afterSeq=40&limit=50");
  expect(html).toContain('href="/evidence/41"');
  expect(html).toContain('href="/evidence/42"');
  expect(html).toContain("hr.event.received");
  expect(html).toContain('href="/evidence?after=90"');
  expect(html).toContain('href="/evidence">First page');
  // The list shows no recorded contents, and a subject by its kind only: its name can be an HR id.
  expect(html).not.toContain("person-a@example.invalid");
  expect(html).toContain("HRPerson");
  expect(html).not.toContain("HR-77031");
});

// The page never vouches for the chain: it says how to verify it with a key the reader holds.
test("the log gives no verdict and says how to verify the chain independently", async () => {
  signInAs("r@example.invalid");
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(200, { items: [event(1, { prevHash: "0".repeat(64) })] })));
  const html = renderToStaticMarkup(await EvidencePage(query({})));
  // The commands as mst accepts them (cli/cmd/mst/evidence.go): -o and --public-key are required.
  expect(html).toContain("mst evidence export -o chain.jsonl --tenant TENANT --actor YOU");
  expect(html).toContain("mst evidence verify -f chain.jsonl --public-key signing-key.pub");
  expect(html).toContain("mst evidence export --knowledge -o knowledge.jsonl");
  expect(html).toContain("does not vouch for it");
  expect(html).toContain("The knowledge service keeps its own chain");
  // What verifying cannot show is said, and nothing claims more.
  expect(html).toContain("it cannot show that the newest events were not removed");
  expect(html).toContain("in production your operator runs the export");
  for (const claim of [/\bverified\b/i, /chain verifies/i, /intact/i, /\bvalid\b/i, /without trusting/i, /cannot be removed/i]) {
    expect(html).not.toMatch(claim);
  }
});

test("an address position that is not a whole number starts at the beginning", () => {
  expect(afterParam({ after: "40" })).toBe(40);
  for (const bad of ["-1", "4.5", "04", "abc", "", "9".repeat(16)]) {
    expect(afterParam({ after: bad }), bad).toBe(0);
  }
  expect(afterParam({ after: ["1", "2"] })).toBe(0);
  expect(afterParam(undefined)).toBe(0);
});

test("an event page shows the event exactly as recorded", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn(async () => jsonResponse(200, { items: [event(7)] }));
  vi.stubGlobal("fetch", fetch);
  const html = renderToStaticMarkup(await EvidenceEventPage(params("7")));
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe("http://control-plane.test/v1/events?afterSeq=6&limit=1");
  expect(html).toContain("b".repeat(64));
  expect(html).toContain('href="/evidence/6"');
  expect(html).toContain("&quot;person-a@example.invalid&quot;");
  // The event's own page names its subject.
  expect(html).toContain("HR-77031");
  expect(html).toContain("None");
});

test("an event page refuses a number that is not an event, and an event that is not there", async () => {
  signInAs("r@example.invalid");
  const fetch = vi.fn(async () => jsonResponse(200, { items: [] }));
  vi.stubGlobal("fetch", fetch);
  for (const bad of ["0", "-3", "abc", "7.5", "07"]) {
    await expect(EvidenceEventPage(params(bad)), bad).rejects.toBeInstanceOf(NotFound);
  }
  expect(fetch).not.toHaveBeenCalled();
  await expect(EvidenceEventPage(params("9"))).rejects.toBeInstanceOf(NotFound);
  // The service answered with a later event: not the one asked for.
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(200, { items: [event(12)] })));
  await expect(EvidenceEventPage(params("9"))).rejects.toBeInstanceOf(NotFound);
});
