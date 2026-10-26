import { beforeEach, describe, expect, test, vi } from "vitest";

import { Redirect, TENANT, cookieJar, jsonResponse, reset, revalidatePath, signInAs } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({ redirect: (await import("@/test/next")).redirect }));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));
vi.mock("next/cache", async () => ({ revalidatePath: (await import("@/test/next")).revalidatePath }));

const { decideProposal } = await import("./proposals/actions");
const { decideLeaverReview } = await import("./leaver-reviews/actions");
const { decideCatalogueRequest } = await import("./catalogue/actions");
const { signIn, signOut } = await import("./sign-in/actions");

function form(fields: Record<string, string | string[]>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) {
    for (const v of Array.isArray(value) ? value : [value]) data.append(name, v);
  }
  return data;
}

function stubFetch(status = 200, body: unknown = {}) {
  const fetch = vi.fn(async () => jsonResponse(status, body));
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

function sent(fetch: ReturnType<typeof stubFetch>) {
  const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
  return { url, body: JSON.parse(init.body as string), headers: init.headers as Record<string, string> };
}

beforeEach(reset);

const decisions = [
  {
    name: "proposal",
    run: (data: FormData) => decideProposal("p-1", {}, data),
    fields: { decision: "approve", reason: "good" },
    url: "http://knowledge.test/v1/knowledge/proposals/p-1/decision",
    body: { decision: "approve", reason: "good" },
    after: "/proposals",
  },
  {
    name: "leaver review",
    run: (data: FormData) => decideLeaverReview("r-1", {}, data),
    fields: { decision: "keep", reason: "needs a closer look" },
    url: "http://knowledge.test/v1/knowledge/leaver-reviews/r-1/decision",
    body: { decision: "keep", reason: "needs a closer look" },
    after: "/leaver-reviews",
  },
  {
    name: "catalogue request",
    run: (data: FormData) => decideCatalogueRequest("c-1", {}, data),
    fields: { decision: "reject", reason: "too broad" },
    url: "http://control-plane.test/v1/catalogue/requests/c-1/decision",
    body: { decision: "reject", reason: "too broad" },
    after: "/catalogue",
  },
];

describe.each(decisions)("deciding a $name", ({ run, fields, url, body, after }) => {
  test("without a session it is sent to sign-in and calls nothing", async () => {
    const fetch = stubFetch();
    await expect(run(form(fields))).rejects.toEqual(new Redirect("/sign-in"));
    expect(fetch).not.toHaveBeenCalled();
  });

  test("without the development flag a stale cookie calls nothing", async () => {
    signInAs("d@example.invalid");
    vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "");
    const fetch = stubFetch();
    await expect(run(form(fields))).rejects.toEqual(new Redirect("/sign-in"));
    expect(fetch).not.toHaveBeenCalled();
  });

  test("it sends the decision as the signed-in person", async () => {
    signInAs("d@example.invalid");
    const fetch = stubFetch();
    await expect(run(form(fields))).rejects.toEqual(new Redirect(after));
    const call = sent(fetch);
    expect(call.url).toBe(url);
    expect(call.body).toEqual(body);
    expect(call.headers["X-Muistamo-Actor"]).toBe("d@example.invalid");
    expect(call.headers["X-Muistamo-Tenant"]).toBe(TENANT);
    expect(revalidatePath).toHaveBeenCalledWith(after);
  });

  test("a refusal is returned for the form to show, and nothing is revalidated", async () => {
    signInAs("d@example.invalid");
    stubFetch(403, { title: "Forbidden", status: 403, detail: "not yours to decide" });
    expect(await run(form(fields))).toEqual({
      problem: { title: "Forbidden", status: 403, detail: "not yours to decide" },
    });
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  test("an unknown decision is not sent", async () => {
    signInAs("d@example.invalid");
    const fetch = stubFetch();
    const result = await run(form({ ...fields, decision: "escalate" }));
    expect(result.problem?.status).toBe(422);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("leaver review merge", () => {
  test("sends the chosen entries, pack and summary", async () => {
    signInAs("m@example.invalid");
    const fetch = stubFetch();
    await expect(
      decideLeaverReview(
        "r-1",
        {},
        form({ decision: "merge", reason: "keep the runbook", pack: "ops", summary: "runbook", entryIds: ["e1", "e2"] }),
      ),
    ).rejects.toEqual(new Redirect("/leaver-reviews"));
    expect(sent(fetch).body).toEqual({
      decision: "merge",
      reason: "keep the runbook",
      pack: "ops",
      summary: "runbook",
      entryIds: ["e1", "e2"],
    });
  });

  test("keep and purge never carry merge fields, even when the form has them", async () => {
    signInAs("m@example.invalid");
    const fetch = stubFetch();
    await expect(
      decideLeaverReview("r-1", {}, form({ decision: "purge", reason: "r", pack: "ops", summary: "s", entryIds: "e1" })),
    ).rejects.toBeInstanceOf(Redirect);
    expect(sent(fetch).body).toEqual({ decision: "purge", reason: "r" });
  });

  test("a merge without entries is not sent", async () => {
    signInAs("m@example.invalid");
    const fetch = stubFetch();
    const result = await decideLeaverReview("r-1", {}, form({ decision: "merge", reason: "r", pack: "ops", summary: "s" }));
    expect(result.problem?.status).toBe(422);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("sign-in", () => {
  test("starts a session and goes home", async () => {
    await expect(signIn({}, form({ tenant: TENANT.toUpperCase(), person: " r@example.invalid " }))).rejects.toEqual(
      new Redirect("/"),
    );
    expect(JSON.parse(cookieJar.get("muistamo_dev_session")!.value)).toEqual({
      tenant: TENANT,
      person: "r@example.invalid",
    });
  });

  test("refuses malformed input", async () => {
    expect((await signIn({}, form({ tenant: "acme", person: "r@example.invalid" }))).problem?.status).toBe(422);
    expect(cookieJar.size).toBe(0);
  });

  test("refuses entirely without the development flag", async () => {
    vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "false");
    expect((await signIn({}, form({ tenant: TENANT, person: "r@example.invalid" }))).problem?.status).toBe(403);
    expect(cookieJar.size).toBe(0);
  });

  test("signing out removes the session", async () => {
    signInAs("r@example.invalid");
    await expect(signOut()).rejects.toEqual(new Redirect("/sign-in"));
    expect(cookieJar.size).toBe(0);
  });
});
