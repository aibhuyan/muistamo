import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, test, vi } from "vitest";

import { reset } from "@/test/next";

vi.mock("next/headers", async () => ({ cookies: (await import("@/test/next")).cookies }));
vi.mock("next/navigation", async () => ({ redirect: (await import("@/test/next")).redirect }));
vi.mock("next/server", async () => ({ connection: (await import("@/test/next")).connection }));

const { Refusal } = await import("./refusal");
const { default: SignInPage } = await import("./sign-in/page");

beforeEach(reset);

test("a refusal shows the service's title and detail", () => {
  const html = renderToStaticMarkup(
    <Refusal problem={{ title: "Forbidden", status: 403, detail: "the proposer cannot decide this proposal" }} />,
  );
  expect(html).toContain('role="alert"');
  expect(html).toContain("403 Forbidden");
  expect(html).toContain("the proposer cannot decide this proposal");
});

test("without the development flag the sign-in page offers no sign-in", async () => {
  vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "");
  const html = renderToStaticMarkup(await SignInPage());
  expect(html).toContain("No authentication configured");
  expect(html).not.toContain("<form");
});

test("with the development flag it does", async () => {
  const html = renderToStaticMarkup(await SignInPage());
  expect(html).toContain("<form");
  expect(html).toContain('name="tenant"');
});
