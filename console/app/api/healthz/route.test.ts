import { expect, test } from "vitest";

import { GET } from "./route";

test("healthz reports ok", async () => {
  const response = GET();

  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ status: "ok", service: "console" });
});
