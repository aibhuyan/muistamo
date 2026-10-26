import { expect, test } from "vitest";

import { routeParam } from "./actions";

test("a route segment is decoded exactly once", () => {
  expect(routeParam("leaver-t-P-77%3A01a1")).toBe("leaver-t-P-77:01a1");
  expect(routeParam("leaver-t-P-77:01a1")).toBe("leaver-t-P-77:01a1");
  expect(routeParam("%253A")).toBe("%3A");
  expect(routeParam("%E0%A4%A")).toBe("%E0%A4%A");
});
