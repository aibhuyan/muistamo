import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@\//, replacement: here("./").replaceAll("\\", "/") },
      // server-only throws outside a React Server Components build; tests import server modules directly.
      { find: /^server-only$/, replacement: here("./test/server-only.ts") },
    ],
  },
  test: {
    environment: "node",
  },
});
