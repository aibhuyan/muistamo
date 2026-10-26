import { vi } from "vitest";

// Stand-ins for next/headers and next/navigation. Each test file wires them up with vi.mock.

export const cookieJar = new Map<string, { value: string; options?: Record<string, unknown> }>();

export const cookies = vi.fn(async () => ({
  get: (name: string) => (cookieJar.has(name) ? { name, value: cookieJar.get(name)!.value } : undefined),
  set: (name: string, value: string, options?: Record<string, unknown>) => {
    cookieJar.set(name, { value, options });
  },
  delete: (name: string) => {
    cookieJar.delete(name);
  },
}));

export class Redirect extends Error {
  constructor(public readonly to: string) {
    super(`redirect to ${to}`);
  }
}

export const redirect = vi.fn((to: string): never => {
  throw new Redirect(to);
});

export const revalidatePath = vi.fn();

export const connection = vi.fn(async () => {});

export const TENANT = "11111111-2222-4333-8444-555555555555";

export function signInAs(person: string, tenant = TENANT) {
  cookieJar.set("muistamo_dev_session", { value: JSON.stringify({ tenant, person }) });
}

export function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

export function reset() {
  cookieJar.clear();
  cookies.mockClear();
  redirect.mockClear();
  revalidatePath.mockClear();
  connection.mockClear();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.stubEnv("MUISTAMO_CONSOLE_INSECURE_DEV_LOGIN", "true");
  vi.stubEnv("MUISTAMO_CONTROL_PLANE_URL", "http://control-plane.test");
  vi.stubEnv("MUISTAMO_KNOWLEDGE_URL", "http://knowledge.test/");
}
