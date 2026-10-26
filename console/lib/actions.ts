import type { Problem } from "./api";

// What a decision form shows after a Server Action: nothing yet, or the service's refusal.
export type ActionState = { problem?: Problem };

export const initialActionState: ActionState = {};

export function field(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value.trim() : "";
}

export function invalid(title: string): ActionState {
  return { problem: { title, status: 422 } };
}

// A dynamic route segment as the service knows it. Next may hand it over still percent-encoded
// (leaver review ids contain ":"), and the API layer encodes it again, so decode it exactly once.
export function routeParam(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}
