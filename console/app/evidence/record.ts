// Personal data on the evidence pages (D70; security review 2026-11-21). Evidence is never
// rewritten, not even after an erasure, so a recorded event can still hold a person's email
// address (an agent's binding, a sponsor, a development caller's name). The console shows auditors
// what happened without it: every email address is hidden. The exact signed form stays in the
// operator's export, which is what verification uses.

// An email address anywhere in a string: local part, @, a domain with a dot.
const EMAIL = /[^\s@"'<>(),;:]+@[^\s@"'<>(),;:]+\.[^\s@"'<>(),;:]+/g;

export const HIDDEN = "[email address hidden]";

// The string with each email address in it replaced.
export function hideEmails(text: string): string {
  return text.replace(EMAIL, HIDDEN);
}

// A recorded value with every email address in its strings (and its keys) hidden.
export function withoutEmails(value: unknown): unknown {
  if (typeof value === "string") return hideEmails(value);
  if (Array.isArray(value)) return value.map(withoutEmails);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [hideEmails(k), withoutEmails(v)]));
  }
  return value;
}
