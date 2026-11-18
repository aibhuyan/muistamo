import Link from "next/link";

// Shared pieces of the management pages (D70): Workforce and the evidence log.

// The service's paging cursor from the page's query, or none. Only a single string is a cursor.
export function cursorParam(query: Record<string, string | string[] | undefined> | undefined): string | undefined {
  const value = query?.cursor;
  return typeof value === "string" && value !== "" ? value : undefined;
}

// A position in the evidence chain from the address: a whole number of events to skip, or the
// start. Anything else is the start.
export function afterParam(query: Record<string, string | string[] | undefined> | undefined): number {
  const value = query?.after;
  return typeof value === "string" && /^(0|[1-9][0-9]{0,14})$/.test(value) ? Number(value) : 0;
}

// Who an agent acts for, by kind only. Which person, team or service it is stays off these pages
// until it is decided how a person's identifier is shown here (docs/console-management-plan.md).
export function bindingKind(type: "user" | "team" | "service"): string {
  return { user: "A person", team: "A team", service: "A service" }[type] ?? type;
}

// The HR ids the console links a person by: the control plane admits only these from the console
// (api.consolePersonID). Others are shown as text, unlinked. None of these characters is escaped
// in a URL, and the control plane refuses an escaped path from the console.
const PERSON_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;

export function personHref(personId: string): string | undefined {
  return PERSON_ID.test(personId) ? `/people/${encodeURIComponent(personId)}` : undefined;
}

// Forward paging, as the service pages: back to the first page, or on to the next.
export function Pager({ path, cursor, nextCursor }: { path: string; cursor?: string; nextCursor?: string }) {
  if (!cursor && !nextCursor) return null;
  return (
    <nav aria-label="Pages" className="pager">
      {cursor ? <Link href={path}>First page</Link> : null}
      {nextCursor ? <Link href={`${path}?cursor=${encodeURIComponent(nextCursor)}`}>Next page</Link> : null}
    </nav>
  );
}
