import Link from "next/link";

// Shared pieces of the Workforce pages (agents and templates, D70).

// The service's paging cursor from the page's query, or none. Only a single string is a cursor.
export function cursorParam(query: Record<string, string | string[] | undefined> | undefined): string | undefined {
  const value = query?.cursor;
  return typeof value === "string" && value !== "" ? value : undefined;
}

// Who an agent acts for, by kind only. Which person, team or service it is stays off these pages
// until it is decided how a person's identifier is shown here (docs/console-management-plan.md).
export function bindingKind(type: "user" | "team" | "service"): string {
  return { user: "A person", team: "A team", service: "A service" }[type] ?? type;
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
