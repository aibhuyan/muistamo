"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

// The console's navigation. Only screens that exist are listed: a link never promises a page the
// services cannot back.
export const NAV_GROUPS: { label: string | null; items: { href: string; name: string }[] }[] = [
  { label: null, items: [{ href: "/", name: "Home" }] },
  {
    label: "Your work",
    items: [
      { href: "/proposals", name: "Knowledge proposals" },
      { href: "/leaver-reviews", name: "Leaver reviews" },
      { href: "/catalogue", name: "Catalogue requests" },
      { href: "/my-knowledge", name: "My knowledge" },
    ],
  },
];

// A link is current on its own page and on the pages beneath it; Home only on "/".
export function isCurrent(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/");
}

export function Nav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Console">
      {NAV_GROUPS.map((group) => (
        <div key={group.label ?? "home"} className="nav-group">
          {group.label ? <div className="nav-label">{group.label}</div> : null}
          {group.items.map((item) => (
            <Link key={item.href} href={item.href} aria-current={isCurrent(pathname, item.href) ? "page" : undefined}>
              {item.name}
            </Link>
          ))}
        </div>
      ))}
    </nav>
  );
}
