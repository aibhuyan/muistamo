"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

type NavGroup = { label: string | null; items: { href: string; name: string }[] };

export type Roles = { administrator: boolean; auditor: boolean };

const NONE: Roles = { administrator: false, auditor: false };

// The console's navigation. Only screens that exist are listed: a link never promises a page the
// services cannot back. Workforce is shown to console administrators and Governance to auditors;
// showing a link is a convenience, not a permission: the control plane decides every read itself.
export function navGroups({ administrator, auditor }: Roles = NONE): NavGroup[] {
  const groups: NavGroup[] = [
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
  if (administrator) {
    groups.push({
      label: "Workforce",
      items: [
        { href: "/agents", name: "Agents" },
        { href: "/templates", name: "Templates" },
      ],
    });
  }
  if (auditor) {
    groups.push({ label: "Governance", items: [{ href: "/evidence", name: "Evidence log" }] });
  }
  return groups;
}

// A link is current on its own page and on the pages beneath it; Home only on "/".
export function isCurrent(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/");
}

export function Nav({ roles = NONE }: { roles?: Roles }) {
  const pathname = usePathname();
  return (
    <nav aria-label="Console">
      {navGroups(roles).map((group) => (
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
