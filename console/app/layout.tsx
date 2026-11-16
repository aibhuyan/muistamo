import "./globals.css";

import Link from "next/link";
import type { ReactNode } from "react";

import { getSession } from "@/lib/session";

import { Nav } from "./nav";
import { signOut } from "./sign-in/actions";

export const metadata = { title: "Muistamo" };

function Brand() {
  return (
    <Link href="/" className="brand">
      <svg aria-hidden="true" width="22" height="22" viewBox="0 0 22 22" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
        <path d="M4 6h14M4 11h14M4 16h8" />
        <circle cx="16.5" cy="16" r="1.6" fill="currentColor" stroke="none" />
      </svg>
      Muistamo
    </Link>
  );
}

export default async function RootLayout({ children }: { children: ReactNode }) {
  const session = await getSession();
  return (
    <html lang="en">
      <body>
        {session ? (
          <div className="shell">
            <div className="rail">
              <Brand />
              <Nav />
              <form action={signOut} className="who">
                <span className="who-name">{session.name ?? session.person}</span>
                <code className="who-tenant">{session.tenant}</code>
                <button type="submit" className="quiet">
                  Sign out
                </button>
              </form>
            </div>
            <main className="content">{children}</main>
          </div>
        ) : (
          <main className="solo">{children}</main>
        )}
      </body>
    </html>
  );
}
