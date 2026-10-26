import "./globals.css";

import Link from "next/link";
import type { ReactNode } from "react";

import { getSession } from "@/lib/session";

import { signOut } from "./sign-in/actions";

export const metadata = { title: "Muistamo" };

export default async function RootLayout({ children }: { children: ReactNode }) {
  const session = await getSession();
  return (
    <html lang="en">
      <body>
        <header>
          <Link href="/" className="brand">
            Muistamo
          </Link>
          {session ? (
            <>
              <nav>
                <Link href="/proposals">Proposals</Link>
                <Link href="/leaver-reviews">Leaver reviews</Link>
                <Link href="/catalogue">Catalogue</Link>
              </nav>
              <form action={signOut} className="who">
                <span>
                  {session.person} · <code>{session.tenant}</code>
                </span>
                <button type="submit">Sign out</button>
              </form>
            </>
          ) : null}
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
