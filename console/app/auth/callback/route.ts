import { cookies } from "next/headers";
import type { NextRequest } from "next/server";

import { SignInError } from "@/lib/entra/claims";
import { entraConfig, mode, tenantConfig } from "@/lib/entra/config";
import { TXN_COOKIE, clearSession, clearTransaction, writeSession } from "@/lib/entra/cookies";
import { finishSignIn, readTransaction } from "@/lib/entra/flow";

// HUMAN REVIEW REQUIRED (AGENTS.md): sign-in. The redirect back from Entra. The transaction cookie
// is deleted on first use, success or not, so a callback is never replayed; the tenant comes from
// that cookie only, never from the query. Nothing secret is logged. The session cookie is
// SameSite=Strict, so it is not sent on this cross-site navigation: an HTML page hands over to the
// console's own origin.

function page(status: number, title: string, body: string): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title></head><body><h1>${title}</h1><p>${body}</p></body></html>`;
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
  });
}

export async function GET(request: NextRequest): Promise<Response> {
  if (mode() !== "entra") return new Response("Entra sign-in is not configured", { status: 404 });
  const requestId = crypto.randomUUID();
  const store = await cookies();
  const sealed = store.get(TXN_COOKIE)?.value;
  clearTransaction(store);
  const txn = await readTransaction(sealed);
  const t = txn && typeof txn.tenant === "string" ? tenantConfig(txn.tenant) : null;
  const again = '<a href="/sign-in">Sign in again</a>.';
  if (!txn || !t) return page(400, "Sign-in expired", `The sign-in took too long or was already used. ${again}`);
  // The URL the browser was sent to, on the console's configured public origin.
  const callback = new URL(request.nextUrl.pathname + request.nextUrl.search, entraConfig().publicUrl);
  try {
    const session = await finishSignIn(t, txn, callback);
    clearSession(store);
    if (!(await writeSession(store, session))) {
      return page(500, "Sign-in failed", `Your session is too large for this console. ${again}`);
    }
    console.info(
      JSON.stringify({ level: "INFO", msg: "signed in", tenant: t.tenant, person: session.person, requestId }),
    );
    return page(200, "Signed in", 'Continue to <a href="/">the console</a>.');
  } catch (error) {
    const reason = error instanceof SignInError ? error.message : "the sign-in could not be completed";
    console.warn(
      JSON.stringify({
        level: "WARN",
        msg: "sign-in refused",
        tenant: t.tenant,
        requestId,
        reason,
        // The OAuth error code only (for example access_denied), never a description or a token.
        error: (error as { error?: unknown })?.error ?? (error instanceof Error ? error.name : "unknown"),
      }),
    );
    return page(403, "Sign-in refused", `${reason.charAt(0).toUpperCase() + reason.slice(1)}. ${again}`);
  }
}
