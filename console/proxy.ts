import { type NextRequest, NextResponse } from "next/server";

import { mode, tenantConfig } from "@/lib/entra/config";
import { type CookieStore, clearSession, readSession, writeSession } from "@/lib/entra/cookies";
import { REFRESH_BEFORE_MS, type Session, grantRevoked, refreshSession } from "@/lib/entra/flow";

// HUMAN REVIEW REQUIRED (AGENTS.md): token handling. Pages can read cookies but not set them, so
// the access token is renewed here, before pages and Server Actions run (both are matched). The
// renewed cookie is written to the response and passed to the same render. One renewal per
// session at a time in this process; a revoked grant ends the session; any other failure refuses
// the request rather than continue on a token about to expire.

const inFlight = new Map<string, Promise<Session>>();

function renew(t: NonNullable<ReturnType<typeof tenantConfig>>, s: Session): Promise<Session> {
  let p = inFlight.get(s.sid);
  if (!p) {
    p = refreshSession(t, s).finally(() => inFlight.delete(s.sid));
    inFlight.set(s.sid, p);
  }
  return p;
}

export async function proxy(request: NextRequest): Promise<NextResponse> {
  if (mode() !== "entra") return NextResponse.next();
  const session = await readSession(request.cookies as unknown as CookieStore);
  if (!session || session.atExp - Date.now() > REFRESH_BEFORE_MS) return NextResponse.next();
  const t = tenantConfig(session.tenant);
  if (!t) return NextResponse.next();
  let renewed: Session;
  try {
    renewed = await renew(t, session);
  } catch (error) {
    if (grantRevoked(error)) {
      // Signed in no more (for example the account was disabled): the pages redirect to sign in.
      clearSession(request.cookies as unknown as CookieStore);
      const response = NextResponse.next({ request: { headers: request.headers } });
      clearSession(response.cookies as unknown as CookieStore);
      console.warn(JSON.stringify({ level: "WARN", msg: "session ended: grant refused", tenant: t.tenant, person: session.person }));
      return response;
    }
    console.error(
      JSON.stringify({
        level: "ERROR",
        msg: "session renewal failed",
        tenant: t.tenant,
        person: session.person,
        error: error instanceof Error ? error.name : "unknown",
      }),
    );
    return new NextResponse("Your session could not be renewed; try again shortly.", { status: 503 });
  }
  // The renewed cookie, for this render (request) and for the browser (response).
  await writeSession(request.cookies as unknown as CookieStore, renewed);
  const response = NextResponse.next({ request: { headers: request.headers } });
  if (!(await writeSession(response.cookies as unknown as CookieStore, renewed))) {
    clearSession(response.cookies as unknown as CookieStore);
  }
  return response;
}

export const config = {
  // Pages and Server Actions; never static assets, the sign-in routes or the health check.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|auth/|api/healthz).*)"],
};
