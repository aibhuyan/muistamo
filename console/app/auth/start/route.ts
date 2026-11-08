import { cookies } from "next/headers";
import { type NextRequest, NextResponse } from "next/server";

import { entraConfig, mode } from "@/lib/entra/config";
import { writeTransaction } from "@/lib/entra/cookies";
import { startSignIn } from "@/lib/entra/flow";

// HUMAN REVIEW REQUIRED (AGENTS.md): sign-in. Starts the OpenID Connect flow for one configured
// tenant: the tenant is chosen only from configuration (by id, or the only one), never as an
// authority from user input, and the sign-in transaction is sealed in its own cookie.

export async function GET(request: NextRequest): Promise<Response> {
  if (mode() !== "entra") return new Response("Entra sign-in is not configured", { status: 404 });
  const { tenants } = entraConfig();
  const asked = request.nextUrl.searchParams.get("tenant");
  const tenant = asked ? tenants.find((t) => t.tenant === asked) : tenants.length === 1 ? tenants[0] : undefined;
  if (!tenant) return NextResponse.redirect(new URL("/sign-in", entraConfig().publicUrl), 303);
  try {
    const { url, txn } = await startSignIn(tenant);
    writeTransaction(await cookies(), txn);
    return NextResponse.redirect(url, 303);
  } catch (error) {
    console.error(
      JSON.stringify({
        level: "ERROR",
        msg: "sign-in could not start",
        tenant: tenant.tenant,
        error: error instanceof Error ? error.name : "unknown",
      }),
    );
    return new Response("Sign-in is unavailable; try again shortly.", { status: 503 });
  }
}
