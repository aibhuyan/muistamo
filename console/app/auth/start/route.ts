import { cookies } from "next/headers";
import { type NextRequest, NextResponse } from "next/server";

import { entraConfig, mode } from "@/lib/entra/config";
import { writeTransaction } from "@/lib/entra/cookies";
import { startSignIn } from "@/lib/entra/flow";

// HUMAN REVIEW REQUIRED (AGENTS.md): sign-in. Starts the OpenID Connect flow for one configured
// tenant: chosen only from configuration (by id or name, or the only one), never as an authority
// from user input. Only a POST from the console's own sign-in page starts it: a link on another
// site cannot set off a silent sign-in. The sign-in transaction is sealed in its own cookie.

function sameOrigin(request: NextRequest): boolean {
  const site = request.headers.get("sec-fetch-site");
  if (site) return site === "same-origin";
  return request.headers.get("origin") === entraConfig().publicUrl.origin;
}

export async function GET(): Promise<Response> {
  if (mode() !== "entra") return new Response("Entra sign-in is not configured", { status: 404 });
  return NextResponse.redirect(new URL("/sign-in", entraConfig().publicUrl), 303);
}

export async function POST(request: NextRequest): Promise<Response> {
  if (mode() !== "entra") return new Response("Entra sign-in is not configured", { status: 404 });
  const { tenants, publicUrl } = entraConfig();
  if (!sameOrigin(request)) return new Response("Start signing in from the console's sign-in page.", { status: 403 });
  let asked = "";
  try {
    const form = await request.formData();
    const value = form.get("organisation");
    asked = typeof value === "string" ? value.trim().toLowerCase() : "";
  } catch {
    asked = "";
  }
  const tenant =
    tenants.length === 1
      ? tenants[0]
      : tenants.find((t) => asked !== "" && (t.tenant === asked || t.name.toLowerCase() === asked));
  // Not found and found are told apart only by where the browser goes next, never by a list.
  if (!tenant) return NextResponse.redirect(new URL("/sign-in?unknown=1", publicUrl), 303);
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
