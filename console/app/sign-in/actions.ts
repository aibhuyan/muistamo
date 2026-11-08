"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { type ActionState, field, invalid } from "@/lib/actions";
import { tenantConfig } from "@/lib/entra/config";
import { forgetControlPlaneToken } from "@/lib/entra/controlplane";
import { clearSession, readSession } from "@/lib/entra/cookies";
import { endSessionUrl } from "@/lib/entra/flow";
import { devLoginEnabled, endSession, entraEnabled, startSession, validSession } from "@/lib/session";

export async function signIn(_previous: ActionState, form: FormData): Promise<ActionState> {
  if (!devLoginEnabled()) return { problem: { title: "No sign-in is configured.", status: 403 } };
  const session = validSession(field(form, "tenant"), field(form, "person"));
  if (!session) return invalid("Enter a tenant UUID and an email address.");
  await startSession(session);
  redirect("/");
}

// A POST (Server Action), never a GET link: Next checks the Origin against the host.
export async function signOut(): Promise<void> {
  if (entraEnabled()) {
    const store = await cookies();
    const session = await readSession(store);
    clearSession(store);
    if (session) forgetControlPlaneToken(session.sid);
    const t = session ? tenantConfig(session.tenant) : null;
    let url: URL | null = null;
    try {
      url = t ? await endSessionUrl(t) : null;
    } catch {
      url = null; // signed out here even if Entra cannot be reached
    }
    redirect(url ? url.toString() : "/sign-in");
  }
  await endSession();
  redirect("/sign-in");
}
