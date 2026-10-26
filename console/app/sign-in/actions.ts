"use server";

import { redirect } from "next/navigation";

import { type ActionState, field, invalid } from "@/lib/actions";
import { devLoginEnabled, endSession, startSession, validSession } from "@/lib/session";

export async function signIn(_previous: ActionState, form: FormData): Promise<ActionState> {
  if (!devLoginEnabled()) return { problem: { title: "No sign-in is configured.", status: 403 } };
  const session = validSession(field(form, "tenant"), field(form, "person"));
  if (!session) return invalid("Enter a tenant UUID and an email address.");
  await startSession(session);
  redirect("/");
}

export async function signOut(): Promise<void> {
  await endSession();
  redirect("/sign-in");
}
