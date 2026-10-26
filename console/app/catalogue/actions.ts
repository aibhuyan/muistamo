"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { type ActionState, field, invalid } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

export async function decideCatalogueRequest(
  requestId: string,
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await requireSession();
  const decision = field(form, "decision");
  if (decision !== "approve" && decision !== "reject") return invalid("Choose approve or reject.");
  const result = await api.decideCatalogueRequest(session, requestId, { decision, reason: field(form, "reason") });
  if (!result.ok) return { problem: result.problem };
  revalidatePath("/catalogue");
  redirect("/catalogue");
}
