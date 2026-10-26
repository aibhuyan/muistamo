"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { type ActionState, field, invalid } from "@/lib/actions";
import { type LeaverReviewDecision, api } from "@/lib/api";
import { requireSession } from "@/lib/session";

export async function decideLeaverReview(
  reviewId: string,
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await requireSession();
  const decision = field(form, "decision");
  const reason = field(form, "reason");
  let body: LeaverReviewDecision;
  if (decision === "merge") {
    const entryIds = form.getAll("entryIds").filter((v): v is string => typeof v === "string");
    if (entryIds.length === 0) return invalid("Choose at least one entry to merge.");
    body = { decision, reason, pack: field(form, "pack"), summary: field(form, "summary"), entryIds };
  } else if (decision === "keep" || decision === "purge") {
    // Only merge carries a pack, entries and summary; the contract refuses them otherwise.
    body = { decision, reason };
  } else {
    return invalid("Choose merge, keep or purge.");
  }
  const result = await api.decideLeaverReview(session, reviewId, body);
  if (!result.ok) return { problem: result.problem };
  revalidatePath("/leaver-reviews");
  redirect("/leaver-reviews");
}
