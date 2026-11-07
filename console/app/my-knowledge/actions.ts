"use server";

import { revalidatePath } from "next/cache";

import { type ActionState, field, invalid } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

// The person's own entries (D59). The knowledge service decides every change: it refuses a
// change while the layer is frozen for a leaver review, and making private an entry already
// proposed. The console relays its answer.

export async function setEntryVisibility(
  entryId: string,
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await requireSession();
  const choice = field(form, "private");
  if (choice !== "true" && choice !== "false") return invalid("Choose private or shared.");
  const result = await api.setEntryVisibility(session, entryId, choice === "true");
  if (!result.ok) return { problem: result.problem };
  revalidatePath("/my-knowledge");
  return {};
}

export async function deleteEntry(entryId: string, _previous: ActionState, form: FormData): Promise<ActionState> {
  const session = await requireSession();
  if (field(form, "confirm") !== "yes") return invalid("Tick the box to confirm the deletion.");
  const result = await api.deleteEntry(session, entryId);
  if (!result.ok) return { problem: result.problem };
  revalidatePath("/my-knowledge");
  return {};
}
