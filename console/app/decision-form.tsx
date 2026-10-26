"use client";

import { type ReactNode, useActionState } from "react";

import { type ActionState, initialActionState } from "@/lib/actions";

import { Refusal } from "./refusal";

type Props = {
  action: (previous: ActionState, form: FormData) => Promise<ActionState>;
  submit: string;
  children: ReactNode;
};

// A form posted to a Server Action. It works before JavaScript loads; afterwards it shows the
// pending state. A refusal from the service is shown above the fields.
export function DecisionForm({ action, submit, children }: Props) {
  const [state, formAction, pending] = useActionState(action, initialActionState);
  return (
    <form action={formAction} className="decision">
      {state.problem ? <Refusal problem={state.problem} /> : null}
      {children}
      <button type="submit" disabled={pending}>
        {pending ? "Sending…" : submit}
      </button>
    </form>
  );
}

export function ReasonField() {
  return (
    <label>
      Reason
      <textarea name="reason" required maxLength={2000} rows={3} />
    </label>
  );
}

export function ApproveReject() {
  return (
    <fieldset>
      <legend>Decision</legend>
      <label>
        <input type="radio" name="decision" value="approve" required /> Approve
      </label>
      <label>
        <input type="radio" name="decision" value="reject" /> Reject
      </label>
    </fieldset>
  );
}
