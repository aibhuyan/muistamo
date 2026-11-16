"use client";

import { type ReactNode, useActionState } from "react";

import { type ActionState, initialActionState } from "@/lib/actions";

import { Refusal } from "./refusal";

type Props = {
  action: (previous: ActionState, form: FormData) => Promise<ActionState>;
  submit: string;
  // How the submit button looks: the page's main action, a secondary one, or a deletion.
  tone?: "primary" | "quiet" | "danger";
  children: ReactNode;
};

// A form posted to a Server Action. It works before JavaScript loads; afterwards it shows the
// pending state. A refusal from the service is shown above the fields.
export function DecisionForm({ action, submit, tone = "primary", children }: Props) {
  const [state, formAction, pending] = useActionState(action, initialActionState);
  return (
    <form action={formAction} className="decision">
      {state.problem ? <Refusal problem={state.problem} /> : null}
      {children}
      <button type="submit" disabled={pending} className={tone === "primary" ? undefined : tone}>
        {pending ? "Sending…" : submit}
      </button>
    </form>
  );
}

export function ReasonField() {
  return (
    <label className="field">
      Reason
      <textarea name="reason" required maxLength={2000} rows={3} />
      <span className="hint">Recorded with your decision. Up to 2,000 characters.</span>
    </label>
  );
}

export function ApproveReject() {
  return (
    <fieldset>
      <legend>Decision</legend>
      <div className="choices">
        <label className="choice">
          <input type="radio" name="decision" value="approve" required /> Approve
        </label>
        <label className="choice">
          <input type="radio" name="decision" value="reject" /> Reject
        </label>
      </div>
    </fieldset>
  );
}
