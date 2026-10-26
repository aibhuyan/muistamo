import { routeParam } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { DecisionForm, ReasonField } from "../../decision-form";
import { when } from "../../entry";
import { Refusal } from "../../refusal";
import { decideLeaverReview } from "../actions";

export default async function LeaverReviewPage({ params }: { params: Promise<{ id: string }> }) {
  const id = routeParam((await params).id);
  const session = await requireSession();
  // The service records this read as evidence: the decider sees the leaver's personal entries.
  const result = await api.leaverReview(session, id);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const r = result.data;
  const entries = r.entries ?? [];
  return (
    <>
      <h1>Personal knowledge of {r.person}</h1>
      <p className="muted">
        {r.status}
        {r.outcome ? ` (${r.outcome})` : ""} · deadline {when(r.deadline)}
        {r.kept ? " · already extended once" : ""}
        {r.proposalId ? ` · became proposal ${r.proposalId}` : ""}
      </p>
      <p className="muted">Your opening of this page is recorded in the evidence log.</p>

      {r.status !== "open" ? (
        <p>This review is closed.</p>
      ) : (
        <DecisionForm action={decideLeaverReview.bind(null, r.id)} submit="Send decision">
          <fieldset>
            <legend>Entries to merge (merge only)</legend>
            {entries.length === 0 ? <p>No entries.</p> : null}
            {entries.map((e) => (
              <div key={e.id} className="entry">
                <label>
                  <span>
                    <input type="checkbox" name="entryIds" value={e.id} /> <strong>{e.title}</strong>{" "}
                    <span className="muted">
                      {e.key} · {e.type} · {e.dataClass}
                    </span>
                  </span>
                </label>
                <pre>{e.body}</pre>
              </div>
            ))}
          </fieldset>
          <label>
            Pack to propose to (merge only)
            <input type="text" name="pack" />
          </label>
          <label>
            Proposal summary (merge only)
            <input type="text" name="summary" maxLength={2000} />
          </label>
          <fieldset>
            <legend>Decision</legend>
            <label>
              <input type="radio" name="decision" value="merge" required /> Merge the chosen entries, purge the rest
            </label>
            <label>
              <input type="radio" name="decision" value="keep" /> Keep for one more period
            </label>
            <label>
              <input type="radio" name="decision" value="purge" /> Purge now
            </label>
          </fieldset>
          <p className="muted">
            A merge becomes an ordinary proposal: the pack&apos;s reviewers decide it, and you cannot approve it.
          </p>
          <ReasonField />
        </DecisionForm>
      )}
    </>
  );
}
