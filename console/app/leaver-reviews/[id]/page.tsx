import Link from "next/link";

import { routeParam } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { DecisionForm, ReasonField } from "../../decision-form";
import { Pill, label, when } from "../../entry";
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
    <div className="page narrow">
      <Link href="/leaver-reviews" className="back">
        Leaver reviews
      </Link>
      <h1>Personal knowledge of {r.person}</h1>
      <dl className="panel facts">
        <div>
          <dt>Status</dt>
          <dd>
            <Pill value={r.status} />
            {r.outcome ? ` ${label(r.outcome)}` : ""}
          </dd>
        </div>
        <div>
          <dt>Deadline</dt>
          <dd>{when(r.deadline)}</dd>
        </div>
        <div>
          <dt>Extension</dt>
          <dd>{r.kept ? "Extended once" : "Not extended"}</dd>
        </div>
        {r.proposalId ? (
          <div>
            <dt>Became proposal</dt>
            <dd className="mono">{r.proposalId}</dd>
          </div>
        ) : null}
      </dl>
      <div className="notice">
        <strong>Your opening of this page is recorded in the evidence log.</strong>
        <span>
          Only entries the person shared are shown. Entries they marked private are never shown here and were deleted
          when they left.
        </span>
      </div>
      {r.status !== "open" ? (
        <p>This review is closed.</p>
      ) : (
        <DecisionForm action={decideLeaverReview.bind(null, r.id)} submit="Send decision">
          <fieldset>
            <legend className="heading">Entries to merge (merge only)</legend>
            <div className="stack">
              {entries.length === 0 ? <p>No entries.</p> : null}
              {entries.map((e) => (
                <div key={e.id} className="pick">
                  <label className="check">
                    <input type="checkbox" name="entryIds" value={e.id} /> <strong>{e.title}</strong>
                  </label>
                  <div className="meta">
                    <span className="mono">{e.key}</span>
                    <span>{label(e.type)}</span>
                    <span>{label(e.dataClass)}</span>
                  </div>
                  <pre>{e.body}</pre>
                </div>
              ))}
            </div>
          </fieldset>
          <div className="panel padded stack">
            <fieldset>
              <legend>Decision</legend>
              <div className="choices column">
                <label className="choice">
                  <input type="radio" name="decision" value="merge" required /> Merge the chosen entries, purge the rest
                </label>
                <label className="choice">
                  <input type="radio" name="decision" value="keep" /> Keep for one more period
                </label>
                <label className="choice">
                  <input type="radio" name="decision" value="purge" /> Purge now
                </label>
              </div>
            </fieldset>
            <div className="fields">
              <label className="field">
                Pack to propose to (merge only)
                <input type="text" name="pack" />
              </label>
              <label className="field">
                Proposal summary (merge only)
                <input type="text" name="summary" maxLength={2000} />
              </label>
            </div>
            <p className="muted">
              A merge becomes an ordinary proposal: the pack&apos;s reviewers decide it, and you cannot approve it.
            </p>
            <ReasonField />
          </div>
        </DecisionForm>
      )}
    </div>
  );
}
