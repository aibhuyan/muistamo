import Link from "next/link";

import { routeParam } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { ApproveReject, DecisionForm, ReasonField } from "../../decision-form";
import { Entry, Pill, decided, when } from "../../entry";
import { Refusal } from "../../refusal";
import { decideProposal } from "../actions";

export default async function ProposalPage({ params }: { params: Promise<{ id: string }> }) {
  const id = routeParam((await params).id);
  const session = await requireSession();
  const result = await api.proposal(session, id);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const p = result.data;
  return (
    <div className="page narrow">
      <Link href="/proposals" className="back">
        Knowledge proposals
      </Link>
      <h1>{p.summary}</h1>
      <dl className="panel facts">
        <div>
          <dt>Pack</dt>
          <dd>{p.pack}</dd>
        </div>
        <div>
          <dt>Contributor</dt>
          <dd>
            {p.contributor}
            {p.proposedBy ? ` (proposed by ${p.proposedBy})` : ""}
          </dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{when(p.createdAt)}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>
            <Pill value={p.status} />
            {p.mergedVersion ? ` merged as ${p.mergedVersion}` : ""}
          </dd>
        </div>
      </dl>
      <section className="section">
        <h2>Checks</h2>
        {p.checks.length === 0 ? (
          <p>All checks passed.</p>
        ) : (
          <div className="panel">
            {p.checks.map((c, i) => (
              <div key={i} className="panel-row">
                <Pill value={c.severity} /> <span className="mono">{c.ruleId}</span> on{" "}
                <span className="mono">{c.entryKey}</span>: {c.message}
              </div>
            ))}
          </div>
        )}
      </section>
      <section className="section">
        <h2>Entries</h2>
        {p.entries.map((e) => (
          <Entry key={e.id} entry={e} />
        ))}
      </section>
      {p.decision ? (
        <section className="section">
          <h2>Decision</h2>
          <div className="panel padded">
            <p>
              <strong>{decided(p.decision.decision)}</strong> by {p.decision.reviewer}
            </p>
            <p>{p.decision.reason}</p>
          </div>
        </section>
      ) : p.status === "in-review" ? (
        <section className="section">
          <h2>Decide</h2>
          <div className="panel padded">
            <DecisionForm action={decideProposal.bind(null, p.id)} submit="Send decision">
              <ApproveReject />
              <ReasonField />
            </DecisionForm>
          </div>
        </section>
      ) : null}
    </div>
  );
}
