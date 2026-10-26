import { routeParam } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { ApproveReject, DecisionForm, ReasonField } from "../../decision-form";
import { Entry, when } from "../../entry";
import { Refusal } from "../../refusal";
import { decideProposal } from "../actions";

export default async function ProposalPage({ params }: { params: Promise<{ id: string }> }) {
  const id = routeParam((await params).id);
  const session = await requireSession();
  const result = await api.proposal(session, id);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const p = result.data;
  return (
    <>
      <h1>{p.summary}</h1>
      <p className="muted">
        To <strong>{p.pack}</strong> from {p.contributor}
        {p.proposedBy ? ` (proposed by ${p.proposedBy})` : ""} · {when(p.createdAt)} · {p.status}
        {p.mergedVersion ? ` · merged as ${p.mergedVersion}` : ""}
      </p>

      <h2>Checks</h2>
      {p.checks.length === 0 ? (
        <p>All checks passed.</p>
      ) : (
        <ul>
          {p.checks.map((c, i) => (
            <li key={i}>
              <strong>{c.severity}</strong> {c.ruleId} on {c.entryKey}: {c.message}
            </li>
          ))}
        </ul>
      )}

      <h2>Entries</h2>
      {p.entries.map((e) => (
        <Entry key={e.id} entry={e} />
      ))}

      {p.decision ? (
        <>
          <h2>Decision</h2>
          <p>
            {p.decision.decision} by {p.decision.reviewer}: {p.decision.reason}
          </p>
        </>
      ) : p.status === "in-review" ? (
        <>
          <h2>Decide</h2>
          <DecisionForm action={decideProposal.bind(null, p.id)} submit="Send decision">
            <ApproveReject />
            <ReasonField />
          </DecisionForm>
        </>
      ) : null}
    </>
  );
}
