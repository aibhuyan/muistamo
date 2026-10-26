import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { ApproveReject, DecisionForm, ReasonField } from "../decision-form";
import { when } from "../entry";
import { Refusal } from "../refusal";
import { decideCatalogueRequest } from "./actions";

export default async function CataloguePage() {
  const session = await requireSession();
  const result = await api.pendingCatalogueRequests(session);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const items = result.data.items;
  return (
    <>
      <h1>Catalogue requests</h1>
      <p className="muted">
        Template versions waiting to be published. Medium risk needs one approver, high risk two; never the
        requester.
      </p>
      {items.length === 0 ? <p>Nothing pending.</p> : null}
      {items.map((c) => (
        <section key={c.id} className="entry">
          <h2>
            {c.template} v{c.version}
          </h2>
          <p className="muted">
            {c.riskTier} risk · requested by {c.requestedBy} · {when(c.createdAt)} · {c.approvals.length} of{" "}
            {c.neededApprovals} approvals
          </p>
          {c.approvals.length > 0 ? (
            <ul>
              {c.approvals.map((a, i) => (
                <li key={i}>
                  {a.decision} by {a.approver}: {a.reason}
                </li>
              ))}
            </ul>
          ) : null}
          <DecisionForm action={decideCatalogueRequest.bind(null, c.id)} submit="Send decision">
            <ApproveReject />
            <ReasonField />
          </DecisionForm>
        </section>
      ))}
    </>
  );
}
