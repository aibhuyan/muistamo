import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { ApproveReject, DecisionForm, ReasonField } from "../decision-form";
import { Pill, decided, label, when } from "../entry";
import { Refusal } from "../refusal";
import { decideCatalogueRequest } from "./actions";

export default async function CataloguePage() {
  const session = await requireSession();
  const result = await api.pendingCatalogueRequests(session);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const items = result.data.items;
  return (
    <div className="page narrow">
      <div className="page-head">
        <h1>Catalogue requests</h1>
        <p className="lede">
          Template versions waiting to be published. Medium risk needs one approver, high risk two; never the
          requester.
        </p>
      </div>
      {items.length === 0 ? <p>Nothing pending.</p> : null}
      {items.map((c) => (
        <section key={c.id} className="panel">
          <div className="panel-head">
            <div>
              <h2>
                {c.template} <span className="muted">version {c.version}</span>
              </h2>
              <p className="muted">
                Requested by {c.requestedBy} on {when(c.createdAt)}
              </p>
            </div>
            <div className="pills">
              <Pill value={c.riskTier}>{label(c.riskTier)} risk</Pill>
              <Pill tone="neutral">
                {c.approvals.length} of {c.neededApprovals} approvals
              </Pill>
            </div>
          </div>
          {c.approvals.map((a, i) => (
            <div key={i} className="panel-row">
              <strong>
                {decided(a.decision)} by {a.approver}
              </strong>
              <p>{a.reason}</p>
            </div>
          ))}
          <div className="panel-body">
            <DecisionForm action={decideCatalogueRequest.bind(null, c.id)} submit="Send decision">
              <ApproveReject />
              <ReasonField />
            </DecisionForm>
          </div>
        </section>
      ))}
    </div>
  );
}
