import Link from "next/link";

import { routeParam } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { Pill, when } from "../../entry";
import { Refusal } from "../../refusal";
import { bindingKind } from "../../workforce";

// One agent, for console administrators (D70). Read-only.
export default async function AgentPage({ params }: { params: Promise<{ name: string }> }) {
  const name = routeParam((await params).name);
  const session = await requireSession();
  const result = await api.instance(session, name);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const rec = result.data;
  const { metadata, spec } = rec.document;
  return (
    <div className="page narrow">
      <Link href="/agents" className="back">
        Agents
      </Link>
      <h1 className="mono-title">{metadata.name}</h1>
      <dl className="panel facts">
        <div>
          <dt>State</dt>
          <dd>
            <Pill value={spec.state} />
          </dd>
        </div>
        <div>
          <dt>Template</dt>
          <dd>
            <Link href={`/templates/${encodeURIComponent(spec.templateRef.name)}`}>{spec.templateRef.name}</Link>{" "}
            <span className="muted">version {spec.templateRef.version}</span>
          </dd>
        </div>
        <div>
          <dt>Acts for</dt>
          <dd>{bindingKind(spec.binding.type)}</dd>
        </div>
        <div>
          <dt>Cost centre</dt>
          <dd>{spec.costCentre ?? "None"}</dd>
        </div>
      </dl>
      <section className="section">
        <h2>Record</h2>
        <dl className="panel facts">
          <div>
            <dt>Created</dt>
            <dd>{when(rec.createdAt)}</dd>
          </div>
          <div>
            <dt>Last change</dt>
            <dd>{when(rec.updatedAt)}</dd>
          </div>
          <div>
            <dt>Revision</dt>
            <dd>{rec.revision}</dd>
          </div>
          <div>
            <dt>Clone of</dt>
            <dd>{spec.cloneRef ? <span className="mono">{spec.cloneRef}</span> : "Not a clone"}</dd>
          </div>
          <div>
            <dt>Directory identity</dt>
            <dd>{spec.identityRef ? <span className="mono">{spec.identityRef}</span> : "None recorded"}</dd>
          </div>
        </dl>
      </section>
      <p className="muted">
        Agents change only through HR events and the lifecycle; nothing on this page changes the agent.
      </p>
    </div>
  );
}
