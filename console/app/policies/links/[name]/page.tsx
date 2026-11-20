import Link from "next/link";

import { routeParam } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { label, when } from "../../../entry";
import { Refusal } from "../../../refusal";
import { ObservesOnly, Target, actFor } from "../../policy";

// One agent link, for console administrators (D70). Read-only.
export default async function LinkPage({ params }: { params: Promise<{ name: string }> }) {
  const name = routeParam((await params).name);
  const session = await requireSession();
  const result = await api.link(session, name);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const rec = result.data;
  const { metadata, spec } = rec.document;
  const depth = spec.maxDelegationDepth ?? 1;
  return (
    <div className="page narrow">
      <Link href="/policies" className="back">
        Policies
      </Link>
      <h1 className="mono-title">{metadata.name}</h1>
      <p className="lede">
        A one-way permission: agents at the first end may call agents at the second. It never allows calls the other way.
      </p>
      <ObservesOnly />
      <dl className="panel facts">
        <div>
          <dt>From</dt>
          <dd>
            <Target target={spec.from} />
          </dd>
        </div>
        <div>
          <dt>To</dt>
          <dd>
            <Target target={spec.to} />
          </dd>
        </div>
        <div>
          <dt>Skills it may use</dt>
          <dd className="mono">{spec.allowedSkills.join(", ")}</dd>
        </div>
        <div>
          <dt>Data classes a call may carry</dt>
          <dd>{spec.dataClasses.length > 0 ? spec.dataClasses.map(label).join(", ") : "None"}</dd>
        </div>
        <div>
          <dt>The called agent acts with the access of</dt>
          <dd>{actFor(spec.actFor)}</dd>
        </div>
        <div>
          <dt>Delegation depth</dt>
          <dd>{depth === 1 ? "1: direct calls only; the called agent may not pass the work on" : depth}</dd>
        </div>
        <div>
          <dt>Rate limit</dt>
          <dd>{spec.rateLimit ? `${spec.rateLimit} (stored, not yet evaluated)` : "None"}</dd>
        </div>
        <div>
          <dt>Revision</dt>
          <dd>
            {rec.revision}, changed {when(rec.updatedAt)}
          </dd>
        </div>
      </dl>
      <p className="muted">A call carrying a data class not listed here is denied. Links are changed as code.</p>
    </div>
  );
}
