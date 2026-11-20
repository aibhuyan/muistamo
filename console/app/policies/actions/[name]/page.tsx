import Link from "next/link";

import { routeParam } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { Pill, when } from "../../../entry";
import { Refusal } from "../../../refusal";
import { ObservesOnly, Target } from "../../policy";

// One action policy, for console administrators (D70). Read-only.
export default async function ActionPolicyPage({ params }: { params: Promise<{ name: string }> }) {
  const name = routeParam((await params).name);
  const session = await requireSession();
  const result = await api.actionPolicy(session, name);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const rec = result.data;
  const { metadata, spec } = rec.document;
  const forClone = spec.appliesTo.clone !== undefined;
  return (
    <div className="page narrow">
      <Link href="/policies" className="back">
        Policies
      </Link>
      <h1 className="mono-title">{metadata.name}</h1>
      <p className="lede">
        {forClone
          ? "The tool actions one clone may take. The clone also keeps its template's policy; this one can only narrow it, with deny and monitor rules."
          : "The tool actions agents of one template, and its clones, may take."}{" "}
        Deny overrides allow: when any deny rule applies, the action is denied whatever else allows it.
      </p>
      <ObservesOnly />
      <dl className="panel facts">
        <div>
          <dt>Applies to</dt>
          <dd>
            <Target target={spec.appliesTo} />
          </dd>
        </div>
        {forClone ? null : (
          <>
            <div>
              <dt>Actions no rule allows</dt>
              <dd>
                <Pill value={spec.default ?? "deny"} />
              </dd>
            </div>
            <div>
              <dt>Mode</dt>
              <dd>
                <Pill value={spec.mode ?? "enforce"} />{" "}
                <span className="muted">
                  {(spec.mode ?? "enforce") === "monitor" ? "denials are only reported" : "denials will be blocked once the gateway enforces"}
                </span>
              </dd>
            </div>
          </>
        )}
        <div>
          <dt>Revision</dt>
          <dd>
            {rec.revision}, changed {when(rec.updatedAt)}
          </dd>
        </div>
      </dl>
      <section className="section">
        <h2>Rules</h2>
        {spec.rules.length === 0 ? (
          <p className="muted">No rules.</p>
        ) : (
          <div className="panel scroll">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Action</th>
                  <th>Effect</th>
                  <th>Only when all of</th>
                  <th>Unless any of</th>
                </tr>
              </thead>
              <tbody>
                {spec.rules.map((r, i) => (
                  <tr key={i}>
                    <td className="muted">{i + 1}</td>
                    <td className="mono">{r.action}</td>
                    <td>
                      <Pill value={r.effect}>{r.effect === "monitor" ? "Allow and flag" : undefined}</Pill>
                    </td>
                    <td className="mono">{r.when && r.when.length > 0 ? r.when.join(", ") : "—"}</td>
                    <td className="mono">{r.unless && r.unless.length > 0 ? r.unless.join(", ") : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted">
          A request attribute that is not supplied counts against the caller: it stops an allow or monitor rule applying,
          and lets a deny rule apply.
        </p>
      </section>
    </div>
  );
}
