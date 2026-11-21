import Link from "next/link";

import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { Pill, label } from "../entry";
import { Refusal } from "../refusal";
import { NotChecked, Target, actFor, actionPolicyHref, linkHref } from "./policy";

// The tenant's agent links and action policies, for console administrators (D70). Read-only:
// policies are changed as code.
export default async function PoliciesPage() {
  const session = await requireSession();
  const [links, policies] = await Promise.all([api.links(session), api.actionPolicies(session)]);
  if (!links.ok) return <Refusal problem={links.problem} />;
  if (!policies.ok) return <Refusal problem={policies.problem} />;
  return (
    <div className="page">
      <div className="page-head">
        <h1>Policies</h1>
        <p className="lede">
          Which agents may call which, and which tool actions agents of each template may take. Without a link, a call is
          denied; an action no rule allows is denied unless the policy&apos;s default is allow.
        </p>
      </div>
      <NotChecked />
      <section className="section">
        <h2>Agent links</h2>
        {links.data.items.length === 0 ? (
          <p>No agent links. Every call from one agent to another is denied.</p>
        ) : (
          <div className="panel scroll">
            <table>
              <thead>
                <tr>
                  <th>Link</th>
                  <th>From</th>
                  <th>To</th>
                  <th>Skills</th>
                  <th>Data classes</th>
                  <th>Acts with the access of</th>
                  <th>Depth</th>
                </tr>
              </thead>
              <tbody>
                {links.data.items.map(({ document: { metadata, spec } }) => (
                  <tr key={metadata.name}>
                    <td>
                      <Link href={linkHref(metadata.name)} className="mono">
                        {metadata.name}
                      </Link>
                    </td>
                    <td>
                      <Target target={spec.from} />
                    </td>
                    <td>
                      <Target target={spec.to} />
                    </td>
                    <td className="mono">{spec.allowedSkills.join(", ")}</td>
                    <td>{spec.dataClasses.length > 0 ? spec.dataClasses.map(label).join(", ") : "None"}</td>
                    <td>{actFor(spec.actFor)}</td>
                    <td>{spec.maxDelegationDepth ?? 1}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="section">
        <h2>Action policies</h2>
        {policies.data.items.length === 0 ? (
          <p>No action policies. Every tool action is denied by default.</p>
        ) : (
          <div className="panel scroll">
            <table>
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Applies to</th>
                  <th>Default</th>
                  <th>Mode</th>
                  <th>Rules</th>
                </tr>
              </thead>
              <tbody>
                {policies.data.items.map(({ document: { metadata, spec } }) => (
                  <tr key={metadata.name}>
                    <td>
                      <Link href={actionPolicyHref(metadata.name)} className="mono">
                        {metadata.name}
                      </Link>
                    </td>
                    <td>
                      <Target target={spec.appliesTo} />
                    </td>
                    <td>{spec.appliesTo.clone ? "Its template's" : <Pill value={spec.default ?? "deny"} />}</td>
                    <td>{spec.appliesTo.clone ? "Its template's" : <Pill value={spec.mode ?? "enforce"} />}</td>
                    <td>{spec.rules.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <p className="muted">Links and action policies are changed as code.</p>
    </div>
  );
}
