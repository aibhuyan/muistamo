import Link from "next/link";

import { routeParam } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import type { ActionPolicyRecord, AgentLinkRecord } from "@/lib/api";

import { Pill, label, when } from "../../entry";
import { Target, actionPolicyHref, forTemplate, linkHref } from "../../policies/policy";
import { Refusal } from "../../refusal";

// The action policy for a template and the links from and to it, each linked to its page.
function TemplatePolicies({ from, to, policies }: { from: AgentLinkRecord[]; to: AgentLinkRecord[]; policies: ActionPolicyRecord[] }) {
  return (
    <dl className="panel facts">
      <div>
        <dt>Action policy</dt>
        <dd>
          {policies.length === 0
            ? "None: every tool action is denied by default"
            : policies.map((p) => (
                <Link key={p.document.metadata.name} href={actionPolicyHref(p.document.metadata.name)} className="mono">
                  {p.document.metadata.name}
                </Link>
              ))}
        </dd>
      </div>
      <div>
        <dt>May call</dt>
        <dd>
          {from.length === 0
            ? "No other agent"
            : from.map((l) => (
                <div key={l.document.metadata.name}>
                  <Target target={l.document.spec.to} /> through{" "}
                  <Link href={linkHref(l.document.metadata.name)} className="mono">
                    {l.document.metadata.name}
                  </Link>
                </div>
              ))}
        </dd>
      </div>
      <div>
        <dt>May be called by</dt>
        <dd>
          {to.length === 0
            ? "No other agent"
            : to.map((l) => (
                <div key={l.document.metadata.name}>
                  <Target target={l.document.spec.from} /> through{" "}
                  <Link href={linkHref(l.document.metadata.name)} className="mono">
                    {l.document.metadata.name}
                  </Link>
                </div>
              ))}
        </dd>
      </div>
    </dl>
  );
}

// The latest version of one template, for console administrators (D70). Read-only.
export default async function TemplatePage({ params }: { params: Promise<{ name: string }> }) {
  const name = routeParam((await params).name);
  const session = await requireSession();
  const [result, links, policies] = await Promise.all([
    api.template(session, name),
    api.links(session),
    api.actionPolicies(session),
  ]);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const rec = result.data;
  const { metadata, spec } = rec.document;
  const packs = spec.knowledgePacks ?? [];
  const tools = spec.tools ?? [];
  const dataClasses = spec.dataClasses ?? [];
  const jobCodes = spec.assignment?.hrJobCodes ?? [];
  return (
    <div className="page narrow">
      <Link href="/templates" className="back">
        Templates
      </Link>
      <h1 className="mono-title">{metadata.name}</h1>
      <p className="lede">{spec.purpose}</p>
      <dl className="panel facts">
        <div>
          <dt>Version</dt>
          <dd>{rec.version}</dd>
        </div>
        <div>
          <dt>Risk</dt>
          <dd>{spec.riskTier ? <Pill value={spec.riskTier}>{label(spec.riskTier)}</Pill> : "Not set"}</dd>
        </div>
        <div>
          <dt>Model</dt>
          <dd className="mono">{spec.modelAlias}</dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{when(rec.createdAt)}</dd>
        </div>
      </dl>
      <section className="section">
        <h2>Knowledge packs</h2>
        {packs.length === 0 ? (
          <p className="muted">None.</p>
        ) : (
          <div className="panel">
            {packs.map((p) => (
              <div key={p.name} className="panel-row">
                <span className="mono">{p.name}</span>
                {p.version ? <span className="muted"> version {p.version}</span> : <span className="muted"> latest</span>}
              </div>
            ))}
          </div>
        )}
      </section>
      <section className="section">
        <h2>Scope</h2>
        <dl className="panel facts">
          <div>
            <dt>Tools</dt>
            <dd>{tools.length > 0 ? tools.join(", ") : "None"}</dd>
          </div>
          <div>
            <dt>Data classes</dt>
            <dd>{dataClasses.length > 0 ? dataClasses.map(label).join(", ") : "None"}</dd>
          </div>
          <div>
            <dt>Autonomy</dt>
            <dd>{spec.autonomy ?? "Not set"}</dd>
          </div>
          <div>
            <dt>Assigned to job codes</dt>
            <dd>{jobCodes.length > 0 ? jobCodes.join(", ") : "None"}</dd>
          </div>
          <div>
            <dt>Budget per agent</dt>
            <dd>
              {spec.budget?.perInstanceMonthlyEUR !== undefined ? `${spec.budget.perInstanceMonthlyEUR} EUR a month` : "None"}
            </dd>
          </div>
          <div>
            <dt>Evaluation set</dt>
            <dd>{spec.evaluationSet ?? "None"}</dd>
          </div>
        </dl>
      </section>
      <section className="section">
        <h2>Policies</h2>
        {!links.ok ? (
          <p className="muted">The links could not be read: {links.problem.title}.</p>
        ) : !policies.ok ? (
          <p className="muted">The action policies could not be read: {policies.problem.title}.</p>
        ) : (
          <TemplatePolicies {...forTemplate(metadata.name, links.data.items, policies.data.items)} />
        )}
        <p className="muted">
          Links and policies that name one of this template&apos;s clones are listed on <Link href="/policies">Policies</Link>,
          not here. Nothing is blocked yet: release 1 observes only.
        </p>
      </section>
      <p className="muted">Templates are changed as code. A new version is published after catalogue approval.</p>
    </div>
  );
}
