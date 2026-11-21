import Link from "next/link";

import { routeParam } from "@/lib/actions";
import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { Pill, when } from "../../entry";
import { Refusal } from "../../refusal";
import { personHref } from "../../workforce";
import { ReceiptRows } from "../receipts";

// One person, by HR id, for console administrators (D70): their HR events and the agents labelled
// with their HR id. Read-only. Nothing from the HR payload, and no agent binding (it holds the person's
// email), reaches this page.
export default async function PersonPage({ params }: { params: Promise<{ id: string }> }) {
  const personId = routeParam((await params).id);
  const session = await requireSession();
  // The control plane admits from the console only ids it can address unescaped; say so plainly
  // rather than show its refusal, which reads like a sign-in problem.
  if (!personHref(personId)) {
    return (
      <div className="page narrow">
        <Link href="/people" className="back">
          People
        </Link>
        <h1>This HR id cannot be opened here</h1>
        <p>
          The console opens a person by an HR id made of letters, digits, dots, underscores and hyphens. This
          person&apos;s HR events are listed on the People page.
        </p>
      </div>
    );
  }
  const result = await api.person(session, personId);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const p = result.data;
  return (
    <div className="page">
      <Link href="/people" className="back">
        People
      </Link>
      <h1>
        Person <span className="mono">{p.personId}</span>
      </h1>
      <p className="muted">Named by the id your HR system gives them. Muistamo keeps this id after an erasure.</p>
      <section className="section">
        <h2>Agents labelled with this HR id</h2>
        {p.agents.length === 0 ? (
          <p>No agent carries this HR id.</p>
        ) : (
          <div className="panel scroll">
            <table>
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Template</th>
                  <th>State</th>
                  <th>Last change</th>
                </tr>
              </thead>
              <tbody>
                {p.agents.map((a) => (
                  <tr key={a.name}>
                    <td>
                      <Link href={`/agents/${encodeURIComponent(a.name)}`} className="mono">
                        {a.name}
                      </Link>
                    </td>
                    <td>
                      {a.templateName} <span className="muted">version {a.templateVersion}</span>
                      {a.cloneName ? <span className="muted"> through clone {a.cloneName}</span> : null}
                    </td>
                    <td>
                      <Pill value={a.state} />
                    </td>
                    <td className="nowrap muted">{when(a.updatedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="section">
        <h2>HR events</h2>
        {p.receipts.length === 0 ? (
          <p>No HR events have been received for this id.</p>
        ) : (
          <ReceiptRows items={p.receipts} showPerson={false} />
        )}
        {p.receiptsTruncated ? <p className="muted">Only the 100 most recent HR events are listed.</p> : null}
      </section>
    </div>
  );
}
