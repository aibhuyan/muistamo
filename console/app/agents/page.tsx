import Link from "next/link";

import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { Pill, when } from "../entry";
import { Refusal } from "../refusal";
import { Pager, bindingKind, cursorParam } from "../workforce";

// Every agent in the tenant, for console administrators (D70). Read-only: agents are created and
// retired by HR events, not here.
export default async function AgentsPage(props: { searchParams?: Promise<Record<string, string | string[] | undefined>> }) {
  const session = await requireSession();
  const cursor = cursorParam(await props.searchParams);
  const result = await api.instances(session, cursor);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const { items, nextCursor } = result.data;
  return (
    <div className="page">
      <div className="page-head">
        <h1>Agents</h1>
        <p className="lede">
          Every agent in your organisation and the template it was made from. Agents are created and retired by HR
          events, not from this page.
        </p>
      </div>
      {items.length === 0 ? (
        <p>{cursor ? "No more agents." : "No agents yet."}</p>
      ) : (
        <div className="panel scroll">
          <table>
            <thead>
              <tr>
                <th>Agent</th>
                <th>Template</th>
                <th>State</th>
                <th>Acts for</th>
                <th>Cost centre</th>
                <th>Last change</th>
              </tr>
            </thead>
            <tbody>
              {items.map((rec) => {
                const { metadata, spec } = rec.document;
                return (
                  <tr key={metadata.name}>
                    <td>
                      <Link href={`/agents/${encodeURIComponent(metadata.name)}`} className="mono">
                        {metadata.name}
                      </Link>
                    </td>
                    <td>
                      {spec.templateRef.name} <span className="muted">version {spec.templateRef.version}</span>
                    </td>
                    <td>
                      <Pill value={spec.state} />
                    </td>
                    <td>{bindingKind(spec.binding.type)}</td>
                    <td>{spec.costCentre ?? <span className="muted">None</span>}</td>
                    <td className="nowrap muted">{when(rec.updatedAt)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <Pager path="/agents" cursor={cursor} nextCursor={nextCursor} />
    </div>
  );
}
