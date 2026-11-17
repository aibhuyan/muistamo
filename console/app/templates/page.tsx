import Link from "next/link";

import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { Pill, label, when } from "../entry";
import { Refusal } from "../refusal";
import { Pager, cursorParam } from "../workforce";

// The latest version of every template, for console administrators (D70). Read-only: templates
// are changed as code.
export default async function TemplatesPage(props: { searchParams?: Promise<Record<string, string | string[] | undefined>> }) {
  const session = await requireSession();
  const cursor = cursorParam(await props.searchParams);
  const result = await api.templates(session, cursor);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const { items, nextCursor } = result.data;
  return (
    <div className="page">
      <div className="page-head">
        <h1>Templates</h1>
        <p className="lede">
          What each kind of agent may know and do, at its latest version. Templates are changed as code, in YAML or
          Terraform, not from this page.
        </p>
      </div>
      {items.length === 0 ? (
        <p>{cursor ? "No more templates." : "No templates yet."}</p>
      ) : (
        <div className="panel scroll">
          <table>
            <thead>
              <tr>
                <th>Template</th>
                <th>Version</th>
                <th>Risk</th>
                <th>Knowledge packs</th>
                <th>Model</th>
                <th>Assigned to job codes</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {items.map((rec) => {
                const { metadata, spec } = rec.document;
                const packs = (spec.knowledgePacks ?? []).map((p) => p.name);
                const jobCodes = spec.assignment?.hrJobCodes ?? [];
                return (
                  <tr key={metadata.name}>
                    <td>
                      <Link href={`/templates/${encodeURIComponent(metadata.name)}`} className="mono">
                        {metadata.name}
                      </Link>
                    </td>
                    <td>{rec.version}</td>
                    <td>
                      {spec.riskTier ? (
                        <Pill value={spec.riskTier}>{label(spec.riskTier)}</Pill>
                      ) : (
                        <span className="muted">Not set</span>
                      )}
                    </td>
                    <td>{packs.length > 0 ? packs.join(", ") : <span className="muted">None</span>}</td>
                    <td className="mono">{spec.modelAlias}</td>
                    <td>{jobCodes.length > 0 ? jobCodes.join(", ") : <span className="muted">None</span>}</td>
                    <td className="nowrap muted">{when(rec.createdAt)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <Pager path="/templates" cursor={cursor} nextCursor={nextCursor} />
    </div>
  );
}
