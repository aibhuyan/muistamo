import Link from "next/link";

import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { Pill, when } from "../entry";
import { Refusal } from "../refusal";

export default async function ProposalsPage() {
  const session = await requireSession();
  const result = await api.reviewerProposals(session);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const items = result.data.items;
  const waiting = items.filter((p) => p.status === "in-review").length;
  return (
    <div className="page">
      <div className="page-head">
        <h1>Knowledge proposals</h1>
        <p className="lede">Proposals to packs you review. You can never decide your own.</p>
      </div>
      {items.length === 0 ? (
        <p>Nothing to review.</p>
      ) : (
        <>
          <p className="muted">
            {waiting} in review, {items.length - waiting} decided or returned.
          </p>
          <div className="panel scroll">
            <table>
              <thead>
                <tr>
                  <th>Summary</th>
                  <th>Pack</th>
                  <th>Contributor</th>
                  <th>Status</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {items.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <Link href={`/proposals/${encodeURIComponent(p.id)}`}>{p.summary}</Link>
                    </td>
                    <td>{p.pack}</td>
                    <td>
                      {p.contributor}
                      {p.proposedBy ? <span className="muted"> (proposed by {p.proposedBy})</span> : null}
                    </td>
                    <td>
                      <Pill value={p.status} />
                    </td>
                    <td className="nowrap muted">{when(p.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
