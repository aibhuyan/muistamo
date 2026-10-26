import Link from "next/link";

import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { when } from "../entry";
import { Refusal } from "../refusal";

export default async function ProposalsPage() {
  const session = await requireSession();
  const result = await api.reviewerProposals(session);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const items = result.data.items;
  return (
    <>
      <h1>Knowledge proposals</h1>
      <p className="muted">Proposals to packs you review. You can never decide your own.</p>
      {items.length === 0 ? (
        <p>Nothing to review.</p>
      ) : (
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
                <td>{p.status}</td>
                <td>{when(p.createdAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
