import Link from "next/link";

import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { when } from "../entry";
import { Refusal } from "../refusal";

export default async function LeaverReviewsPage() {
  const session = await requireSession();
  const result = await api.leaverReviews(session);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const items = result.data.items;
  return (
    <>
      <h1>Leaver reviews</h1>
      <p className="muted">
        Leavers&apos; personal knowledge you decide. While a review is open the layer is frozen; without a decision
        it is purged at the deadline.
      </p>
      {items.length === 0 ? (
        <p>No reviews.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Leaver</th>
              <th>Entries</th>
              <th>Status</th>
              <th>Deadline</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link href={`/leaver-reviews/${encodeURIComponent(r.id)}`}>{r.person}</Link>
                </td>
                <td>{r.entryCount}</td>
                <td>
                  {r.status}
                  {r.outcome ? ` (${r.outcome})` : ""}
                </td>
                <td>
                  {when(r.deadline)}
                  {r.kept ? <span className="muted"> · extended</span> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
