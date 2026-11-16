import Link from "next/link";

import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { Pill, label, when } from "../entry";
import { Refusal } from "../refusal";

export default async function LeaverReviewsPage() {
  const session = await requireSession();
  const result = await api.leaverReviews(session);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const items = result.data.items;
  return (
    <div className="page">
      <div className="page-head">
        <h1>Leaver reviews</h1>
        <p className="lede">
          Leavers&apos; personal knowledge you decide. While a review is open the layer is frozen; without a decision
          it is purged at the deadline.
        </p>
      </div>
      {items.length === 0 ? (
        <p>No reviews.</p>
      ) : (
        <div className="panel scroll">
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
                    <Pill value={r.status} />
                    {r.outcome ? <span className="muted"> {label(r.outcome)}</span> : null}
                  </td>
                  <td className="nowrap">
                    {when(r.deadline)}
                    {r.kept ? <span className="muted">, extended</span> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
