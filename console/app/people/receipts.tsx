import Link from "next/link";

import type { HrReceipt } from "@/lib/api";

import { Pill, label, when } from "../entry";
import { personHref } from "../workforce";

// A person by HR id, linked to their page when the id can be addressed from the console.
export function PersonId({ personId }: { personId: string }) {
  const href = personHref(personId);
  return href ? (
    <Link href={href} className="mono">
      {personId}
    </Link>
  ) : (
    <span className="mono">{personId}</span>
  );
}

// Whether the workflow still uses the event's HR details (email, manager). Released says only that:
// not that the workflow, a grace period or provider clean-up has finished.
function HrDetails({ receipt }: { receipt: HrReceipt }) {
  if (receipt.decision !== "accepted") return <span className="muted">Not applicable</span>;
  return receipt.setupCompleted ? <>Released</> : <span className="muted">In use</span>;
}

// HR events as rows, for the feed and for a person's page.
export function ReceiptRows({ items, showPerson }: { items: HrReceipt[]; showPerson: boolean }) {
  return (
    <div className="panel scroll">
      <table>
        <thead>
          <tr>
            <th>Received</th>
            <th>Event</th>
            {showPerson ? <th>Person</th> : null}
            <th>Takes effect</th>
            <th>Decision</th>
            <th>Workflow</th>
            <th>HR details</th>
          </tr>
        </thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.eventId}>
              <td className="nowrap muted">{when(r.receivedAt)}</td>
              <td>
                {label(r.type)} <span className="mono muted">{r.eventId}</span>
              </td>
              {showPerson ? (
                <td>
                  <PersonId personId={r.personId} />
                </td>
              ) : null}
              <td className="nowrap muted">{when(r.occurredAt)}</td>
              <td>
                <Pill value={r.decision} />
              </td>
              <td>
                <Pill value={r.dispatchState} />
              </td>
              <td>
                <HrDetails receipt={r} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
