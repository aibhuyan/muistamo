import Link from "next/link";

import { type Result, api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { day } from "./entry";

// One inbox on the home page: how many items wait, or the service's refusal status in place of
// the number. The console never turns a refusal into a zero.
function Inbox<T>({
  href,
  result,
  open,
  what,
  detail,
  go,
}: {
  href: string;
  result: Result<{ items: T[] }>;
  open: (item: T) => boolean;
  what: string;
  detail: (waiting: T[]) => string;
  go: string;
}) {
  const waiting = result.ok ? result.data.items.filter(open) : [];
  return (
    <Link href={href}>
      <span className={result.ok ? "queue-count" : "queue-count refused"}>
        {result.ok ? String(waiting.length) : `${result.problem.status}`}
      </span>
      <span className="queue-what">
        <strong>{what}</strong>
        <span className="muted">
          {result.ok ? (waiting.length === 0 ? "Nothing is waiting." : detail(waiting)) : "The service refused this inbox. Open it to read why."}
        </span>
      </span>
      <span className="queue-go">{go}</span>
    </Link>
  );
}

// The earliest of some timestamps, as a date. ISO 8601 UTC strings sort as text.
function earliest(timestamps: string[]): string {
  return day([...timestamps].sort()[0]);
}

export default async function Home() {
  const session = await requireSession();
  const [proposals, reviews, catalogue] = await Promise.all([
    api.reviewerProposals(session),
    api.leaverReviews(session),
    api.pendingCatalogueRequests(session),
  ]);
  return (
    <div className="page narrow">
      <div className="page-head">
        <h1>Waiting for you</h1>
        <p className="lede">Decisions only you can make. The services record each one as evidence before it takes effect.</p>
      </div>
      <div className="panel queue">
        <Inbox
          href="/proposals"
          result={proposals}
          open={(p) => p.status === "in-review"}
          what="Knowledge proposals to review"
          detail={(waiting) => `The oldest was created on ${earliest(waiting.map((p) => p.createdAt))}.`}
          go="Review"
        />
        <Inbox
          href="/leaver-reviews"
          result={reviews}
          open={(r) => r.status === "open"}
          what="Leaver reviews open"
          detail={(waiting) => `The next deadline is ${earliest(waiting.map((r) => r.deadline))}. Undecided entries are purged then.`}
          go="Decide"
        />
        <Inbox
          href="/catalogue"
          result={catalogue}
          open={() => true}
          what="Catalogue requests pending"
          detail={(waiting) => {
            const high = waiting.filter((c) => c.riskTier === "high").length;
            return high === 0 ? "None is high risk." : `${high} high risk, needing two approvers.`;
          }}
          go="Approve or reject"
        />
      </div>
      <p className="muted">A number like 403 is the service&apos;s answer for that inbox; open it to see why.</p>
    </div>
  );
}
