import Link from "next/link";

import { type Result, api } from "@/lib/api";
import { requireSession } from "@/lib/session";

function count<T>(result: Result<{ items: T[] }>, open: (item: T) => boolean) {
  return result.ok ? String(result.data.items.filter(open).length) : `${result.problem.status}`;
}

export default async function Home() {
  const session = await requireSession();
  const [proposals, reviews, catalogue] = await Promise.all([
    api.reviewerProposals(session),
    api.leaverReviews(session),
    api.pendingCatalogueRequests(session),
  ]);
  return (
    <>
      <h1>Waiting for you</h1>
      <div className="cards">
        <Link href="/proposals">
          <strong>{count(proposals, (p) => p.status === "in-review")}</strong>
          knowledge proposals to review
        </Link>
        <Link href="/leaver-reviews">
          <strong>{count(reviews, (r) => r.status === "open")}</strong>
          leaver reviews open
        </Link>
        <Link href="/catalogue">
          <strong>{count(catalogue, () => true)}</strong>
          catalogue requests pending
        </Link>
      </div>
      <p className="muted">A number like 403 is the service&apos;s answer for that inbox; open it to see why.</p>
    </>
  );
}
