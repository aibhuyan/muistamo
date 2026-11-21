import Link from "next/link";

import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { when } from "../entry";
import { Refusal } from "../refusal";
import { afterParam } from "../workforce";
import { hideEmails } from "./record";

// The control plane's evidence chain, in chain order, for console auditors (D70). Read-only. The
// page shows the chain; it does not say whether the chain verifies. A verdict computed by the
// control plane with its own stored keys would be the system vouching for itself, so the page says
// how to verify it independently instead.
export default async function EvidencePage(props: { searchParams?: Promise<Record<string, string | string[] | undefined>> }) {
  const session = await requireSession();
  const after = afterParam(await props.searchParams);
  const result = await api.events(session, after);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const { items, nextAfterSeq } = result.data;
  return (
    <div className="page">
      <div className="page-head">
        <h1>Evidence log</h1>
        <p className="lede">
          The control plane&apos;s signed record of consequential actions. Each event is written in the same transaction as
          the action it describes and carries the hash of the one before it, so changing an event, or removing one from
          the middle, breaks the chain.
        </p>
      </div>
      <div className="notice">
        <strong>Checking this chain</strong>
        <span>
          This page shows the chain; it does not vouch for it. To check it, export the chain and verify the file against
          the public key recorded when the signing key was created:
        </span>
        <code>mst evidence export -o chain.jsonl --tenant TENANT --actor YOU</code>
        <code>mst evidence verify -f chain.jsonl --public-key signing-key.pub</code>
        <span>
          Today <code className="inline">mst</code> reaches the control plane only with development sign-in, so in
          production your operator runs the export. Verifying shows that no event was changed or removed from the middle;
          it cannot show that the newest events were not removed. Keep the latest event&apos;s number and hash, and compare
          them next time.
        </span>
      </div>
      <p className="muted">
        This is the control plane&apos;s chain. The knowledge service keeps its own chain, which privacy officers export
        with <code>mst evidence export --knowledge -o knowledge.jsonl</code>.
      </p>
      {items.length === 0 ? (
        <p>{after > 0 ? "No more events." : "No events yet."}</p>
      ) : (
        <div className="panel scroll">
          <table>
            <thead>
              <tr>
                <th>Event</th>
                <th>Recorded</th>
                <th>Action</th>
                <th>About</th>
                <th>By</th>
                <th>Hash, after</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.seq}>
                  <td>
                    <Link href={`/evidence/${e.seq}`}>{e.seq}</Link>
                  </td>
                  <td className="nowrap muted">{when(e.occurredAt)}</td>
                  <td className="mono">{e.action}</td>
                  {/* The kind only: a subject's name can be a person's HR id; it is on the event's page. */}
                  <td>{e.subject.kind}</td>
                  <td className="mono">{hideEmails(e.actor)}</td>
                  <td className="mono nowrap">
                    {e.hash.slice(0, 12)}
                    <br />
                    <span className="muted">{e.prevHash.slice(0, 12)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {after > 0 || nextAfterSeq !== undefined ? (
        <nav aria-label="Pages" className="pager">
          {after > 0 ? <Link href="/evidence">First page</Link> : null}
          {nextAfterSeq !== undefined ? <Link href={`/evidence?after=${nextAfterSeq}`}>Next page</Link> : null}
        </nav>
      ) : null}
    </div>
  );
}
