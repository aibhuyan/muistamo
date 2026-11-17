import Link from "next/link";
import { notFound } from "next/navigation";

import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { when } from "../../entry";
import { Refusal } from "../../refusal";

// The recorded state as it was signed, readable: JSON with two-space indents, or "None".
function recorded(value: unknown): string {
  return value === null || value === undefined ? "None" : JSON.stringify(value, null, 2);
}

// One evidence event, as recorded, for console auditors (D70). Read-only.
export default async function EvidenceEventPage({ params }: { params: Promise<{ seq: string }> }) {
  const raw = (await params).seq;
  if (!/^[1-9][0-9]{0,14}$/.test(raw)) notFound();
  const seq = Number(raw);
  const session = await requireSession();
  // The control plane lists the chain in order; the event is the one after seq - 1.
  const result = await api.events(session, seq - 1, 1);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const e = result.data.items[0];
  if (!e || e.seq !== seq) notFound();
  return (
    <div className="page narrow">
      <Link href="/evidence" className="back">
        Evidence log
      </Link>
      <h1>
        Event {e.seq}: <span className="mono">{e.action}</span>
      </h1>
      <dl className="panel facts">
        <div>
          <dt>Recorded</dt>
          <dd>{when(e.occurredAt)}</dd>
        </div>
        <div>
          <dt>By</dt>
          <dd className="mono">{e.actor}</dd>
        </div>
        <div>
          <dt>About</dt>
          <dd>
            {e.subject.kind} <span className="mono">{e.subject.name}</span>
          </dd>
        </div>
        <div>
          <dt>Request</dt>
          <dd className="mono">{e.requestId}</dd>
        </div>
      </dl>
      <section className="section">
        <h2>Chain</h2>
        <dl className="panel facts">
          <div>
            <dt>Hash</dt>
            <dd className="mono">{e.hash}</dd>
          </div>
          <div>
            <dt>Follows</dt>
            <dd className="mono">
              {e.seq > 1 ? <Link href={`/evidence/${e.seq - 1}`}>{e.prevHash}</Link> : `${e.prevHash} (the start)`}
            </dd>
          </div>
          <div>
            <dt>Signed with key</dt>
            <dd className="mono">{e.keyId}</dd>
          </div>
        </dl>
      </section>
      <section className="section">
        <h2>Before</h2>
        <pre className="panel padded record">{recorded(e.before)}</pre>
      </section>
      <section className="section">
        <h2>After</h2>
        <pre className="panel padded record">{recorded(e.after)}</pre>
      </section>
      <p className="muted">
        Shown as recorded, re-indented for reading; the export holds the exact signed form. Evidence is never rewritten,
        not even after an erasure: changing an event would break the chain from that event on.
      </p>
    </div>
  );
}
