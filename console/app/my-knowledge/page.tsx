import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { DecisionForm } from "../decision-form";
import { Pill, label, when } from "../entry";
import { Refusal } from "../refusal";
import { deleteEntry, setEntryVisibility } from "./actions";

export default async function MyKnowledgePage() {
  const session = await requireSession();
  const result = await api.personalEntries(session);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const items = result.data.items;
  return (
    <div className="page narrow">
      <div className="page-head">
        <h1>My knowledge</h1>
        <p className="lede">What you taught your assistants. Only you see this list.</p>
      </div>
      <div className="fields">
        <div className="panel padded stack">
          <span>
            <Pill tone="ok">Shared entries</Pill>
          </span>
          <p>Can be proposed to a pack, and are shown to whoever decides your leaver review.</p>
        </div>
        <div className="panel padded stack">
          <span>
            <Pill tone="info">Private entries</Pill>
          </span>
          <p>
            Never proposed, never shown at your leaver review, and deleted when you leave; a privacy officer answering
            a data-access request can still export them. Your own assistant still reads private entries to help you:
            private stops your manager seeing them, not your assistant repeating what it read.
          </p>
        </div>
      </div>
      <p className="muted">
        An assistant can make an entry private, but only you, here, can share it again or delete a private entry.
      </p>
      {items.length === 0 ? (
        <p>No entries.</p>
      ) : (
        items.map((e) => (
          <section key={e.id} className="entry">
            <div className="entry-head">
              <div className="entry-title">
                <strong>{e.title}</strong>
                <Pill tone={e.private ? "info" : "ok"}>{e.private ? "Private" : "Shared"}</Pill>
              </div>
              <div className="meta">
                <span className="mono">{e.key}</span>
                <span>{label(e.type)}</span>
                <span>Taught {when(e.createdAt)}</span>
              </div>
            </div>
            <pre>{e.body}</pre>
            <div className="entry-actions">
              <DecisionForm
                action={setEntryVisibility.bind(null, e.id)}
                submit={e.private ? "Share again" : "Make private"}
                tone="quiet"
              >
                <input type="hidden" name="private" value={e.private ? "false" : "true"} />
                {e.private ? (
                  <p className="hint">Shared again, it can be proposed and is shown at your leaver review.</p>
                ) : null}
              </DecisionForm>
              <DecisionForm action={deleteEntry.bind(null, e.id)} submit="Delete" tone="danger">
                <label className="check">
                  <input type="checkbox" name="confirm" value="yes" required /> Delete this entry for good
                </label>
                {e.private ? null : <p className="hint">Copies you already proposed to a pack stay with its reviewers.</p>}
              </DecisionForm>
            </div>
          </section>
        ))
      )}
    </div>
  );
}
