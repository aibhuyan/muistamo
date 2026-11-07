import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { DecisionForm } from "../decision-form";
import { when } from "../entry";
import { Refusal } from "../refusal";
import { deleteEntry, setEntryVisibility } from "./actions";

export default async function MyKnowledgePage() {
  const session = await requireSession();
  const result = await api.personalEntries(session);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const items = result.data.items;
  return (
    <>
      <h1>My knowledge</h1>
      <p className="muted">
        What you taught your assistants. Only you see these entries. A private entry is never proposed, never shown
        to anyone at your leaver review, and deleted when you leave. Your own assistant still reads it to help you;
        private stops your manager seeing it, not your assistant repeating what it read.
      </p>
      <p className="muted">
        An assistant can make an entry private, but only you, here, can share it again or delete a private entry.
      </p>
      {items.length === 0 ? (
        <p>No entries.</p>
      ) : (
        items.map((e) => (
          <section key={e.id} className="entry">
            <strong>{e.title}</strong>{" "}
            <span className="muted">
              {e.key} · {e.type} · {when(e.createdAt)}
            </span>{" "}
            <span className={e.private ? "badge private" : "badge"}>{e.private ? "Private" : "Shared"}</span>
            <pre>{e.body}</pre>
            <DecisionForm
              action={setEntryVisibility.bind(null, e.id)}
              submit={e.private ? "Share again" : "Make private"}
            >
              <input type="hidden" name="private" value={e.private ? "false" : "true"} />
              {e.private ? (
                <p className="muted">Shared again, it can be proposed and is shown at your leaver review.</p>
              ) : null}
            </DecisionForm>
            <DecisionForm action={deleteEntry.bind(null, e.id)} submit="Delete">
              <label>
                <input type="checkbox" name="confirm" value="yes" required /> Delete this entry for good
              </label>
            </DecisionForm>
          </section>
        ))
      )}
    </>
  );
}
