import type { components } from "@contracts/knowledge";

type KnowledgeEntry = components["schemas"]["KnowledgeEntry"];

export function Entry({ entry }: { entry: KnowledgeEntry }) {
  return (
    <div className="entry">
      <strong>{entry.title}</strong>{" "}
      <span className="muted">
        {entry.key} · {entry.type} · {entry.dataClass} · by {entry.contributor}
      </span>
      <pre>{entry.body}</pre>
    </div>
  );
}

export function when(timestamp: string | undefined): string {
  return timestamp ? new Date(timestamp).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "";
}
