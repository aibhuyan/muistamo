import type { components } from "@contracts/knowledge";
import type { ReactNode } from "react";

type KnowledgeEntry = components["schemas"]["KnowledgeEntry"];

export function Entry({ entry }: { entry: KnowledgeEntry }) {
  return (
    <article className="entry">
      <div className="entry-head">
        <strong>{entry.title}</strong>
        <div className="meta">
          <span className="mono">{entry.key}</span>
          <span>{label(entry.type)}</span>
          <span>{label(entry.dataClass)}</span>
          <span>by {entry.contributor}</span>
        </div>
      </div>
      <pre>{entry.body}</pre>
    </article>
  );
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// A date in UTC, written the same for every reader: "7 Nov 2026".
export function day(timestamp: string | undefined): string {
  if (!timestamp) return "";
  const d = new Date(timestamp);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

// A moment in UTC: "7 Nov 2026, 10:00 UTC". Never the reader's local time: reviewers and auditors
// in different countries must read the same deadline.
export function when(timestamp: string | undefined): string {
  if (!timestamp) return "";
  const d = new Date(timestamp);
  if (Number.isNaN(d.getTime())) return "";
  const two = (n: number) => String(n).padStart(2, "0");
  return `${day(timestamp)}, ${two(d.getUTCHours())}:${two(d.getUTCMinutes())} UTC`;
}

// A service value such as "in-review" as a person reads it: "In review". The value itself is
// never changed, only its spelling.
export function label(value: string): string {
  const words = value.replaceAll("-", " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// A recorded decision in the past tense: "approve" was the choice, "Approved" is what happened.
export function decided(decision: string): string {
  return { approve: "Approved", reject: "Rejected" }[decision] ?? label(decision);
}

type Tone = "ok" | "wait" | "stop" | "info" | "neutral";

const TONES: Record<string, Tone> = {
  // proposals
  "in-review": "wait",
  approved: "ok",
  rejected: "neutral",
  "checks-failed": "stop",
  // leaver reviews
  open: "wait",
  closed: "neutral",
  // catalogue risk tiers and check severities
  high: "stop",
  medium: "wait",
  low: "neutral",
  blocking: "stop",
  warning: "wait",
};

// A status as a word on a tinted ground. A value the console does not know is shown neutrally,
// as the service spelt it.
export function Pill({ value, tone, children }: { value?: string; tone?: Tone; children?: ReactNode }) {
  const resolved = tone ?? (value ? TONES[value] : undefined) ?? "neutral";
  return <span className={resolved === "neutral" ? "pill" : `pill pill-${resolved}`}>{children ?? (value ? label(value) : "")}</span>;
}
