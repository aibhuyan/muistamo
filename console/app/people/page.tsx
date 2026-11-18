import { api } from "@/lib/api";
import { requireSession } from "@/lib/session";

import { Refusal } from "../refusal";
import { Pager, cursorParam } from "../workforce";
import { ReceiptRows } from "./receipts";

// HR events as the control plane received and decided them, newest first, for console
// administrators (D70). Read-only. People are named by HR id only: nothing from the HR system's
// payload (email, job code, manager) reaches this page.
export default async function PeoplePage(props: { searchParams?: Promise<Record<string, string | string[] | undefined>> }) {
  const session = await requireSession();
  const cursor = cursorParam(await props.searchParams);
  const result = await api.hrReceipts(session, cursor);
  if (!result.ok) return <Refusal problem={result.problem} />;
  const { items, nextCursor } = result.data;
  return (
    <div className="page">
      <div className="page-head">
        <h1>People</h1>
        <p className="lede">
          Joiner and leaver events from your HR system, as Muistamo received and decided them, newest first. Ignored
          and cancelled events are listed too: an event that changed nothing is worth seeing.
        </p>
      </div>
      {items.length === 0 ? (
        <p>{cursor ? "No more HR events." : "No HR events yet."}</p>
      ) : (
        <ReceiptRows items={items} showPerson />
      )}
      <Pager path="/people" cursor={cursor} nextCursor={nextCursor} />
    </div>
  );
}
