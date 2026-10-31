"""Sources, indexing and permission-preserving retrieval (FR-503, invariant 1).

HUMAN REVIEW REQUIRED (CLAUDE.md): the authorisation path in retrieve().

retrieve() works in these steps:

0. For an Entra caller, the delegation first: the control plane decides now whether the person's
   own agent may act for them, and names the agent's template packs. Without one, only the
   caller's personal layer and mandatory packs are searched and every source is reported
   unavailable. With one, the packs in scope are the template's packs the caller asked for (all
   of them if none were named) plus mandatory packs; requested packs outside the template are
   reported and nothing from them is returned (invariant 2).
1. Candidates: full-text search over the caller's effective entries (resolve() precedence, so
   other people's personal layers never appear) and over the indexed documents of the packs in
   scope.
2. Authorisation, live and per person: candidates are grouped by source and each source's
   connector answers authorise(principal, ids) under the acting person's own rights (for an
   Entra caller, with the token delegated to their agent). Nothing is cached.
3. Only documents named in that same answer are returned. If a source cannot answer, all its
   documents are withheld and the source is reported unavailable; there is no fallback to a
   broader index (PRD section 12a).

Ranking is PostgreSQL full-text search ('simple' configuration, language-neutral). Embeddings
need the model gateway (D28) and come later.
"""

from __future__ import annotations

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

from psycopg import Cursor
from psycopg.types.json import Jsonb

from muistamo_knowledge.connectors import Connector, NotBuilt, Principal
from muistamo_knowledge.delegation import Outcome
from muistamo_knowledge.service import Actor, Forbidden, Invalid, Knowledge, NotFound

log = logging.getLogger("muistamo.knowledge.retrieval")

AUTHORISE_TIMEOUT_SECONDS = 5.0
DELEGATION_TIMEOUT_SECONDS = 5.0
# Every source's authorisation together, after the delegation: what is left over is withheld.
RETRIEVAL_BUDGET_SECONDS = 15.0
CANDIDATE_POOL = 200
HEADLINE = "MaxWords=35, MinWords=12, StartSel=, StopSel=, HighlightAll=false"

_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="authorise")


class Sources:
    def __init__(self, knowledge: Knowledge) -> None:
        self.k = knowledge

    # Sources --------------------------------------------------------------------------------

    def connector(self, source: str, document: dict[str, Any], tenant: uuid.UUID) -> Connector:
        spec = document["spec"]
        factory = self.k.connectors.get(spec["connector"])
        if factory is None:
            raise Invalid(f"connector {spec['connector']!r} is not enabled on this service")
        try:
            return factory(source, spec, tenant)
        except (NotBuilt, ValueError) as exc:
            raise Invalid(str(exc)) from exc

    def apply(
        self, actor: Actor, name: str, document: dict[str, Any]
    ) -> tuple[dict[str, Any], bool]:
        if document["metadata"]["name"] != name:
            raise Invalid(
                f"path name {name!r} does not match metadata.name {document['metadata']['name']!r}"
            )
        spec = document["spec"]
        self.connector(
            name, document, actor.tenant
        )  # refuses unknown, disabled or unbuilt connectors
        with self.k.db.in_tenant(actor.tenant) as cur:
            self._require_reviewer(cur, actor, spec["pack"])
            cur.execute(
                "SELECT document, pack FROM knowledge.sources WHERE name = %s FOR UPDATE", (name,)
            )
            row = cur.fetchone()
            if row is not None and row[0] == document:
                return self._record(cur, name), False
            if row is not None and row[1] != spec["pack"]:
                # Moving a source between packs would change who may search it; do it explicitly.
                raise Invalid("a source cannot move to another pack; create a new source instead")
            if row is None:
                cur.execute(
                    "INSERT INTO knowledge.sources (tenant_id, name, pack, connector, document) VALUES (%s, %s, %s, %s, %s)",
                    (actor.tenant, name, spec["pack"], spec["connector"], Jsonb(document)),
                )
            else:
                cur.execute(
                    "UPDATE knowledge.sources SET connector = %s, document = %s, updated_at = now() WHERE name = %s",
                    (spec["connector"], Jsonb(document), name),
                )
            # Evidence names the configuration, never document content (invariant 5).
            documents = len((spec.get("test") or {}).get("documents", []))
            self.k._evidence(
                cur,
                actor,
                "knowledge.source.applied",
                "KnowledgeSource",
                name,
                after={
                    "pack": spec["pack"],
                    "connector": spec["connector"],
                    "configuredDocuments": documents,
                },
            )
            return self._record(cur, name), row is None

    def get(self, actor: Actor, name: str) -> dict[str, Any]:
        with self.k.db.in_tenant(actor.tenant) as cur:
            return self._record(cur, name)

    def list(self, actor: Actor) -> list[dict[str, Any]]:
        with self.k.db.in_tenant(actor.tenant) as cur:
            cur.execute("SELECT name FROM knowledge.sources ORDER BY name")
            return [self._record(cur, r[0]) for r in cur.fetchall()]

    def sync(self, actor: Actor, name: str) -> dict[str, Any]:
        with self.k.db.in_tenant(actor.tenant) as cur:
            document = self._document(cur, name)
            self._require_reviewer(cur, actor, document["spec"]["pack"])
        listed = self.connector(
            name, document, actor.tenant
        ).list_documents()  # outside the transaction
        with self.k.db.in_tenant(actor.tenant) as cur:
            self._require_reviewer(cur, actor, document["spec"]["pack"])
            ids = [d.external_id for d in listed]
            for d in listed:
                cur.execute(
                    "INSERT INTO knowledge.documents (tenant_id, source, external_id, title, url, body, modified_at)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)"
                    " ON CONFLICT (tenant_id, source, external_id) DO UPDATE SET title = EXCLUDED.title,"
                    " url = EXCLUDED.url, body = EXCLUDED.body, modified_at = EXCLUDED.modified_at, indexed_at = now()",
                    (actor.tenant, name, d.external_id, d.title, d.url, d.body, d.modified_at),
                )
            cur.execute(
                "DELETE FROM knowledge.documents WHERE source = %s AND NOT (external_id = ANY(%s))",
                (name, ids),
            )
            removed = cur.rowcount
            cur.execute(
                "UPDATE knowledge.sources SET last_synced_at = now() WHERE name = %s", (name,)
            )
            result = {
                "source": name,
                "indexed": len(listed),
                "removed": removed,
                "total": len(listed),
            }
            self.k._evidence(
                cur, actor, "knowledge.source.synced", "KnowledgeSource", name, after=result
            )
            return result

    def _require_reviewer(self, cur: Cursor, actor: Actor, pack: str) -> None:
        if actor.name not in self.k._pack(cur, pack)["reviewers"]:
            raise Forbidden("only the pack's reviewers can manage its sources")

    def _document(self, cur: Cursor, name: str) -> dict[str, Any]:
        cur.execute("SELECT document FROM knowledge.sources WHERE name = %s", (name,))
        row = cur.fetchone()
        if row is None:
            raise NotFound(f"source {name!r}")
        return row[0]

    def _record(self, cur: Cursor, name: str) -> dict[str, Any]:
        cur.execute(
            "SELECT s.document, s.last_synced_at, s.created_at, s.updated_at,"
            " (SELECT count(*) FROM knowledge.documents d WHERE d.tenant_id = s.tenant_id AND d.source = s.name)"
            " FROM knowledge.sources s WHERE s.name = %s",
            (name,),
        )
        row = cur.fetchone()
        if row is None:
            raise NotFound(f"source {name!r}")
        record = {
            "document": row[0],
            "createdAt": row[2],
            "updatedAt": row[3],
            "documentCount": row[4],
        }
        if row[1] is not None:
            record["lastSyncedAt"] = row[1]
        return record

    # Retrieval ------------------------------------------------------------------------------

    def retrieve(
        self,
        actor: Actor,
        query: str,
        packs: list[str],
        limit: int = 10,
        tool: str = "rest.retrieve",
    ) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        coverage: dict[str, Any] = {}
        principal = Principal(person=actor.name)
        searchable = True
        agent: str | None = None
        template: set[str] | None = None
        deadline = time.monotonic() + RETRIEVAL_BUDGET_SECONDS
        # Every Entra caller is delegated: an entra: identity never gets development scope, even
        # if its token was somehow not carried along (fail closed).
        if actor.name.startswith("entra:"):
            outcome = (
                self._delegate(actor) if actor.bearer is not None else Outcome(None, "unavailable")
            )
            if outcome.delegation is None:
                coverage["delegation"] = {
                    "status": "unavailable"
                    if outcome.reason in ("unavailable", "not-configured")
                    else "refused",
                    "reason": outcome.reason or "unavailable",
                }
                # Only the person's own layer and what everyone must see; no source is asked.
                packs, searchable = [], False
            else:
                delegation = outcome.delegation
                agent = delegation.instance
                coverage["delegation"] = {"status": "issued", "agent": agent}
                template = set(delegation.packs)
                principal = Principal(person=actor.name, graph_token=delegation.graph_token)
        with self.k.db.in_tenant(actor.tenant) as cur:
            if template is not None:
                packs = self._within_template(cur, packs, template, coverage)
            names, effective = self.k._resolve(cur, actor, packs)
            items += self._entry_hits(cur, query, effective)
            cur.execute(
                "SELECT name, document FROM knowledge.sources WHERE pack = ANY(%s) ORDER BY name",
                (names,),
            )
            sources = {r[0]: r[1] for r in cur.fetchall()}
            candidates = self._document_candidates(cur, query, list(sources)) if searchable else []
        # Remote authorisation runs outside the transaction, so no database lock waits on a source.

        unavailable: list[str] = []
        test_sources: list[str] = []
        by_source: dict[str, list[dict[str, Any]]] = {}
        for c in candidates:
            by_source.setdefault(c["source"], []).append(c)
        for source, document in sources.items():
            if not searchable:
                unavailable.append(source)
                continue
            try:
                connector = self.connector(source, document, actor.tenant)
            except Invalid:
                unavailable.append(source)
                continue
            if connector.is_test:
                test_sources.append(source)
            hits = by_source.get(source, [])
            if not hits:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # The retrieval budget is spent: the rest are withheld, never returned unchecked.
                unavailable.append(source)
                continue
            permitted = self._authorise(
                connector, principal, [h["externalId"] for h in hits], remaining
            )
            if permitted is None:
                unavailable.append(source)
                continue
            for h in hits:
                if h["externalId"] in permitted:
                    items.append(_document_item(h, connector.name))

        items.sort(key=lambda i: i["score"], reverse=True)
        result = {
            "query": query,
            "items": items[:limit],
            "coverage": {
                "sourcesQueried": sorted(sources),
                "sourcesUnavailable": sorted(unavailable),
                "testConnectors": sorted(test_sources),
                **coverage,
            },
        }
        self.record_read(actor, tool, result["items"], agent)
        return result

    def record_read(
        self, actor: Actor, tool: str, items: list[dict[str, Any]], agent: str | None = None
    ) -> None:
        """Record what the person was shown, and through which agent: citations only, never the
        query (invariant 5)."""
        keep = ("type", "entryKey", "layer", "pack", "version", "source", "externalId")
        citations = [{k: v for k, v in i["citation"].items() if k in keep} for i in items]
        with self.k.db.in_tenant(actor.tenant) as cur:
            cur.execute(
                "INSERT INTO knowledge.reads (tenant_id, id, person, tool, result_count, citations, agent)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (actor.tenant, uuid.uuid4(), actor.name, tool, len(items), Jsonb(citations), agent),
            )

    @staticmethod
    def _within_template(
        cur: Cursor, packs: list[str], template: set[str], coverage: dict[str, Any]
    ) -> list[str]:
        """The packs a delegated agent searches: the template's packs the caller asked for (all
        of them if none), of those that exist. Mandatory packs are added by _resolve and are
        never outside scope. Template packs missing here are reported, not fatal, and a requested
        pack outside the template is reported without saying whether it exists."""
        cur.execute(
            "SELECT name, mandatory FROM knowledge.packs WHERE mandatory OR name = ANY(%s)",
            (sorted(template),),
        )
        rows = cur.fetchall()
        existing = {name for name, _ in rows}
        mandatory = {name for name, is_mandatory in rows if is_mandatory}
        requested = set(packs)
        outside = sorted(requested - template - mandatory)
        missing = sorted(template - existing)
        if outside:
            coverage["packsOutsideAgentScope"] = outside
        if missing:
            coverage["packsUnavailable"] = missing
        scope = (requested & template) if requested else template
        return sorted(scope & existing)

    def reads(self, actor: Actor, limit: int = 100) -> list[dict[str, Any]]:
        """The caller's own reads, newest first."""
        with self.k.db.in_tenant(actor.tenant) as cur:
            cur.execute(
                "SELECT id, person, at, tool, result_count, citations, agent FROM knowledge.reads"
                " WHERE person = %s ORDER BY at DESC LIMIT %s",
                (actor.name, limit),
            )
            return [
                {
                    "id": r[0],
                    "person": r[1],
                    "at": r[2],
                    "tool": r[3],
                    "resultCount": r[4],
                    "citations": r[5],
                    **({"agent": r[6]} if r[6] is not None else {}),
                }
                for r in cur.fetchall()
            ]

    def _delegate(self, actor: Actor) -> Outcome:
        """The control plane's delegation for this request, or why there is none, within a
        wall-clock deadline."""
        client = self.k.delegations
        bearer = actor.bearer
        if client is None or bearer is None:
            return Outcome(None, "not-configured")
        future = _pool.submit(client.request, actor.tenant, bearer)
        try:
            return future.result(timeout=DELEGATION_TIMEOUT_SECONDS)
        except FutureTimeout:
            log.warning("delegation timed out; no sources", extra={"tenant": str(actor.tenant)})
            return Outcome(None, "unavailable")

    @staticmethod
    def _authorise(
        connector: Connector,
        principal: Principal,
        ids: list[str],
        budget: float = AUTHORISE_TIMEOUT_SECONDS,
    ) -> set[str] | None:
        """The person's permitted subset of ids, or None if the source could not answer."""
        future = _pool.submit(connector.authorise, principal, ids)
        try:
            allowed = future.result(timeout=min(budget, AUTHORISE_TIMEOUT_SECONDS))
        except FutureTimeout:
            log.warning(
                "authorisation timed out; withholding source", extra={"connector": connector.name}
            )
            return None
        except Exception as exc:  # noqa: BLE001 - any failure withholds the source (fail closed)
            # Only the error's type: a source's message may carry the delegated token.
            log.warning(
                "authorisation failed; withholding source",
                extra={"connector": connector.name, "error": type(exc).__name__},
            )
            return None
        # Never trust a connector to return only what it was asked about.
        return set(allowed) & set(ids)

    @staticmethod
    def _entry_hits(
        cur: Cursor, query: str, effective: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        by_id = {str(item["entry"]["id"]): item for item in effective}
        if not by_id:
            return []
        cur.execute(
            "SELECT e.id, ts_rank(to_tsvector('simple', e.title || ' ' || e.body), q),"
            " ts_headline('simple', e.body, q, %s)"
            " FROM knowledge.entries e, plainto_tsquery('simple', %s) q"
            " WHERE e.id = ANY(%s::uuid[]) AND to_tsvector('simple', e.title || ' ' || e.body) @@ q",
            (HEADLINE, query, list(by_id)),
        )
        hits = []
        for entry_id, score, snippet in cur.fetchall():
            item = by_id[str(entry_id)]
            entry = item["entry"]
            citation: dict[str, Any] = {
                "type": "entry",
                "layer": item["layer"],
                "entryKey": entry["key"],
            }
            if "pack" in item:
                citation |= {"pack": item["pack"], "version": item["version"]}
            hit = {
                "title": entry["title"],
                "snippet": snippet,
                "score": float(score),
                "citation": citation,
            }
            # Decay and provenance travel with the hit; they never change its rank (FR-307).
            for extra in ("decay", "provenance"):
                if extra in item:
                    hit[extra] = item[extra]
            hits.append(hit)
        return hits

    @staticmethod
    def _document_candidates(cur: Cursor, query: str, sources: list[str]) -> list[dict[str, Any]]:
        if not sources:
            return []
        cur.execute(
            "SELECT d.source, d.external_id, d.title, d.url, d.modified_at, ts_rank(d.tsv, q),"
            " ts_headline('simple', d.body, q, %s)"
            " FROM knowledge.documents d, plainto_tsquery('simple', %s) q"
            " WHERE d.source = ANY(%s) AND d.tsv @@ q ORDER BY ts_rank(d.tsv, q) DESC LIMIT %s",
            (HEADLINE, query, sources, CANDIDATE_POOL),
        )
        return [
            {
                "source": r[0],
                "externalId": r[1],
                "title": r[2],
                "url": r[3],
                "modifiedAt": r[4],
                "score": float(r[5]),
                "snippet": r[6],
            }
            for r in cur.fetchall()
        ]


def _document_item(hit: dict[str, Any], connector: str) -> dict[str, Any]:
    citation: dict[str, Any] = {
        "type": "document",
        "source": hit["source"],
        "connector": connector,
        "externalId": hit["externalId"],
    }
    if hit["url"]:
        citation["url"] = hit["url"]
    if hit["modifiedAt"] is not None:
        citation["modifiedAt"] = hit["modifiedAt"]
    return {
        "title": hit["title"],
        "snippet": hit["snippet"],
        "score": hit["score"],
        "citation": citation,
    }
