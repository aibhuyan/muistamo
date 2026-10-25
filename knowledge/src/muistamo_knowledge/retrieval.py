"""Sources, indexing and permission-preserving retrieval (FR-503, invariant 1).

HUMAN REVIEW REQUIRED (CLAUDE.md): the authorisation path in retrieve().

retrieve() works in three steps:

1. Candidates: full-text search over the caller's effective entries (resolve() precedence, so
   other people's personal layers never appear) and over the indexed documents of the packs in
   scope.
2. Authorisation, live and per person: candidates are grouped by source and each source's
   connector answers authorise(person, ids) under the acting person's own rights. Nothing is
   cached.
3. Only documents named in that same answer are returned. If a source cannot answer, all its
   documents are withheld and the source is reported unavailable; there is no fallback to a
   broader index (PRD section 12a).

Ranking is PostgreSQL full-text search ('simple' configuration, language-neutral). Embeddings
need the model gateway (D28) and come later.
"""

from __future__ import annotations

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

from psycopg import Cursor
from psycopg.types.json import Jsonb

from muistamo_knowledge.connectors import Connector, NotBuilt
from muistamo_knowledge.service import Actor, Forbidden, Invalid, Knowledge, NotFound

log = logging.getLogger("muistamo.knowledge.retrieval")

AUTHORISE_TIMEOUT_SECONDS = 5.0
CANDIDATE_POOL = 200
HEADLINE = "MaxWords=35, MinWords=12, StartSel=, StopSel=, HighlightAll=false"

_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="authorise")


class Sources:
    def __init__(self, knowledge: Knowledge) -> None:
        self.k = knowledge

    # Sources --------------------------------------------------------------------------------

    def connector(self, source: str, document: dict[str, Any]) -> Connector:
        spec = document["spec"]
        factory = self.k.connectors.get(spec["connector"])
        if factory is None:
            raise Invalid(f"connector {spec['connector']!r} is not enabled on this service")
        try:
            return factory(source, spec)
        except NotBuilt as exc:
            raise Invalid(str(exc)) from exc

    def apply(
        self, actor: Actor, name: str, document: dict[str, Any]
    ) -> tuple[dict[str, Any], bool]:
        if document["metadata"]["name"] != name:
            raise Invalid(
                f"path name {name!r} does not match metadata.name {document['metadata']['name']!r}"
            )
        spec = document["spec"]
        self.connector(name, document)  # refuses unknown, disabled or unbuilt connectors
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
        listed = self.connector(name, document).list_documents()  # outside the transaction
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
        with self.k.db.in_tenant(actor.tenant) as cur:
            names, effective = self.k._resolve(cur, actor, packs)
            items += self._entry_hits(cur, query, effective)
            cur.execute(
                "SELECT name, document FROM knowledge.sources WHERE pack = ANY(%s) ORDER BY name",
                (names,),
            )
            sources = {r[0]: r[1] for r in cur.fetchall()}
            candidates = self._document_candidates(cur, query, list(sources))
        # Remote authorisation runs outside the transaction, so no database lock waits on a source.

        unavailable: list[str] = []
        test_sources: list[str] = []
        by_source: dict[str, list[dict[str, Any]]] = {}
        for c in candidates:
            by_source.setdefault(c["source"], []).append(c)
        for source, document in sources.items():
            try:
                connector = self.connector(source, document)
            except Invalid:
                unavailable.append(source)
                continue
            if connector.is_test:
                test_sources.append(source)
            hits = by_source.get(source, [])
            if not hits:
                continue
            allowed = self._authorise(connector, actor.name, [h["externalId"] for h in hits])
            if allowed is None:
                unavailable.append(source)
                continue
            for h in hits:
                if h["externalId"] in allowed:
                    items.append(_document_item(h, connector.name))

        items.sort(key=lambda i: i["score"], reverse=True)
        result = {
            "query": query,
            "items": items[:limit],
            "coverage": {
                "sourcesQueried": sorted(sources),
                "sourcesUnavailable": sorted(unavailable),
                "testConnectors": sorted(test_sources),
            },
        }
        self.record_read(actor, tool, result["items"])
        return result

    def record_read(self, actor: Actor, tool: str, items: list[dict[str, Any]]) -> None:
        """Record what the person was shown: citations only, never the query (invariant 5)."""
        keep = ("type", "entryKey", "layer", "pack", "version", "source", "externalId")
        citations = [{k: v for k, v in i["citation"].items() if k in keep} for i in items]
        with self.k.db.in_tenant(actor.tenant) as cur:
            cur.execute(
                "INSERT INTO knowledge.reads (tenant_id, id, person, tool, result_count, citations)"
                " VALUES (%s, %s, %s, %s, %s, %s)",
                (actor.tenant, uuid.uuid4(), actor.name, tool, len(items), Jsonb(citations)),
            )

    def reads(self, actor: Actor, limit: int = 100) -> list[dict[str, Any]]:
        """The caller's own reads, newest first."""
        with self.k.db.in_tenant(actor.tenant) as cur:
            cur.execute(
                "SELECT id, person, at, tool, result_count, citations FROM knowledge.reads"
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
                }
                for r in cur.fetchall()
            ]

    @staticmethod
    def _authorise(connector: Connector, person: str, ids: list[str]) -> set[str] | None:
        """The person's permitted subset of ids, or None if the source could not answer."""
        future = _pool.submit(connector.authorise, person, ids)
        try:
            allowed = future.result(timeout=AUTHORISE_TIMEOUT_SECONDS)
        except FutureTimeout:
            log.warning(
                "authorisation timed out; withholding source", extra={"connector": connector.name}
            )
            return None
        except Exception as exc:  # noqa: BLE001 - any failure withholds the source (fail closed)
            log.warning(
                "authorisation failed; withholding source",
                extra={"connector": connector.name, "error": str(exc)},
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
            hits.append(
                {
                    "title": entry["title"],
                    "snippet": snippet,
                    "score": float(score),
                    "citation": citation,
                }
            )
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
