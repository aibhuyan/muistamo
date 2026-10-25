"""Knowledge packs, personal layers, proposals, review and resolution (FR-301-306).

HUMAN REVIEW REQUIRED (CLAUDE.md): the authorisation rules here. A personal layer is visible
to its owner only. Only a pack's reviewers decide proposals or roll back, and never on their
own proposal. Anything the caller may not see is reported as not found, so existence does not
leak.

Every write records a signed evidence event in the same transaction (invariant 4).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from psycopg import Cursor
from psycopg.types.json import Jsonb

from muistamo_knowledge import checks, evidence
from muistamo_knowledge.connectors import ConnectorFactory
from muistamo_knowledge.db import Database

LAYER_PRECEDENCE = {"personal": 0, "team": 1, "role": 2, "company": 3}


class NotFound(Exception):
    pass


class Forbidden(Exception):
    pass


class Conflict(Exception):
    pass


class Invalid(Exception):
    pass


@dataclass(frozen=True)
class Actor:
    tenant: UUID
    name: str
    request_id: str


def bump_minor(version: str) -> str:
    major, minor, _ = (int(p) for p in version.split("."))
    return f"{major}.{minor + 1}.0"


class Knowledge:
    def __init__(
        self,
        db: Database,
        signer: evidence.LocalKey,
        connectors: dict[str, ConnectorFactory] | None = None,
    ) -> None:
        self.db = db
        self.signer = signer
        self.connectors = connectors or {}

    def _evidence(
        self,
        cur: Cursor,
        actor: Actor,
        action: str,
        kind: str,
        name: str,
        after: Any,
        before: Any = None,
    ) -> None:
        evidence.append(
            cur,
            self.signer,
            tenant=actor.tenant,
            actor=actor.name,
            action=action,
            subject_kind=kind,
            subject_name=name,
            request_id=actor.request_id,
            before=before,
            after=after,
        )

    # Packs ----------------------------------------------------------------------------------

    def apply_pack(
        self, actor: Actor, name: str, document: dict[str, Any]
    ) -> tuple[dict[str, Any], bool]:
        """Create or update a pack definition. Content changes only through proposals."""
        if document["metadata"]["name"] != name:
            raise Invalid(
                f"path name {name!r} does not match metadata.name {document['metadata']['name']!r}"
            )
        spec = document["spec"]
        requires_eval = "evaluation" in (spec.get("mergePolicy") or {}).get("requires", [])
        with self.db.in_tenant(actor.tenant) as cur:
            cur.execute("SELECT document FROM knowledge.packs WHERE name = %s FOR UPDATE", (name,))
            row = cur.fetchone()
            if row is not None and row[0] == document:
                return self._pack_record(cur, name), False
            values = (
                spec["layer"],
                spec.get("mandatory", False),
                spec["reviewers"],
                requires_eval,
                Jsonb(document),
            )
            if row is None:
                cur.execute(
                    "INSERT INTO knowledge.packs (tenant_id, name, layer, mandatory, reviewers, requires_eval, document)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (actor.tenant, name, *values),
                )
            else:
                cur.execute(
                    "UPDATE knowledge.packs SET layer = %s, mandatory = %s, reviewers = %s, requires_eval = %s,"
                    " document = %s, updated_at = now() WHERE name = %s",
                    (*values, name),
                )
            self._evidence(
                cur,
                actor,
                "knowledge.pack.applied",
                "KnowledgePack",
                name,
                after=document,
                before=row[0] if row else None,
            )
            return self._pack_record(cur, name), row is None

    def get_pack(self, actor: Actor, name: str) -> dict[str, Any]:
        with self.db.in_tenant(actor.tenant) as cur:
            return self._pack_record(cur, name)

    def list_packs(self, actor: Actor) -> list[dict[str, Any]]:
        with self.db.in_tenant(actor.tenant) as cur:
            cur.execute("SELECT name FROM knowledge.packs ORDER BY name")
            return [self._pack_record(cur, r[0]) for r in cur.fetchall()]

    def _pack_record(self, cur: Cursor, name: str) -> dict[str, Any]:
        cur.execute(
            "SELECT document, latest_version, created_at, updated_at FROM knowledge.packs WHERE name = %s",
            (name,),
        )
        row = cur.fetchone()
        if row is None:
            raise NotFound(f"pack {name!r}")
        return {
            "document": row[0],
            "latestVersion": row[1],
            "createdAt": row[2],
            "updatedAt": row[3],
        }

    def _pack(self, cur: Cursor, name: str, lock: bool = False) -> dict[str, Any]:
        if lock:
            cur.execute(
                "SELECT layer, mandatory, reviewers, requires_eval, latest_version FROM knowledge.packs WHERE name = %s FOR UPDATE",
                (name,),
            )
        else:
            cur.execute(
                "SELECT layer, mandatory, reviewers, requires_eval, latest_version FROM knowledge.packs WHERE name = %s",
                (name,),
            )
        row = cur.fetchone()
        if row is None:
            raise NotFound(f"pack {name!r}")
        return {
            "layer": row[0],
            "mandatory": row[1],
            "reviewers": row[2],
            "requires_eval": row[3],
            "latest": row[4],
        }

    def list_versions(self, actor: Actor, name: str) -> list[dict[str, Any]]:
        with self.db.in_tenant(actor.tenant) as cur:
            self._pack(cur, name)
            cur.execute(
                "SELECT version FROM knowledge.pack_versions WHERE pack = %s ORDER BY created_at DESC, version DESC",
                (name,),
            )
            return [self._version(cur, name, r[0]) for r in cur.fetchall()]

    def get_version(self, actor: Actor, name: str, version: str) -> dict[str, Any]:
        with self.db.in_tenant(actor.tenant) as cur:
            return self._version(cur, name, version)

    def _version(self, cur: Cursor, pack: str, version: str) -> dict[str, Any]:
        cur.execute(
            "SELECT parent, reason, created_by, created_at FROM knowledge.pack_versions WHERE pack = %s AND version = %s",
            (pack, version),
        )
        row = cur.fetchone()
        if row is None:
            raise NotFound(f"pack {pack!r} version {version!r}")
        cur.execute(
            "SELECT e.id, e.key, e.type, e.title, e.body, e.source, e.data_class, e.contributor, e.created_at,"
            " v.proposal_id, v.reviewer FROM knowledge.pack_version_entries v"
            " JOIN knowledge.entries e ON e.tenant_id = v.tenant_id AND e.id = v.entry_id"
            " WHERE v.pack = %s AND v.version = %s ORDER BY v.key",
            (pack, version),
        )
        entries = [
            {"entry": _entry(r[:9]), "proposal": r[9], "reviewer": r[10]} for r in cur.fetchall()
        ]
        out = {
            "pack": pack,
            "version": version,
            "reason": row[1],
            "createdBy": row[2],
            "createdAt": row[3],
            "entries": entries,
        }
        if row[0] is not None:
            out["parent"] = row[0]
        return out

    # Personal layer -------------------------------------------------------------------------

    def capture(self, actor: Actor, entry: dict[str, Any]) -> dict[str, Any]:
        with self.db.in_tenant(actor.tenant) as cur:
            created = self._insert_entry(cur, actor.tenant, entry, contributor=actor.name)
            cur.execute(
                "INSERT INTO knowledge.personal_entries (tenant_id, owner, entry_id) VALUES (%s, %s, %s)",
                (actor.tenant, actor.name, created["id"]),
            )
            self._evidence(
                cur,
                actor,
                "knowledge.entry.captured",
                "KnowledgeEntry",
                str(created["id"]),
                after={"key": created["key"], "type": created["type"], "layer": "personal"},
            )
            return created

    def list_personal(self, actor: Actor) -> list[dict[str, Any]]:
        with self.db.in_tenant(actor.tenant) as cur:
            return self._personal(cur, actor)

    def _personal(self, cur: Cursor, actor: Actor) -> list[dict[str, Any]]:
        cur.execute(
            _ENTRY_SELECT
            + " JOIN knowledge.personal_entries p ON p.tenant_id = e.tenant_id AND p.entry_id = e.id"
            " WHERE p.owner = %s ORDER BY e.key, e.created_at",
            (actor.name,),
        )
        return [_entry(r) for r in cur.fetchall()]

    def delete_personal(self, actor: Actor, entry_id: UUID) -> None:
        """Delete one of the caller's own entries. Copies already submitted in proposals remain."""
        with self.db.in_tenant(actor.tenant) as cur:
            cur.execute(
                "DELETE FROM knowledge.personal_entries WHERE entry_id = %s AND owner = %s RETURNING entry_id",
                (entry_id, actor.name),
            )
            if cur.fetchone() is None:
                raise NotFound(f"entry {entry_id}")
            cur.execute("DELETE FROM knowledge.entries WHERE id = %s", (entry_id,))
            self._evidence(
                cur,
                actor,
                "knowledge.entry.deleted",
                "KnowledgeEntry",
                str(entry_id),
                after={"deleted": True, "layer": "personal"},
            )

    # Proposals ------------------------------------------------------------------------------

    def propose(
        self, actor: Actor, pack: str, entry_ids: list[UUID], summary: str
    ) -> dict[str, Any]:
        with self.db.in_tenant(actor.tenant) as cur:
            info = self._pack(cur, pack)
            own = {e["id"]: e for e in self._personal(cur, actor)}
            missing = [str(i) for i in entry_ids if i not in own]
            if missing:
                raise NotFound(f"entries {', '.join(missing)}")
            current = {
                e["entry"]["key"]: e["entry"]["body"]
                for e in self._version_entries(cur, pack, info["latest"])
            }

            proposal_id = uuid.uuid4()
            findings: list[checks.Finding] = []
            copies = []
            for entry_id in entry_ids:
                source = own[entry_id]
                findings += checks.check_entry(
                    source["key"], source["title"], source["body"], source.get("source")
                )
                findings += checks.duplicate(source["key"], source["body"], current)
                # The proposal holds its own revision, so deleting the personal entry later
                # does not break the proposal's lineage.
                copies.append(
                    self._insert_entry(
                        cur, actor.tenant, source, contributor=actor.name, derived_from=entry_id
                    )
                )
            status = "checks-failed" if checks.blocked(findings) else "in-review"
            check_json = [
                {
                    "ruleId": f.rule_id,
                    "severity": f.severity,
                    "entryKey": f.entry_key,
                    "message": f.message,
                }
                for f in findings
            ]
            cur.execute(
                "INSERT INTO knowledge.proposals (tenant_id, id, pack, contributor, summary, status, checks)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (actor.tenant, proposal_id, pack, actor.name, summary, status, Jsonb(check_json)),
            )
            for copy in copies:
                cur.execute(
                    "INSERT INTO knowledge.proposal_entries (tenant_id, proposal_id, entry_id) VALUES (%s, %s, %s)",
                    (actor.tenant, proposal_id, copy["id"]),
                )
            self._evidence(
                cur,
                actor,
                "knowledge.proposal.created",
                "Proposal",
                str(proposal_id),
                after={
                    "pack": pack,
                    "status": status,
                    "entries": [c["key"] for c in copies],
                    "checks": check_json,
                },
            )
            return self._proposal(cur, proposal_id)

    def list_proposals(self, actor: Actor, role: str) -> list[dict[str, Any]]:
        with self.db.in_tenant(actor.tenant) as cur:
            if role == "reviewer":
                cur.execute(
                    "SELECT p.id FROM knowledge.proposals p JOIN knowledge.packs k ON k.tenant_id = p.tenant_id"
                    " AND k.name = p.pack WHERE %s = ANY(k.reviewers) ORDER BY p.created_at DESC",
                    (actor.name,),
                )
            else:
                cur.execute(
                    "SELECT id FROM knowledge.proposals WHERE contributor = %s ORDER BY created_at DESC",
                    (actor.name,),
                )
            return [self._proposal(cur, r[0]) for r in cur.fetchall()]

    def get_proposal(self, actor: Actor, proposal_id: UUID) -> dict[str, Any]:
        with self.db.in_tenant(actor.tenant) as cur:
            proposal = self._proposal(cur, proposal_id)
            if not self._may_see(cur, actor, proposal):
                raise NotFound(f"proposal {proposal_id}")
            return proposal

    def decide(
        self,
        actor: Actor,
        proposal_id: UUID,
        decision: str,
        reason: str,
        edits: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        with self.db.in_tenant(actor.tenant) as cur:
            cur.execute(
                "SELECT pack, contributor, status FROM knowledge.proposals WHERE id = %s FOR UPDATE",
                (proposal_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise NotFound(f"proposal {proposal_id}")
            pack, contributor, status = row
            info = self._pack(cur, pack, lock=True)
            if actor.name not in info["reviewers"]:
                if actor.name == contributor:
                    raise Forbidden("only the pack's reviewers can decide a proposal")
                raise NotFound(f"proposal {proposal_id}")
            if actor.name == contributor:
                raise Forbidden("a reviewer cannot decide their own proposal")
            if status != "in-review":
                raise Conflict(f"proposal is {status}; only proposals in review can be decided")

            merged_version = None
            if decision == "approve":
                if info["requires_eval"]:
                    raise Conflict(
                        "this pack requires an evaluation run before merging, and the evaluation gate is not built yet"
                    )
                merged_version = self._merge(
                    cur, actor, pack, info["latest"], proposal_id, edits or []
                )
            elif edits:
                raise Invalid("edits are only allowed when approving")
            cur.execute(
                "UPDATE knowledge.proposals SET status = %s, reviewer = %s, decision = %s, reason = %s,"
                " decided_at = now(), merged_version = %s WHERE id = %s",
                (
                    "approved" if decision == "approve" else "rejected",
                    actor.name,
                    decision,
                    reason,
                    merged_version,
                    proposal_id,
                ),
            )
            self._evidence(
                cur,
                actor,
                f"knowledge.proposal.{'approved' if decision == 'approve' else 'rejected'}",
                "Proposal",
                str(proposal_id),
                after={
                    "pack": pack,
                    "reason": reason,
                    "mergedVersion": merged_version,
                    "edited": [e["key"] for e in edits or []],
                },
            )
            return self._proposal(cur, proposal_id)

    def _merge(
        self,
        cur: Cursor,
        actor: Actor,
        pack: str,
        latest: str,
        proposal_id: UUID,
        edits: list[dict[str, str]],
    ) -> str:
        cur.execute(
            _ENTRY_SELECT
            + " JOIN knowledge.proposal_entries pe ON pe.tenant_id = e.tenant_id AND pe.entry_id = e.id"
            " WHERE pe.proposal_id = %s ORDER BY e.key",
            (proposal_id,),
        )
        proposed = {e["key"]: e for e in (_entry(r) for r in cur.fetchall())}
        unknown = [e["key"] for e in edits if e["key"] not in proposed]
        if unknown:
            raise Invalid(f"edits name keys not in the proposal: {', '.join(unknown)}")
        for edit in edits:
            original = proposed[edit["key"]]
            edited = self._insert_entry(
                cur,
                actor.tenant,
                {**original, "body": edit["body"]},
                contributor=original["contributor"],
                derived_from=original["id"],
            )
            proposed[edit["key"]] = edited
            checked = checks.check_entry(
                edited["key"], edited["title"], edited["body"], edited.get("source")
            )
            if checks.blocked(checked):
                raise Invalid(
                    f"the edit to {edit['key']!r} fails checks: {', '.join(f.rule_id for f in checked)}"
                )

        version = bump_minor(latest)
        lineage = {
            e["entry"]["key"]: (e["entry"]["id"], e["proposal"], e["reviewer"])
            for e in self._version_entries(cur, pack, latest)
        }
        for key, entry in proposed.items():
            lineage[key] = (entry["id"], proposal_id, actor.name)
        self._publish(cur, actor, pack, version, latest, f"merged proposal {proposal_id}", lineage)
        return version

    def rollback(self, actor: Actor, pack: str, to_version: str, reason: str) -> dict[str, Any]:
        with self.db.in_tenant(actor.tenant) as cur:
            info = self._pack(cur, pack, lock=True)
            if actor.name not in info["reviewers"]:
                raise Forbidden("only the pack's reviewers can roll back")
            # Raises NotFound for an unknown version; 0.0.0 is the empty pack.
            target = self._version_entries(cur, pack, to_version)
            version = bump_minor(info["latest"])
            lineage = {
                e["entry"]["key"]: (e["entry"]["id"], e["proposal"], e["reviewer"]) for e in target
            }
            self._publish(
                cur,
                actor,
                pack,
                version,
                info["latest"],
                f"rollback to {to_version}: {reason}",
                lineage,
            )
            return self._version(cur, pack, version)

    def _publish(
        self,
        cur: Cursor,
        actor: Actor,
        pack: str,
        version: str,
        parent: str,
        reason: str,
        lineage: dict[str, tuple[UUID, UUID, str]],
    ) -> None:
        cur.execute(
            "INSERT INTO knowledge.pack_versions (tenant_id, pack, version, parent, reason, created_by)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (actor.tenant, pack, version, parent, reason, actor.name),
        )
        for key, (entry_id, proposal_id, reviewer) in sorted(lineage.items()):
            cur.execute(
                "INSERT INTO knowledge.pack_version_entries (tenant_id, pack, version, key, entry_id, proposal_id, reviewer)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (actor.tenant, pack, version, key, entry_id, proposal_id, reviewer),
            )
        cur.execute(
            "UPDATE knowledge.packs SET latest_version = %s, updated_at = now() WHERE name = %s",
            (version, pack),
        )
        self._evidence(
            cur,
            actor,
            "knowledge.pack.version.published",
            "KnowledgePack",
            pack,
            before={"version": parent},
            after={
                "version": version,
                "reason": reason,
                "entries": {k: str(v[0]) for k, v in sorted(lineage.items())},
            },
        )

    def _version_entries(self, cur: Cursor, pack: str, version: str) -> list[dict[str, Any]]:
        if version == "0.0.0":
            return []
        return self._version(cur, pack, version)["entries"]

    def _proposal(self, cur: Cursor, proposal_id: UUID) -> dict[str, Any]:
        cur.execute(
            "SELECT id, pack, contributor, summary, status, checks, reviewer, decision, reason, decided_at,"
            " merged_version, created_at FROM knowledge.proposals WHERE id = %s",
            (proposal_id,),
        )
        r = cur.fetchone()
        if r is None:
            raise NotFound(f"proposal {proposal_id}")
        cur.execute(
            _ENTRY_SELECT
            + " JOIN knowledge.proposal_entries pe ON pe.tenant_id = e.tenant_id AND pe.entry_id = e.id"
            " WHERE pe.proposal_id = %s ORDER BY e.key",
            (proposal_id,),
        )
        out: dict[str, Any] = {
            "id": r[0],
            "pack": r[1],
            "contributor": r[2],
            "summary": r[3],
            "status": r[4],
            "checks": r[5],
            "entries": [_entry(e) for e in cur.fetchall()],
            "createdAt": r[11],
        }
        if r[7] is not None:
            out["decision"] = {
                "reviewer": r[6],
                "decision": r[7],
                "reason": r[8],
                "decidedAt": r[9],
            }
        if r[10] is not None:
            out["mergedVersion"] = r[10]
        return out

    def _may_see(self, cur: Cursor, actor: Actor, proposal: dict[str, Any]) -> bool:
        return (
            proposal["contributor"] == actor.name
            or actor.name in self._pack(cur, proposal["pack"])["reviewers"]
        )

    # Resolution -----------------------------------------------------------------------------

    def resolve(self, actor: Actor, packs: list[str]) -> list[dict[str, Any]]:
        """The caller's effective entries: personal > team > role > company, by key.

        Within one layer, packs are taken in name order and the first holding a key wins.
        """
        with self.db.in_tenant(actor.tenant) as cur:
            return self._resolve(cur, actor, packs)[1]

    def _resolve(
        self, cur: Cursor, actor: Actor, packs: list[str]
    ) -> tuple[list[str], list[dict[str, Any]]]:
        """The packs in scope (requested plus mandatory) and the effective entries."""
        cur.execute(
            "SELECT name FROM knowledge.packs WHERE mandatory OR name = ANY(%s) ORDER BY name",
            (packs,),
        )
        names = [r[0] for r in cur.fetchall()]
        unknown = sorted(set(packs) - set(names))
        if unknown:
            raise NotFound(f"packs {', '.join(unknown)}")
        candidates: list[tuple[int, str, dict[str, Any]]] = []
        for entry in self._personal(cur, actor):
            candidates.append(
                (LAYER_PRECEDENCE["personal"], "", {"entry": entry, "layer": "personal"})
            )
        for name in names:
            info = self._pack(cur, name)
            for e in self._version_entries(cur, name, info["latest"]):
                candidates.append(
                    (
                        LAYER_PRECEDENCE[info["layer"]],
                        name,
                        {
                            "entry": e["entry"],
                            "layer": info["layer"],
                            "pack": name,
                            "version": info["latest"],
                        },
                    )
                )
        effective: dict[str, dict[str, Any]] = {}
        for _, _, item in sorted(candidates, key=lambda c: (c[0], c[1])):
            effective.setdefault(item["entry"]["key"], item)
        return names, [effective[k] for k in sorted(effective)]

    # Evidence -------------------------------------------------------------------------------

    def events(self, actor: Actor, after_seq: int, limit: int) -> list[evidence.Event]:
        with self.db.in_tenant(actor.tenant) as cur:
            return evidence.list_events(cur, after_seq, limit)

    # Helpers --------------------------------------------------------------------------------

    def _insert_entry(
        self,
        cur: Cursor,
        tenant: UUID,
        entry: dict[str, Any],
        *,
        contributor: str,
        derived_from: UUID | None = None,
    ) -> dict[str, Any]:
        entry_id = uuid.uuid4()
        cur.execute(
            "INSERT INTO knowledge.entries (tenant_id, id, key, type, title, body, source, data_class, contributor, derived_from)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " RETURNING id, key, type, title, body, source, data_class, contributor, created_at",
            (
                tenant,
                entry_id,
                entry["key"],
                entry["type"],
                entry["title"],
                entry["body"],
                entry.get("source"),
                entry.get("dataClass", "internal"),
                contributor,
                derived_from,
            ),
        )
        row = cur.fetchone()
        if row is None:
            raise RuntimeError("entry insert returned no row")
        return _entry(row)


_ENTRY_COLUMNS = "id, key, type, title, body, source, data_class, contributor, created_at"
_ENTRY_SELECT = (  # constant column list, no caller input
    "SELECT "  # noqa: S608
    + ", ".join("e." + c for c in _ENTRY_COLUMNS.split(", "))
    + " FROM knowledge.entries e"
)


def _entry(row: tuple) -> dict[str, Any]:
    out = {
        "id": row[0],
        "key": row[1],
        "type": row[2],
        "title": row[3],
        "body": row[4],
        "dataClass": row[6],
        "contributor": row[7],
        "createdAt": row[8],
    }
    if row[5] is not None:
        out["source"] = row[5]
    return out


def to_jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))
