"""Knowledge packs, personal layers, proposals, review and resolution (FR-301-306).

HUMAN REVIEW REQUIRED (CLAUDE.md): the authorisation rules here. A personal layer is visible
to its owner only. Only a pack's reviewers decide proposals or roll back, and never on their
own proposal. Anything the caller may not see is reported as not found, so existence does not
leak.

Every write records a signed evidence event in the same transaction (invariant 4).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from psycopg import Cursor
from psycopg.types.json import Jsonb

from muistamo_knowledge import checks, decay, evidence, skills
from muistamo_knowledge.connectors import ConnectorFactory
from muistamo_knowledge.db import Database
from muistamo_knowledge.delegation import DelegationClient

log = logging.getLogger("muistamo.knowledge")

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
    # An Entra caller's own access token, kept only to ask the control plane for a delegation
    # in the same request (PR D). Never logged, stored or compared.
    bearer: str | None = field(default=None, repr=False, compare=False)


def bump_minor(version: str) -> str:
    major, minor, _ = (int(p) for p in version.split("."))
    return f"{major}.{minor + 1}.0"


class Knowledge:
    def __init__(
        self,
        db: Database,
        signer: evidence.LocalKey,
        connectors: dict[str, ConnectorFactory] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.db = db
        # Decay is judged against this clock; tests move it instead of waiting.
        self.clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))
        self.signer = signer
        self.connectors = connectors or {}
        # Entra callers' delegations (PR D); None refuses every Entra caller's sources.
        self.delegations: DelegationClient | None = None
        # Called after a new pack version commits, with (actor, pack, version). Delivery targets
        # (Agent Skills destinations, FR-312) subscribe here; a failing hook never undoes a merge.
        self.on_publish: list[Callable[[Actor, str, str], None]] = []

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
            cur.execute(
                "SELECT document, mandatory, reviewers FROM knowledge.packs WHERE name = %s FOR UPDATE",
                (name,),
            )
            row = cur.fetchone()
            if row is not None and row[0] == document:
                return self._pack_record(cur, name), False
            mandatory = spec.get("mandatory", False)
            # The contract says so too, but the generated models do not enforce if/then, and the
            # database refuses it as a last resort: a mandatory pack must be a company pack.
            if mandatory and spec["layer"] != "company":
                raise Invalid("only company packs can be mandatory")
            was = bool(row[1]) if row is not None else False
            if mandatory or was:
                # A mandatory pack decides what everyone's agents are told: a compliance
                # decision, so privacy officers only (FR-1708, E20.3). That covers every change
                # to one, not only the flag: whoever sets its reviewers controls its content and
                # can roll it back to empty.
                from muistamo_knowledge.privacy import is_officer

                if not is_officer(cur, actor.name):
                    raise Forbidden("only privacy officers can create or change a mandatory pack")
            elif row is not None and actor.name not in row[2]:
                # Changing a pack is the reviewers' call: its reviewers decide what it says and its
                # decay policy decides how long that stays served (FR-307). Anyone could otherwise
                # make themselves its reviewer, or stretch the policy to revive expired entries.
                from muistamo_knowledge.privacy import is_officer

                if not is_officer(cur, actor.name):
                    raise Forbidden("only the pack's reviewers can change it")
            if row is not None:
                old_every, old_grace = decay.policy(row[0]["spec"].get("decay"))
                new_every, new_grace = decay.policy(spec.get("decay"))
                if new_every > old_every or new_every + new_grace > old_every + old_grace:
                    # Policy changes apply to historical exports too. Extending a contributor's
                    # own confirmation must require someone independent, just like verifying it.
                    cur.execute(
                        "SELECT 1 FROM knowledge.pack_version_entries v"
                        " JOIN knowledge.entries e ON e.tenant_id = v.tenant_id AND e.id = v.entry_id"
                        " JOIN knowledge.proposals p ON p.tenant_id = v.tenant_id AND p.id = v.proposal_id"
                        " WHERE v.pack = %s AND (e.contributor = %s OR p.proposed_by = %s) LIMIT 1",
                        (name, actor.name, actor.name),
                    )
                    if cur.fetchone() is not None:
                        raise Forbidden(
                            "cannot extend decay for your own entries; ask another reviewer"
                        )
            if mandatory != was:
                self._evidence(
                    cur,
                    actor,
                    "knowledge.pack.mandatory.changed",
                    "KnowledgePack",
                    name,
                    before={"mandatory": was},
                    after={"mandatory": mandatory},
                )
            values = (
                spec["layer"],
                mandatory,
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
                "SELECT layer, mandatory, reviewers, requires_eval, latest_version, document -> 'spec' -> 'decay'"
                " FROM knowledge.packs WHERE name = %s FOR UPDATE",
                (name,),
            )
        else:
            cur.execute(
                "SELECT layer, mandatory, reviewers, requires_eval, latest_version, document -> 'spec' -> 'decay'"
                " FROM knowledge.packs WHERE name = %s",
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
            "decay": decay.policy(row[5]),
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
            self._ensure_not_frozen(cur, actor.name)
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
        return self._personal_of(cur, actor.name)

    def _personal_of(self, cur: Cursor, owner: str) -> list[dict[str, Any]]:
        cur.execute(
            _ENTRY_SELECT
            + " JOIN knowledge.personal_entries p ON p.tenant_id = e.tenant_id AND p.entry_id = e.id"
            " WHERE p.owner = %s ORDER BY e.key, e.created_at",
            (owner,),
        )
        return [_entry(r) for r in cur.fetchall()]

    def _ensure_not_frozen(self, cur: Cursor, person: str) -> None:
        """A leaver's personal layer is frozen while their review is open (E4.2)."""
        cur.execute(
            "SELECT EXISTS (SELECT 1 FROM knowledge.leaver_reviews"
            " WHERE person = %s AND status = 'open')",
            (person,),
        )
        row = cur.fetchone()
        if row and row[0]:
            raise Conflict(
                "this personal layer is frozen while its leaver review is open; nothing can be"
                " added, proposed or deleted"
            )

    def delete_personal(self, actor: Actor, entry_id: UUID) -> None:
        """Delete one of the caller's own entries. Copies already submitted in proposals remain."""
        with self.db.in_tenant(actor.tenant) as cur:
            self._ensure_not_frozen(cur, actor.name)
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
            self._ensure_not_frozen(cur, actor.name)
            return self._propose(cur, actor, actor.name, pack, entry_ids, summary)

    def _propose(
        self,
        cur: Cursor,
        actor: Actor,
        owner: str,
        pack: str,
        entry_ids: list[UUID],
        summary: str,
        proposed_by: str | None = None,
    ) -> dict[str, Any]:
        """Propose owner's personal entries. proposed_by is set when someone else proposes on the
        owner's behalf (a leaver's decider); the owner stays the contributor, for lineage."""
        info = self._pack(cur, pack)
        own = {e["id"]: e for e in self._personal_of(cur, owner)}
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
                    cur, actor.tenant, source, contributor=owner, derived_from=entry_id
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
            "INSERT INTO knowledge.proposals"
            " (tenant_id, id, pack, contributor, summary, status, checks, proposed_by)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                actor.tenant,
                proposal_id,
                pack,
                owner,
                summary,
                status,
                Jsonb(check_json),
                proposed_by,
            ),
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
                **({"onBehalfOf": owner} if proposed_by else {}),
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
                "SELECT pack, contributor, status, proposed_by FROM knowledge.proposals"
                " WHERE id = %s FOR UPDATE",
                (proposal_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise NotFound(f"proposal {proposal_id}")
            pack, contributor, status, proposed_by = row
            info = self._pack(cur, pack, lock=True)
            if actor.name not in info["reviewers"]:
                if actor.name == contributor:
                    raise Forbidden("only the pack's reviewers can decide a proposal")
                raise NotFound(f"proposal {proposal_id}")
            if actor.name == contributor:
                raise Forbidden("a reviewer cannot decide their own proposal")
            if actor.name == proposed_by:
                raise Forbidden("whoever proposed on a leaver's behalf cannot decide that proposal")
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
            result = self._proposal(cur, proposal_id)
        if merged_version is not None:
            self._published(actor, pack, merged_version)
        return result

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
        # Approving is vouching: the reviewer verified each merged entry now (FR-307).
        now = self.clock()
        for entry in proposed.values():
            decay.record(
                cur, actor.tenant, pack, entry["id"], now, actor.name, f"merged {proposal_id}"
            )
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
            # Entries the rollback brings back into service: absent from the latest version, or
            # present but expired (withheld, not yet swept).
            served = {
                e["entry"]["id"]
                for e in self._decayed(cur, pack, info)
                if e["decay"]["status"] != "expired"
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
            # Bringing an entry back is vouching for it, so a restored entry starts a fresh decay
            # clock, evidenced like any confirmation. Entries still in service keep theirs. A
            # rollback never vouches for the roller's own entry: that would let a contributor who
            # reviews the pack renew their own knowledge without anyone else (FR-307, ASI06).
            now = self.clock()
            for e in target:
                if e["entry"]["id"] in served or actor.name in self._cannot_vouch(cur, e):
                    continue
                why = f"restored by rollback to {to_version}"
                decay.record(cur, actor.tenant, pack, e["entry"]["id"], now, actor.name, why)
                self._evidence(
                    cur,
                    actor,
                    "knowledge.entry.verified",
                    "KnowledgePack",
                    pack,
                    after={
                        "key": e["entry"]["key"],
                        "entryId": str(e["entry"]["id"]),
                        "version": version,
                        "reason": why,
                        "verifiedAt": _iso(now),
                    },
                )
            result = self._version(cur, pack, version)
        self._published(actor, pack, version)
        return result

    def _published(self, actor: Actor, pack: str, version: str) -> None:
        for hook in self.on_publish:
            try:
                hook(actor, pack, version)
            except Exception:  # noqa: BLE001 - delivery must never undo a committed merge
                log.exception("publish hook failed", extra={"pack": pack, "version": version})

    def export_skills(self, actor: Actor, pack: str, version: str) -> tuple[str, bytes]:
        """A published version as a deterministic Agent Skills zip, recorded as evidence."""
        with self.db.in_tenant(actor.tenant) as cur:
            info = self._pack(cur, pack)
            resolved = info["latest"] if version == "latest" else version
            if resolved == "0.0.0":
                raise Conflict(f"pack {pack!r} has nothing published to export")
            # Knowledge nobody vouches for any more does not leave as skills either (FR-307),
            # from any version: an expired entry is withheld wherever it is read.
            decayed = self._decayed(cur, pack, info, resolved)
            entries = [e for e in decayed if e["decay"]["status"] != "expired"]
            withheld = len(decayed) - len(entries)
            if not entries:
                raise Conflict(
                    f"pack {pack!r} version {resolved} has no entries to export"
                    + (f" ({withheld} expired, awaiting confirmation)" if withheld else "")
                )
            data = skills.archive(skills.render(pack, resolved, info["layer"], entries))
            # Knowledge leaving Muistamo is recorded; the evidence names the archive, not its content.
            self._evidence(
                cur,
                actor,
                "knowledge.pack.exported",
                "KnowledgePack",
                pack,
                after={
                    "version": resolved,
                    "format": "agent-skills-zip",
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "entries": len(entries),
                    "withheldExpired": withheld,
                },
            )
            return resolved, data

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
            " merged_version, created_at, proposed_by FROM knowledge.proposals WHERE id = %s",
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
        if r[12] is not None:
            out["proposedBy"] = r[12]
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
        # (mandatory first, layer precedence, pack name): a mandatory pack's entry wins its key over
        # every other layer, the caller's own personal entry included, so nobody can shadow it
        # (FR-1708). Everything else keeps personal > team > role > company.
        candidates: list[tuple[int, int, str, dict[str, Any]]] = []
        for entry in self._personal(cur, actor):
            # Personal entries are the person's own and nobody reviewed them: no decay (not in
            # this slice), and provenance from their source alone.
            item = {
                "entry": entry,
                "layer": "personal",
                "provenance": decay.provenance(
                    reviewed=False,
                    has_source="source" in entry,
                    reviewer_edited=False,
                    status=None,
                ),
            }
            candidates.append((1, LAYER_PRECEDENCE["personal"], "", item))
        for name in names:
            info = self._pack(cur, name)
            for e in self._decayed(cur, name, info):
                if e["decay"]["status"] == "expired":
                    # Fail closed (FR-307): nobody vouches for it any more, so no agent is told
                    # it, whether or not the sweep has removed it from the pack yet.
                    continue
                item = {
                    "entry": e["entry"],
                    "layer": info["layer"],
                    "pack": name,
                    "version": info["latest"],
                    "decay": e["decay"],
                    "provenance": e["provenance"],
                }
                if info["mandatory"]:
                    item["mandatory"] = True
                candidates.append(
                    (0 if info["mandatory"] else 1, LAYER_PRECEDENCE[info["layer"]], name, item)
                )
        effective: dict[str, dict[str, Any]] = {}
        for *_, item in sorted(candidates, key=lambda c: (c[0], c[1], c[2])):
            key = item["entry"]["key"]
            winner = effective.get(key)
            if winner is None:
                effective[key] = item
            elif winner.get("mandatory"):
                # Say so when a mandatory entry overrides something, so nobody is misled about
                # which entry is in force.
                shadowed = {"layer": item["layer"]}
                if "pack" in item:
                    shadowed["pack"] = item["pack"]
                winner.setdefault("overrides", []).append(shadowed)
        return names, [effective[k] for k in sorted(effective)]

    # Decay (FR-307) -------------------------------------------------------------------------

    def _decayed(
        self, cur: Cursor, pack: str, info: dict[str, Any], version: str | None = None
    ) -> list[dict[str, Any]]:
        """A version's entries (the latest by default), each with its decay state and provenance."""
        entries = self._version_entries(cur, pack, version or info["latest"])
        ids = [e["entry"]["id"] for e in entries]
        verified = decay.latest(cur, pack, ids)
        edited = decay.edited(cur, [(e["entry"]["id"], e["proposal"]) for e in entries])
        every, grace = info["decay"]
        now = self.clock()
        out = []
        for e in entries:
            at, by = verified.get(e["entry"]["id"], (None, None))
            state = decay.state(at, by, every, grace, info["mandatory"], now)
            out.append(
                {
                    **e,
                    "decay": state,
                    "provenance": decay.provenance(
                        reviewed=True,
                        has_source="source" in e["entry"],
                        reviewer_edited=e["entry"]["id"] in edited,
                        status=state["status"],
                    ),
                }
            )
        return out

    def _cannot_vouch(self, cur: Cursor, e: dict[str, Any]) -> set[str]:
        """Who may never vouch for a pack entry: its contributor, and whoever proposed it on a
        leaver's behalf, just as neither may approve it (FR-305, E4.2)."""
        cur.execute("SELECT proposed_by FROM knowledge.proposals WHERE id = %s", (e["proposal"],))
        row = cur.fetchone()
        return {e["entry"]["contributor"]} | ({row[0]} if row and row[0] else set())

    def _may_confirm(self, cur: Cursor, actor: Actor, info: dict[str, Any]) -> bool:
        if actor.name in info["reviewers"]:
            return True
        # Mandatory packs answer to compliance as well as to their reviewers (FR-1708).
        if info["mandatory"]:
            from muistamo_knowledge.privacy import is_officer

            return is_officer(cur, actor.name)
        return False

    def _verification(self, pack: str, info: dict[str, Any], e: dict[str, Any]) -> dict[str, Any]:
        out = {
            "pack": pack,
            "version": info["latest"],
            "entry": e["entry"],
            "decay": e["decay"],
            "provenance": e["provenance"],
        }
        if info["mandatory"]:
            out["mandatory"] = True
        return out

    def verify_entry(
        self, actor: Actor, pack: str, key: str, entry_id: UUID, reason: str
    ) -> dict[str, Any]:
        """A reviewer confirms an entry is still right, restarting its decay clock."""
        with self.db.in_tenant(actor.tenant) as cur:
            info = self._pack(cur, pack, lock=True)
            if not self._may_confirm(cur, actor, info):
                raise Forbidden("only the pack's reviewers can confirm its entries")
            current = {e["entry"]["key"]: e for e in self._decayed(cur, pack, info)}
            if key not in current:
                raise NotFound(f"entry {key!r} in pack {pack!r}")
            entry = current[key]["entry"]
            if entry["id"] != entry_id:
                raise Conflict("the entry changed; reload it before confirming")
            # Vouching for one's own knowledge is no check at all, as with approving it.
            if actor.name in self._cannot_vouch(cur, current[key]):
                raise Forbidden("nobody can confirm their own entry")
            before = current[key]["decay"]
            now = self.clock()
            decay.record(cur, actor.tenant, pack, entry["id"], now, actor.name, reason)
            self._evidence(
                cur,
                actor,
                "knowledge.entry.verified",
                "KnowledgePack",
                pack,
                before={"status": before["status"], "verifiedAt": _iso(before.get("verifiedAt"))},
                after={
                    "key": key,
                    "entryId": str(entry["id"]),
                    "version": info["latest"],
                    "reason": reason,
                    "verifiedAt": _iso(now),
                },
            )
            renewed = {e["entry"]["key"]: e for e in self._decayed(cur, pack, info)}[key]
            return self._verification(pack, info, renewed)

    def verification_queue(self, actor: Actor) -> list[dict[str, Any]]:
        """Entries due or expired (not yet swept) in packs the caller may confirm."""
        with self.db.in_tenant(actor.tenant) as cur:
            cur.execute("SELECT name FROM knowledge.packs ORDER BY name")
            out = []
            for (name,) in cur.fetchall():
                info = self._pack(cur, name)
                if not self._may_confirm(cur, actor, info):
                    continue
                for e in self._decayed(cur, name, info):
                    if e["decay"]["status"] != "current" and actor.name not in self._cannot_vouch(
                        cur, e
                    ):
                        out.append(self._verification(name, info, e))
        far = datetime.max.replace(tzinfo=UTC)
        out.sort(
            key=lambda v: (
                v["decay"].get("expiresAt", far),
                v["decay"].get("dueAt", far),
                v["pack"],
                v["entry"]["key"],
            )
        )
        return out

    def sweep_decay(self, tenant: UUID) -> dict[str, list[str]]:
        """Remove expired entries from every pack but mandatory ones, as new pack versions.

        Expired entries are already withheld from agents; this makes the removal permanent and
        visible in the pack's history. Restoring is a rollback or a new proposal. Safe to run
        repeatedly and concurrently: each pack is locked, and nothing expired means no version.
        """
        actor = Actor(tenant=tenant, name=decay.SWEEP_ACTOR, request_id=f"decay-{uuid.uuid4()}")
        with self.db.in_tenant(tenant) as cur:
            cur.execute("SELECT name FROM knowledge.packs WHERE NOT mandatory ORDER BY name")
            names = [r[0] for r in cur.fetchall()]
        removed: dict[str, list[str]] = {}
        for name in names:
            with self.db.in_tenant(tenant) as cur:
                info = self._pack(cur, name, lock=True)
                if info["mandatory"]:
                    continue
                entries = self._decayed(cur, name, info)
                expired = [e for e in entries if e["decay"]["status"] == "expired"]
                if not expired:
                    continue
                version = bump_minor(info["latest"])
                for e in expired:
                    self._evidence(
                        cur,
                        actor,
                        "knowledge.entry.expired",
                        "KnowledgePack",
                        name,
                        before={
                            "key": e["entry"]["key"],
                            "entryId": str(e["entry"]["id"]),
                            "version": info["latest"],
                            "verifiedAt": _iso(e["decay"].get("verifiedAt")),
                            "expiresAt": _iso(e["decay"].get("expiresAt")),
                        },
                        after={"removedIn": version},
                    )
                keys = sorted(e["entry"]["key"] for e in expired)
                lineage = {
                    e["entry"]["key"]: (e["entry"]["id"], e["proposal"], e["reviewer"])
                    for e in entries
                    if e["decay"]["status"] != "expired"
                }
                self._publish(
                    cur,
                    actor,
                    name,
                    version,
                    info["latest"],
                    f"decay: expired unconfirmed ({', '.join(keys)})",
                    lineage,
                )
            removed[name] = keys
            self._published(actor, name, version)
        return removed

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


def _iso(value: datetime | None) -> str | None:
    """Timestamps in evidence payloads as RFC 3339, not str()'s space-separated form."""
    return None if value is None else value.isoformat()


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
    """JSON-ready API output. Datetimes are RFC 3339 (the contracts' date-time), never str()'s
    space-separated form, which strict clients such as the control plane cannot parse."""
    return json.loads(json.dumps(value, default=_json_default))


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
