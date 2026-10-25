"""Erasure and access requests for the knowledge service (FR-309, GDPR Arts 15-17).

HUMAN REVIEW REQUIRED (CLAUDE.md): a deletion path. Only privacy officers erase, and never
themselves. A person may export the records held under their own identity; anything keyed by an
email needs an officer, because an email cannot be verified as the caller's. The rewriting itself
is knowledge.erase_subject (migration 0004), the only path by which the server's role can change
entries or lineage. Evidence events are retained, never rewritten.

The control plane implements the same rules for its own data; the CLI sends one request id to
both, and each service records its own proof.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg import Cursor, errors
from psycopg.types.json import Jsonb

from muistamo_knowledge.service import Actor, Conflict, Forbidden, Invalid, Knowledge, NotFound

SERVICE = "knowledge"

# The tenant tables that can hold a person's identifiers. Access exports search all of them and
# the tests scan all of them after an erasure. Source documents are copies of company documents,
# not attributable to a person, and are listed under retained instead.
PERSONAL_DATA_TABLES = (
    "entries",
    "personal_entries",
    "proposals",
    "pack_versions",
    "pack_version_entries",
    "packs",
    "sources",
    "reads",
    "privacy_officers",
    "erasure_requests",
    "evidence_events",
)

RETAINED = [
    {
        "data": "evidence_events",
        "reason": "Retained under GDPR Art 17(3)(b) and (e): the signed, hash-chained audit record "
        "(NFR-10). Rewriting an event would break every signature after it.",
    },
    {
        "data": "merged entry content",
        "reason": "Company knowledge stays with its lineage intact, attributed to the pseudonym. "
        "Entries whose text is itself personal data are redacted when named in redactEntries.",
    },
    {
        "data": "proposal summaries and review reasons",
        "reason": "Free text is not searched for the person; it is shown in the access export "
        "for review.",
    },
    {
        "data": "documents",
        "reason": "Copies of source documents, not attributable to a person. Erase at the source; "
        "the next sync removes the copy.",
    },
    {
        "data": "backups",
        "reason": "Backups expire on their own schedule; data restored from one must be erased "
        "again.",
    },
]


def subject_identifiers(subject: dict[str, Any], with_hr: bool) -> list[str]:
    """The identities and email (and the HR person id if with_hr), sorted and de-duplicated."""
    values = {subject["email"], *subject["identities"]}
    if with_hr and subject.get("hrPersonId"):
        values.add(subject["hrPersonId"])
    return sorted(values)


def subject_digest(tenant: UUID, subject: dict[str, Any]) -> str:
    """SHA-256 over the tenant id and the sorted identifiers, as the control plane computes it."""
    h = hashlib.sha256(str(tenant).encode())
    for v in subject_identifiers(subject, with_hr=True):
        h.update(("\n" + v).encode())
    return h.hexdigest()


def _is_officer(cur: Cursor, name: str) -> bool:
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM knowledge.privacy_officers WHERE officer = %s)", (name,)
    )
    row = cur.fetchone()
    return bool(row and row[0])


def rows_mentioning(cur: Cursor, table: str, values: list[str]) -> list[dict[str, Any]]:
    """Rows of table (one of PERSONAL_DATA_TABLES, never input) in which any of values appears
    as a whole JSON string value. It names the tenant explicitly as well as relying on
    row-level security, so it is scoped whichever role runs it."""
    if table not in PERSONAL_DATA_TABLES:
        raise ValueError(f"{table!r} is not a personal-data table")
    needles = [json.dumps(v) for v in values]
    cur.execute(
        f"SELECT to_jsonb(t) FROM knowledge.{table} t"  # noqa: S608 - table is a constant
        " WHERE t.tenant_id = current_setting('muistamo.tenant_id', true)::uuid"
        " AND EXISTS (SELECT 1 FROM unnest(%s::text[]) n WHERE strpos(to_jsonb(t)::text, n) > 0)",
        (needles,),
    )
    return [r[0] for r in cur.fetchall()]


def replace_officers(owner_url: str, tenant: UUID, officers: list[str]) -> None:
    """Replace the tenant's privacy officers, as the schema owner (an operator command)."""
    with psycopg.connect(owner_url) as conn, conn.transaction():
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(tenant),))
        conn.execute("DELETE FROM knowledge.privacy_officers WHERE tenant_id = %s", (tenant,))
        for officer in officers:
            conn.execute(
                "INSERT INTO knowledge.privacy_officers (tenant_id, officer) VALUES (%s, %s)",
                (tenant, officer),
            )


class Privacy:
    def __init__(self, knowledge: Knowledge) -> None:
        self.k = knowledge

    def erase(self, actor: Actor, request: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Erase a person's knowledge data. Returns the proof and whether this call erased
        (False: the id was already completed and the stored proof is returned)."""
        request_id = UUID(str(request["id"]))
        subject = request["subject"]
        values = subject_identifiers(subject, with_hr=False)
        digest = subject_digest(actor.tenant, subject)
        redact = [UUID(str(e)) for e in request.get("redactEntries") or []]
        with self.k.db.in_tenant(actor.tenant) as cur:
            if not _is_officer(cur, actor.name):
                raise Forbidden("only privacy officers can erase personal data")
            if actor.name in values:
                raise Forbidden(
                    "a privacy officer cannot erase their own data; another officer must"
                )
            reason = request["reason"]
            if any(v.lower() in reason.lower() for v in values):
                raise Invalid("the reason must not contain the person's identifiers; it is stored")

            cur.execute(
                "SELECT subject_digest, proof FROM knowledge.erasure_requests WHERE id = %s",
                (request_id,),
            )
            row = cur.fetchone()
            if row is not None:
                if row[0] != digest:
                    raise Conflict(f"erasure {request_id} was already used for a different person")
                return row[1], False

            pseudonym = f"erased:{request_id}"
            try:
                cur.execute(
                    "SELECT knowledge.erase_subject(%s, %s, %s)", (values, pseudonym, redact)
                )
            except errors.RaiseException as exc:
                # The whole transaction rolls back: nothing is erased.
                if "named for redaction does not exist" in str(exc):
                    raise Invalid("an entry named in redactEntries does not exist") from exc
                raise
            counts_row = cur.fetchone()
            counts = counts_row[0] if counts_row else {}

            cur.execute(
                "SELECT name FROM knowledge.packs WHERE NOT EXISTS"
                " (SELECT 1 FROM unnest(reviewers) r WHERE r NOT LIKE 'erased:%') ORDER BY name"
            )
            orphaned = [r[0] for r in cur.fetchall()]
            completed = datetime.now(UTC)
            proof: dict[str, Any] = {
                "id": str(request_id),
                "service": SERVICE,
                "completedAt": completed.isoformat().replace("+00:00", "Z"),
                "requestedBy": actor.name,
                "pseudonym": pseudonym,
                "counts": counts,
                "retained": RETAINED,
                "subjectDigest": digest,
            }
            if orphaned:
                proof["warnings"] = [
                    f"pack {name} has no reviewer left; assign one before its next proposal"
                    for name in orphaned
                ]
            cur.execute(
                "INSERT INTO knowledge.erasure_requests"
                " (tenant_id, id, subject_digest, requested_by, reason, proof, completed_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (actor.tenant, request_id, digest, actor.name, reason, Jsonb(proof), completed),
            )
            self.k._evidence(
                cur,
                actor,
                "privacy.erasure.completed",
                "ErasureRequest",
                str(request_id),
                after=proof,
            )
        return proof, True

    def get_erasure(self, actor: Actor, request_id: UUID) -> dict[str, Any]:
        with self.k.db.in_tenant(actor.tenant) as cur:
            if not _is_officer(cur, actor.name):
                raise Forbidden("only privacy officers can read erasure proofs")
            cur.execute("SELECT proof FROM knowledge.erasure_requests WHERE id = %s", (request_id,))
            row = cur.fetchone()
            if row is None:
                raise NotFound(f"erasure {request_id}")
            return row[0]

    def export(self, actor: Actor, subject: dict[str, Any]) -> dict[str, Any]:
        """Every row of PERSONAL_DATA_TABLES holding one of the person's identifiers."""
        with self.k.db.in_tenant(actor.tenant) as cur:
            officer = _is_officer(cur, actor.name)
            if officer:
                values = subject_identifiers(subject, with_hr=False)
            elif subject["identities"] == [actor.name]:
                values = [actor.name]
            else:
                raise Forbidden(
                    "you can export only your own data; ask a privacy officer for anyone else's"
                )
            sections = {
                table: rows_mentioning(cur, table, values) for table in PERSONAL_DATA_TABLES
            }
            after: dict[str, Any] = {
                "counts": {table: len(rows) for table, rows in sections.items()},
                "self": not officer,
            }
            if officer:
                after["subjectDigest"] = subject_digest(actor.tenant, subject)
            self.k._evidence(
                cur,
                actor,
                "privacy.access.exported",
                "AccessRequest",
                str(uuid.uuid4()),
                after=after,
            )
        return {
            "service": SERVICE,
            "generatedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "sections": sections,
        }
