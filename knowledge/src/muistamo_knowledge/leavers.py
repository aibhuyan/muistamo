"""Leaver personal-layer reviews (E4.2, J2).

HUMAN REVIEW REQUIRED (CLAUDE.md): an authorisation exception and a deletion path.

The control plane's leaver workflow opens a review with a signed service call. While it is open
the leaver's personal layer is frozen, and its decider (the manager, else an instance sponsor,
else any privacy officer) is the one person besides the owner who may read it. Every read is
recorded. The decider merges chosen entries as a proposal (which they cannot approve), keeps the
layer for one more period (once), or purges it. When the workflow reports the grace period over,
an undecided layer is purged. A rehire cancels the review and unfreezes the layer.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg
from psycopg import Cursor

from muistamo_knowledge.auth import IdentityMap, UnmappedIdentity
from muistamo_knowledge.privacy import is_officer
from muistamo_knowledge.service import Actor, Conflict, Invalid, Knowledge, NotFound

REVIEW_PERIOD = timedelta(days=30)  # the control plane's leaver grace period
SERVICE_ACTOR = "service:control-plane"

_COLUMNS = (
    "id, person, decider_kind, decider, status, outcome, deadline, kept, entry_count,"
    " proposal_id, opened_at, closed_at"
)


def _review(row: tuple) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row[0],
        "person": row[1],
        "deciderKind": row[2],
        "status": row[4],
        "deadline": row[6],
        "kept": row[7],
        "entryCount": row[8],
        "openedAt": row[10],
    }
    for key, value in (
        ("decider", row[3]),
        ("outcome", row[5]),
        ("proposalId", row[9]),
        ("closedAt", row[11]),
    ):
        if value is not None:
            out[key] = value
    return out


def set_service_secret(owner_url: str, tenant: UUID, secret: bytes) -> None:
    """Store the tenant's service secret, as the schema owner (an operator command)."""
    if len(secret) < 32:
        raise ValueError("a service secret must be at least 32 bytes")
    with psycopg.connect(owner_url) as conn, conn.transaction():
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(tenant),))
        conn.execute(
            "INSERT INTO knowledge.service_secrets (tenant_id, secret) VALUES (%s, %s)"
            " ON CONFLICT (tenant_id) DO UPDATE SET secret = EXCLUDED.secret, created_at = now()",
            (tenant, secret),
        )


class Leavers:
    def __init__(self, knowledge: Knowledge, identity_for_email: IdentityMap) -> None:
        self.k = knowledge
        self.identity_for_email = identity_for_email

    # Service calls (signed by the control plane) ---------------------------------------------

    def service_secret(self, tenant: UUID) -> bytes | None:
        """The tenant's service secret, or None. An unregistered tenant raises UnknownTenant."""
        with self.k.db.in_tenant(tenant) as cur:
            cur.execute("SELECT secret FROM knowledge.service_secrets")
            row = cur.fetchone()
            return bytes(row[0]) if row else None

    def open(self, tenant: UUID, request: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Open and freeze the review. Repeating an id returns the existing review."""
        actor = Actor(
            tenant=tenant, name=SERVICE_ACTOR, request_id=f"leaver-review:{request['id']}"
        )
        try:
            person = self.identity_for_email(request["person"]["email"])
            candidates = [
                (self.identity_for_email(d["email"]), d["kind"]) for d in request["deciders"]
            ]
        except UnmappedIdentity as exc:
            raise Invalid(f"cannot open a review: {exc}") from exc
        decider, kind = next(
            ((i, k) for i, k in candidates if i != person), (None, "privacy-officers")
        )

        with self.k.db.in_tenant(tenant) as cur:
            existing = self._get(cur, request["id"], lock=True)
            if existing is not None:
                return existing, False
            cur.execute(
                "SELECT id FROM knowledge.leaver_reviews WHERE person = %s AND status = 'open'",
                (person,),
            )
            other = cur.fetchone()
            if other is not None:
                raise Conflict(f"review {other[0]} is already open for this person")
            count = len(self.k._personal_of(cur, person))
            now = datetime.now(UTC)
            status, outcome, closed = (
                ("closed", "empty", now) if count == 0 else ("open", None, None)
            )
            cur.execute(
                "INSERT INTO knowledge.leaver_reviews (tenant_id, id, person, decider_kind, decider,"
                " status, outcome, deadline, entry_count, opened_at, closed_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    tenant,
                    request["id"],
                    person,
                    kind,
                    decider,
                    status,
                    outcome,
                    now + REVIEW_PERIOD,
                    count,
                    now,
                    closed,
                ),
            )
            review = self._require(cur, request["id"])
            self.k._evidence(
                cur,
                actor,
                "knowledge.leaver-review.opened",
                "LeaverReview",
                request["id"],
                after={
                    k: review[k]
                    for k in ("person", "deciderKind", "status", "deadline", "entryCount")
                }
                | ({"decider": decider} if decider else {})
                | ({"outcome": outcome} if outcome else {}),
            )
        return review, True

    def expire(self, tenant: UUID, review_id: str) -> dict[str, Any]:
        """The grace period is over: purge an undecided layer whose deadline has passed. A kept
        review is returned still open, with its later deadline, for the workflow to wait for."""
        actor = Actor(tenant=tenant, name=SERVICE_ACTOR, request_id=f"leaver-review:{review_id}")
        with self.k.db.in_tenant(tenant) as cur:
            review = self._require(cur, review_id)
            if review["status"] == "closed" or review["deadline"] > datetime.now(UTC):
                return review
            purged = self._purge(cur, review["person"])
            self._close(cur, review_id, "expired")
            self.k._evidence(
                cur,
                actor,
                "knowledge.leaver-review.expired",
                "LeaverReview",
                review_id,
                after={"outcome": "expired", "purgedEntries": purged},
            )
            return self._require(cur, review_id)

    def cancel(self, tenant: UUID, review_id: str) -> dict[str, Any]:
        """The person was rehired: close an open review and unfreeze the layer."""
        actor = Actor(tenant=tenant, name=SERVICE_ACTOR, request_id=f"leaver-review:{review_id}")
        with self.k.db.in_tenant(tenant) as cur:
            review = self._require(cur, review_id)
            if review["status"] == "closed":
                return review
            self._close(cur, review_id, "cancelled")
            self.k._evidence(
                cur,
                actor,
                "knowledge.leaver-review.cancelled",
                "LeaverReview",
                review_id,
                after={"outcome": "cancelled"},
            )
            return self._require(cur, review_id)

    # The decider ---------------------------------------------------------------------------

    def list(self, actor: Actor) -> list[dict[str, Any]]:
        with self.k.db.in_tenant(actor.tenant) as cur:
            officer = is_officer(cur, actor.name)
            cur.execute(
                f"SELECT {_COLUMNS} FROM knowledge.leaver_reviews"  # noqa: S608 - constant columns
                " WHERE decider = %s OR (decider IS NULL AND %s)"
                " ORDER BY status DESC, opened_at DESC",
                (actor.name, officer),
            )
            return [_review(r) for r in cur.fetchall()]

    def get(self, actor: Actor, review_id: str) -> dict[str, Any]:
        """The review and the leaver's personal entries, to its decider only. Recorded."""
        with self.k.db.in_tenant(actor.tenant) as cur:
            review = self._for_decider(cur, actor, review_id)
            review["entries"] = self.k._personal_of(cur, review["person"])
            self.k._evidence(
                cur,
                actor,
                "knowledge.leaver-review.read",
                "LeaverReview",
                review_id,
                after={"entries": len(review["entries"])},
            )
            return review

    def decide(self, actor: Actor, review_id: str, body: dict[str, Any]) -> dict[str, Any]:
        decision = body["decision"]
        with self.k.db.in_tenant(actor.tenant) as cur:
            review = self._for_decider(cur, actor, review_id, lock=True)
            if review["status"] != "open":
                raise Conflict(f"review is closed ({review.get('outcome')})")
            after: dict[str, Any] = {"decision": decision, "reason": body["reason"]}
            if decision == "keep":
                if review["kept"]:
                    raise Conflict("this review was already kept once; merge or purge it")
                cur.execute(
                    "UPDATE knowledge.leaver_reviews SET kept = true, deadline = deadline + %s WHERE id = %s",
                    (REVIEW_PERIOD, review_id),
                )
                after["deadline"] = self._require(cur, review_id)["deadline"]
            elif decision == "merge":
                ids = [UUID(str(i)) for i in body["entryIds"]]
                proposal = self.k._propose(
                    cur,
                    actor,
                    review["person"],
                    body["pack"],
                    ids,
                    body["summary"],
                    proposed_by=actor.name,
                )
                after |= {
                    "pack": body["pack"],
                    "proposal": proposal["id"],
                    "purgedEntries": self._purge(cur, review["person"]),
                }
                self._close(cur, review_id, "merged", proposal["id"])
            elif decision == "purge":
                after["purgedEntries"] = self._purge(cur, review["person"])
                self._close(cur, review_id, "purged")
            else:
                raise Invalid(f"unknown decision {decision!r}")
            self.k._evidence(
                cur,
                actor,
                "knowledge.leaver-review.decided",
                "LeaverReview",
                review_id,
                after=after,
            )
            return self._require(cur, review_id)

    # Helpers ---------------------------------------------------------------------------------

    def _get(self, cur: Cursor, review_id: str, lock: bool = False) -> dict[str, Any] | None:
        cur.execute(
            f"SELECT {_COLUMNS} FROM knowledge.leaver_reviews WHERE id = %s"  # noqa: S608
            + (" FOR UPDATE" if lock else ""),
            (review_id,),
        )
        row = cur.fetchone()
        return _review(row) if row else None

    def _require(self, cur: Cursor, review_id: str) -> dict[str, Any]:
        review = self._get(cur, review_id, lock=True)
        if review is None:
            raise NotFound(f"leaver review {review_id}")
        return review

    def _for_decider(
        self, cur: Cursor, actor: Actor, review_id: str, lock: bool = False
    ) -> dict[str, Any]:
        """The review if actor decides it; otherwise not found, so existence does not leak."""
        review = self._get(cur, review_id, lock=lock)
        if review is None:
            raise NotFound(f"leaver review {review_id}")
        decider = review.get("decider")
        if decider == actor.name or (decider is None and is_officer(cur, actor.name)):
            return review
        raise NotFound(f"leaver review {review_id}")

    def _close(
        self, cur: Cursor, review_id: str, outcome: str, proposal: UUID | None = None
    ) -> None:
        cur.execute(
            "UPDATE knowledge.leaver_reviews SET status = 'closed', outcome = %s, proposal_id = %s,"
            " closed_at = now() WHERE id = %s",
            (outcome, proposal, review_id),
        )

    def _purge(self, cur: Cursor, person: str) -> int:
        """Delete the person's personal layer. Copies already in proposals remain."""
        cur.execute(
            "DELETE FROM knowledge.personal_entries WHERE owner = %s RETURNING entry_id", (person,)
        )
        ids = [r[0] for r in cur.fetchall()]
        if ids:
            cur.execute(
                "DELETE FROM knowledge.entries e WHERE e.id = ANY(%s)"
                " AND NOT EXISTS (SELECT 1 FROM knowledge.proposal_entries p WHERE p.tenant_id = e.tenant_id AND p.entry_id = e.id)"
                " AND NOT EXISTS (SELECT 1 FROM knowledge.pack_version_entries v WHERE v.tenant_id = e.tenant_id AND v.entry_id = e.id)",
                (ids,),
            )
        return len(ids)
