"""Leaver personal-layer reviews (E4.2, J2).

HUMAN REVIEW REQUIRED (CLAUDE.md): an authorisation exception and a deletion path.

The control plane's leaver workflow opens a review with a signed service call. While it is open
the leaver's personal layer is frozen, and its decider (the manager, else an instance sponsor,
else any privacy officer) is the one person besides the owner who may read it. Every read is
recorded. The decider merges chosen entries as a proposal (which they cannot approve), keeps the
layer for one more period (once), or purges it. When the workflow reports the grace period over,
an undecided layer is purged. A rehire cancels the review and unfreezes the layer.

Live (Entra) reviews are ordered by HR generation (docs/live-review-plan.md). The person's fence
is the highest generation the control plane has sent for them, and it only moves forward. A call
from an earlier generation is refused as superseded, with signed evidence, and changes nothing:
a late call from a leaving cannot freeze, expose or purge the layer of a person since rehired.
Raising the fence cancels the person's open reviews from earlier generations.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg
from psycopg import Cursor

from muistamo_knowledge.auth import IdentityMap, UnmappedIdentity
from muistamo_knowledge.privacy import is_officer
from muistamo_knowledge.service import Actor, Conflict, Invalid, Knowledge, NotFound, Superseded

REVIEW_PERIOD = timedelta(days=30)  # the control plane's leaver grace period
SERVICE_ACTOR = "service:control-plane"

_COLUMNS = (
    "id, person, decider_kind, decider, status, outcome, deadline, kept, entry_count,"
    " proposal_id, opened_at, closed_at, generation"
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
        ("generation", row[12]),
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
        """Open and freeze the review. Repeating an id returns the existing review. A live
        review from a generation older than the person's fence is refused as superseded."""
        actor = Actor(
            tenant=tenant, name=SERVICE_ACTOR, request_id=f"leaver-review:{request['id']}"
        )
        generation = request.get("generation")
        person, candidates = self._parties(request)
        decider, kind = next(
            ((i, k) for i, k in candidates if i != person), (None, "privacy-officers")
        )

        refused: Superseded | None = None
        with self.k.db.in_tenant(tenant) as cur:
            if generation is not None:
                fence = self._raise_fence(cur, tenant, person, generation)
                if fence > generation:
                    refused = self._refuse(cur, actor, request["id"], generation, fence)
                else:
                    self._cancel_before(cur, actor, person, generation)
            if refused is None:
                return self._open(cur, actor, request["id"], person, decider, kind, generation)
        # Committed: the refusal's evidence, and nothing else.
        raise refused

    def fence(self, tenant: UUID, user: str, generation: int) -> dict[str, Any]:
        """A live person was rehired at this generation: raise their fence, never lowering it,
        and cancel their open reviews from earlier generations. Repeating it is safe."""
        actor = Actor(tenant=tenant, name=SERVICE_ACTOR, request_id=f"leaver-fence:{generation}")
        with self.k.db.in_tenant(tenant) as cur:
            previous = self._fence_of(cur, user, lock=True)
            current = self._raise_fence(cur, tenant, user, generation)
            cancelled = self._cancel_before(cur, actor, user, current)
            if previous != current or cancelled:
                self.k._evidence(
                    cur,
                    actor,
                    "knowledge.leaver-review.fenced",
                    "LeaverReviewFence",
                    user,
                    after={
                        "user": user,
                        "generation": current,
                        "previous": previous,
                        "cancelled": cancelled,
                    },
                )
            return {"user": user, "generation": current, "cancelled": cancelled}

    def expire(self, tenant: UUID, review_id: str) -> dict[str, Any]:
        """The grace period is over: purge an undecided layer whose deadline has passed. A kept
        review is returned still open, with its later deadline, for the workflow to wait for.
        A live review purges only while its generation is still the person's fence."""
        actor = Actor(tenant=tenant, name=SERVICE_ACTOR, request_id=f"leaver-review:{review_id}")
        refused: Superseded | None = None
        with self.k.db.in_tenant(tenant) as cur:
            review = self._require(cur, review_id)
            if review["status"] == "closed":
                return review
            refused = self._check_current(cur, actor, review)
            if refused is None:
                if review["deadline"] > datetime.now(UTC):
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
        raise refused

    def cancel(self, tenant: UUID, review_id: str) -> dict[str, Any]:
        """The person was rehired: close an open review and unfreeze the layer. Legacy reviews
        only; a live review is cancelled by the person's fence, which orders late calls."""
        actor = Actor(tenant=tenant, name=SERVICE_ACTOR, request_id=f"leaver-review:{review_id}")
        with self.k.db.in_tenant(tenant) as cur:
            review = self._require(cur, review_id)
            if review.get("generation") is not None:
                raise Invalid("a live review is cancelled by the person's fence, not by id")
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
        refused: Superseded | None = None
        with self.k.db.in_tenant(actor.tenant) as cur:
            review = self._for_decider(cur, actor, review_id, lock=True)
            if review["status"] != "open":
                raise Conflict(f"review is closed ({review.get('outcome')})")
            refused = self._check_current(cur, actor, review)
            if refused is None:
                return self._decide(cur, actor, review, body)
        raise refused

    # Helpers ---------------------------------------------------------------------------------

    def _parties(self, request: dict[str, Any]) -> tuple[str, list[tuple[str, str]]]:
        """The person and candidate deciders. A live leaver names them all by user and carries
        its generation; a legacy one names them by email, mapped here, and carries none."""
        doc, deciders = request["person"], request["deciders"]
        live = "user" in doc
        if live == ("email" in doc):
            raise Invalid("name the person by exactly one of email or user")
        if live != (request.get("generation") is not None):
            raise Invalid(
                "a live leaver, named by user, carries its HR generation; a legacy one does not"
            )
        field, other = ("user", "email") if live else ("email", "user")
        if any(field not in d or other in d for d in deciders):
            raise Invalid(f"name every decider by {field}, as the person is")
        if live:
            return doc["user"], [(d["user"], d["kind"]) for d in deciders]
        try:
            return self.identity_for_email(doc["email"]), [
                (self.identity_for_email(d["email"]), d["kind"]) for d in deciders
            ]
        except UnmappedIdentity as exc:
            raise Invalid(f"cannot open a review: {exc}") from exc

    def _open(
        self,
        cur: Cursor,
        actor: Actor,
        review_id: str,
        person: str,
        decider: str | None,
        kind: str,
        generation: int | None,
    ) -> tuple[dict[str, Any], bool]:
        existing = self._get(cur, review_id, lock=True)
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
        status, outcome, closed = ("closed", "empty", now) if count == 0 else ("open", None, None)
        cur.execute(
            "INSERT INTO knowledge.leaver_reviews (tenant_id, id, person, decider_kind, decider,"
            " status, outcome, deadline, entry_count, opened_at, closed_at, generation)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                actor.tenant,
                review_id,
                person,
                kind,
                decider,
                status,
                outcome,
                now + REVIEW_PERIOD,
                count,
                now,
                closed,
                generation,
            ),
        )
        review = self._require(cur, review_id)
        self.k._evidence(
            cur,
            actor,
            "knowledge.leaver-review.opened",
            "LeaverReview",
            review_id,
            after={
                k: review[k] for k in ("person", "deciderKind", "status", "deadline", "entryCount")
            }
            | ({"decider": decider} if decider else {})
            | ({"outcome": outcome} if outcome else {})
            | ({"generation": generation} if generation is not None else {}),
        )
        return review, True

    def _decide(
        self, cur: Cursor, actor: Actor, review: dict[str, Any], body: dict[str, Any]
    ) -> dict[str, Any]:
        review_id, decision = review["id"], body["decision"]
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

    def _fence_of(self, cur: Cursor, person: str, lock: bool = False) -> int | None:
        cur.execute(
            "SELECT generation FROM knowledge.leaver_review_fences WHERE person = %s"  # noqa: S608
            + (" FOR UPDATE" if lock else " FOR SHARE"),
            (person,),
        )
        row = cur.fetchone()
        return int(row[0]) if row else None

    def _raise_fence(self, cur: Cursor, tenant: UUID, person: str, generation: int) -> int:
        """Raise the person's fence to generation if it is lower, under the fence row's lock,
        and return the fence. It never moves back; the table's trigger also refuses that."""
        cur.execute(
            "INSERT INTO knowledge.leaver_review_fences (tenant_id, person, generation)"
            " VALUES (%s, %s, %s) ON CONFLICT (tenant_id, person) DO NOTHING",
            (tenant, person, generation),
        )
        current = self._fence_of(cur, person, lock=True)
        if current is None:
            raise Conflict("the person's leaver-review fence could not be read")
        if current >= generation:
            return current
        cur.execute(
            "UPDATE knowledge.leaver_review_fences SET generation = %s, updated_at = now()"
            " WHERE person = %s",
            (generation, person),
        )
        return generation

    def _cancel_before(self, cur: Cursor, actor: Actor, person: str, generation: int) -> list[str]:
        """Cancel the person's open live reviews from generations before this one."""
        cur.execute(
            "SELECT id FROM knowledge.leaver_reviews WHERE person = %s AND status = 'open'"
            " AND generation IS NOT NULL AND generation < %s ORDER BY id FOR UPDATE",
            (person, generation),
        )
        ids = [r[0] for r in cur.fetchall()]
        for review_id in ids:
            self._close(cur, review_id, "cancelled")
            self.k._evidence(
                cur,
                actor,
                "knowledge.leaver-review.cancelled",
                "LeaverReview",
                review_id,
                after={"outcome": "cancelled", "fence": generation},
            )
        return ids

    def _check_current(
        self, cur: Cursor, actor: Actor, review: dict[str, Any]
    ) -> Superseded | None:
        """A live review acts only while its generation is still the person's fence."""
        generation = review.get("generation")
        if generation is None:
            return None
        fence = self._fence_of(cur, review["person"])
        if fence == generation:
            return None
        return self._refuse(cur, actor, review["id"], generation, fence)

    def _refuse(
        self, cur: Cursor, actor: Actor, review_id: str, generation: int, fence: int | None
    ) -> Superseded:
        """Record the refusal. The caller commits only this, then raises what is returned."""
        self.k._evidence(
            cur,
            actor,
            "knowledge.leaver-review.refused",
            "LeaverReview",
            review_id,
            after={"reason": "superseded", "generation": generation, "fence": fence},
        )
        return Superseded(
            f"leaver review {review_id} is from HR generation {generation};"
            f" the person's fence is {fence}"
        )

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
