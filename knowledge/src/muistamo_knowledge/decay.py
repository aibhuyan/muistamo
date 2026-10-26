"""Decay and provenance of knowledge entries (FR-307).

HUMAN REVIEW REQUIRED (CLAUDE.md): this decides which pack entries agents are still told.

A pack entry is trusted for as long as a reviewer last vouched for it: by approving the proposal
that merged it, by confirming it again, or by rolling the pack back to bring it back. Each of
those writes a row in knowledge.verifications. Against the pack's decay policy an entry is

    current  until verifiedAt + reviewEveryDays,
    due      for graceDays after that: still served, flagged, queued for the pack's reviewers,
    expired  afterwards: never served (resolve withholds it), and removed by the next sweep.

Mandatory packs never expire: their entries stay due and are flagged to privacy officers, because
silently dropping a compliance rule is worse than serving an unconfirmed one.

The provenance score is informational and never changes ranking. Its factors are listed, so
anyone can see why an entry scored what it did.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from psycopg import Cursor

log = logging.getLogger("muistamo.knowledge")

DEFAULT_REVIEW_EVERY_DAYS = 365
DEFAULT_GRACE_DAYS = 30

# Who removes expired entries. Not a person: the sweep acts on the packs' own decay policies.
SWEEP_ACTOR = "system:decay"

POINTS_REVIEWED = 40
POINTS_SOURCE = 20
POINTS_REVIEWER_EDITED = 10
POINTS_FRESHNESS = {"current": 30, "due": 10, "expired": 0}


def policy(decay: dict[str, Any] | None) -> tuple[int, int]:
    """(reviewEveryDays, graceDays) from a pack's spec.decay, with the defaults."""
    decay = decay or {}
    return (
        int(decay.get("reviewEveryDays", DEFAULT_REVIEW_EVERY_DAYS)),
        int(decay.get("graceDays", DEFAULT_GRACE_DAYS)),
    )


def state(
    verified_at: datetime | None,
    verified_by: str | None,
    every_days: int,
    grace_days: int,
    mandatory: bool,
    now: datetime,
) -> dict[str, Any]:
    """An entry's decay state. No verification at all means nobody vouches for it: expired
    (withheld), or due for a mandatory pack, which never expires."""
    if verified_at is None or verified_by is None:
        log.warning("pack entry has no verification; treating it as unconfirmed")
        return {"status": "due" if mandatory else "expired"}
    due_at = verified_at + timedelta(days=every_days)
    expires_at = due_at + timedelta(days=grace_days)
    if now < due_at:
        status = "current"
    elif mandatory or now < expires_at:
        status = "due"
    else:
        status = "expired"
    out: dict[str, Any] = {
        "status": status,
        "verifiedAt": verified_at,
        "verifiedBy": verified_by,
        "dueAt": due_at,
    }
    if not mandatory:
        out["expiresAt"] = expires_at
    return out


def provenance(
    *, reviewed: bool, has_source: bool, reviewer_edited: bool, status: str | None
) -> dict[str, Any]:
    """The 0-100 score and the factors that make it up."""
    factors = []
    if reviewed:
        factors.append({"factor": "reviewed", "points": POINTS_REVIEWED})
    if has_source:
        factors.append({"factor": "source", "points": POINTS_SOURCE})
    if reviewer_edited:
        factors.append({"factor": "reviewer-edited", "points": POINTS_REVIEWER_EDITED})
    if status is not None:
        factors.append({"factor": "freshness", "points": POINTS_FRESHNESS[status]})
    return {"score": sum(f["points"] for f in factors), "factors": factors}


def latest(cur: Cursor, pack: str, entry_ids: list[UUID]) -> dict[UUID, tuple[datetime, str]]:
    """The latest verification of each entry in a pack: {entry id: (verified at, by)}."""
    if not entry_ids:
        return {}
    cur.execute(
        "SELECT DISTINCT ON (entry_id) entry_id, verified_at, verified_by FROM knowledge.verifications"
        " WHERE pack = %s AND entry_id = ANY(%s) ORDER BY entry_id, verified_at DESC",
        (pack, entry_ids),
    )
    return {r[0]: (r[1], r[2]) for r in cur.fetchall()}


def edited(cur: Cursor, merged: list[tuple[UUID, UUID]]) -> set[UUID]:
    """Of (entry id, proposal id) pairs, the entries that are a reviewer's edit of what was
    proposed: an edit is a new revision, so it is not one of its proposal's own entries.
    (derived_from alone cannot tell: every proposal copies its entries with derived_from set.)"""
    if not merged:
        return set()
    cur.execute(
        "SELECT m.entry_id FROM unnest(%s::uuid[], %s::uuid[]) AS m(entry_id, proposal_id)"
        " WHERE NOT EXISTS (SELECT 1 FROM knowledge.proposal_entries pe"
        "   WHERE pe.proposal_id = m.proposal_id AND pe.entry_id = m.entry_id)",
        ([m[0] for m in merged], [m[1] for m in merged]),
    )
    return {r[0] for r in cur.fetchall()}


def record(
    cur: Cursor,
    tenant: UUID,
    pack: str,
    entry_id: UUID,
    at: datetime,
    by: str,
    reason: str,
) -> None:
    cur.execute(
        "INSERT INTO knowledge.verifications (tenant_id, id, pack, entry_id, verified_at, verified_by, reason)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (tenant, uuid.uuid4(), pack, entry_id, at, by, reason),
    )
