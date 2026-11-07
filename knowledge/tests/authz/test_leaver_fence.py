"""Adversarial suite: live leaver reviews ordered by HR generation (docs/live-review-plan.md).

HUMAN REVIEW REQUIRED (CLAUDE.md): a deletion path. Never skip or weaken.

A late call from an earlier leaving, arriving after the person was rehired, must change nothing:
no freeze, no exposure to the decider, and above all no purge of a returning person's layer.
"""

from __future__ import annotations

import json
import uuid

import psycopg
import pytest
from muistamo_knowledge import auth, entra, evidence
from muistamo_knowledge.leavers import set_service_secret

pytestmark = pytest.mark.authz

SECRET = b"mks_test-only-not-a-secret-0123456789abcdef"
SUPERSEDED = "https://muistamo.dev/problems/superseded"
PERSON = uuid.UUID("7a000000-0000-4000-8000-00000000000a")
CONSOLE = uuid.UUID("7a000000-0000-4000-8000-0000000c0501")
MANAGER = uuid.UUID("7a000000-0000-4000-8000-00000000000b")
OTHER = uuid.UUID("7a000000-0000-4000-8000-00000000000c")
P, M = f"entra:{PERSON}", f"entra:{MANAGER}"
NOTE = {"key": "fiscal-year", "type": "fact", "title": "Fiscal year", "body": "Starts in April."}


class Live:
    """The control plane's signed service calls, and each person's own Entra client."""

    def __init__(self, entra_world) -> None:
        self.ew, self.world = entra_world, entra_world.world
        set_service_secret(self.world.db.owner_url, self.world.tenant, SECRET)
        self.service = entra_world.client(None)
        # Leaver reviews are decided in the console, never through an assistant (migration 0013).
        entra.allow_assistant(
            self.world.db.owner_url, self.world.tenant, CONSOLE, "Muistamo console", "console"
        )

    def post(self, path: str, body: dict | None = None):
        raw = json.dumps(body).encode() if body is not None else b""
        return self.service.post(
            path,
            content=raw,
            headers={
                "X-Muistamo-Tenant": str(self.world.tenant),
                "X-Muistamo-Signature": auth.sign(SECRET, raw, method="POST", path=path),
                "Content-Type": "application/json",
            },
        )

    def open(self, review_id: str, generation: int, deciders: list | None = None):
        deciders = [{"user": M, "kind": "manager"}] if deciders is None else deciders
        return self.post(
            "/v1/knowledge/internal/leaver-reviews",
            {
                "id": review_id,
                "generation": generation,
                "person": {"user": P},
                "deciders": deciders,
            },
        )

    def fence(self, generation: int, user: str = P):
        return self.post(
            "/v1/knowledge/internal/leaver-reviews/fence", {"user": user, "generation": generation}
        )

    def expire(self, review_id: str):
        return self.post(f"/v1/knowledge/internal/leaver-reviews/{review_id}/expire")

    def person(self, who: uuid.UUID):
        return self.ew.client(self.ew.directory.token(who))

    def console(self, who: uuid.UUID):
        """The person acting as themselves, in Muistamo's console."""
        return self.ew.client(self.ew.directory.token(who, azp=str(CONSOLE)))

    def entries(self) -> list:
        return self.person(PERSON).get("/v1/knowledge/personal/entries").json()["items"]

    def frozen(self) -> bool:
        res = self.person(PERSON).post(
            "/v1/knowledge/personal/entries",
            json={
                "key": f"probe-{uuid.uuid4().hex[:8]}",
                "type": "fact",
                "title": "p",
                "body": "b",
            },
        )
        assert res.status_code in (201, 409), res.text
        if res.status_code == 201:
            assert (
                self.person(PERSON)
                .delete(f"/v1/knowledge/personal/entries/{res.json()['id']}")
                .status_code
                == 204
            )
        return res.status_code == 409

    def owner_sql(self, sql: str, params: tuple = ()) -> list[tuple]:
        """As the schema owner, inside the tenant (row-level security is forced for it too)."""
        with psycopg.connect(self.world.db.owner_url) as conn, conn.transaction():
            conn.execute(
                "SELECT set_config('muistamo.tenant_id', %s, true)", (str(self.world.tenant),)
            )
            cur = conn.execute(sql, params)
            return cur.fetchall() if cur.description else []

    def past_deadline(self, review_id: str) -> None:
        self.owner_sql(
            "UPDATE knowledge.leaver_reviews SET deadline = now() - interval '1 day' WHERE id = %s",
            (review_id,),
        )

    def actions(self) -> list[tuple[str, dict]]:
        # Read directly: the export itself is for privacy officers (D59).
        with self.world.knowledge.db.in_tenant(self.world.tenant) as cur:
            events = evidence.list_events(cur, 0, 1000)
        return [(e.action, e.after or {}) for e in events]


@pytest.fixture
def live(entra_world) -> Live:
    live = Live(entra_world)
    assert live.person(PERSON).post("/v1/knowledge/personal/entries", json=NOTE).status_code == 201
    return live


def superseded(res) -> bool:
    return res.status_code == 409 and res.json().get("type") == SUPERSEDED


def test_a_live_review_is_opened_by_user_at_its_generation_and_decided_by_the_manager(live) -> None:
    res = live.open("leave-2:run", 2)
    assert res.status_code == 201, res.text
    review = res.json()
    assert review["person"] == P and review["decider"] == M and review["generation"] == 2
    assert live.frozen()
    got = live.console(MANAGER).get("/v1/knowledge/leaver-reviews/leave-2:run")
    assert got.status_code == 200 and [e["key"] for e in got.json()["entries"]] == ["fiscal-year"]
    assert live.console(OTHER).get("/v1/knowledge/leaver-reviews/leave-2:run").status_code == 404
    assert live.open("leave-2:run", 2).json() == review  # a retry is the same review


def test_a_late_open_after_the_rehire_fence_freezes_and_exposes_nothing(live) -> None:
    fenced = live.fence(3)
    assert fenced.status_code == 200 and fenced.json() == {
        "user": P,
        "generation": 3,
        "cancelled": [],
    }
    late = live.open("leave-2:run", 2)
    assert superseded(late), late.text
    assert not live.frozen()
    assert live.console(MANAGER).get("/v1/knowledge/leaver-reviews").json()["items"] == []
    assert live.owner_sql("SELECT count(*) FROM knowledge.leaver_reviews")[0][0] == 0
    refused = [a for a in live.actions() if a[0] == "knowledge.leaver-review.refused"]
    assert refused and refused[-1][1]["reason"] == "superseded" and refused[-1][1]["fence"] == 3


def test_the_fence_cancels_the_earlier_review_and_late_calls_cannot_purge_the_layer(live) -> None:
    assert live.open("leave-2:run", 2).status_code == 201
    fenced = live.fence(3)
    assert fenced.json() == {"user": P, "generation": 3, "cancelled": ["leave-2:run"]}
    assert not live.frozen()
    # The old leaver run, retried after the rehire: its open and its expiry change nothing.
    assert superseded(live.open("leave-2:run", 2))
    live.past_deadline("leave-2:run")
    expired = live.expire("leave-2:run")
    assert expired.status_code == 200 and expired.json()["outcome"] == "cancelled"
    assert [e["key"] for e in live.entries()] == ["fiscal-year"]
    # Nor can the manager decide it any more.
    decision = live.console(MANAGER).post(
        "/v1/knowledge/leaver-reviews/leave-2:run/decision",
        json={"decision": "purge", "reason": "late"},
    )
    assert decision.status_code == 409 and [e["key"] for e in live.entries()] == ["fiscal-year"]
    assert (
        "knowledge.leaver-review.fenced",
        {"user": P, "generation": 3, "previous": 2, "cancelled": ["leave-2:run"]},
    ) in live.actions()


def test_an_expiry_purges_only_while_no_later_generation_is_known(live) -> None:
    assert live.open("leave-2:run", 2).status_code == 201
    live.past_deadline("leave-2:run")
    # A later generation recorded without the fence call's cancellation (defence in depth).
    live.owner_sql(
        "UPDATE knowledge.leaver_review_fences SET generation = 3 WHERE person = %s", (P,)
    )
    assert superseded(live.expire("leave-2:run"))
    assert [e["key"] for e in live.entries()] == ["fiscal-year"] and live.frozen()
    assert live.actions()[-1] == (
        "knowledge.leaver-review.refused",
        {"reason": "superseded", "generation": 2, "fence": 3},
    )


def test_an_expiry_at_the_current_generation_purges_the_undecided_layer(live) -> None:
    assert live.open("leave-2:run", 2).status_code == 201
    live.past_deadline("leave-2:run")
    expired = live.expire("leave-2:run")
    assert expired.status_code == 200 and expired.json()["outcome"] == "expired"
    assert live.entries() == []


def test_a_decision_is_refused_once_a_later_generation_is_known(live) -> None:
    assert live.open("leave-2:run", 2).status_code == 201
    live.owner_sql(
        "UPDATE knowledge.leaver_review_fences SET generation = 3 WHERE person = %s", (P,)
    )
    decision = live.console(MANAGER).post(
        "/v1/knowledge/leaver-reviews/leave-2:run/decision",
        json={"decision": "purge", "reason": "the layer is not needed"},
    )
    assert superseded(decision), decision.text
    assert [e["key"] for e in live.entries()] == ["fiscal-year"]
    assert live.actions()[-1] == (
        "knowledge.leaver-review.refused",
        {"reason": "superseded", "generation": 2, "fence": 3},
    )


def test_another_run_of_the_same_leaving_takes_over_its_open_review(live) -> None:
    # A reset leaver workflow opens again at the same generation under a new run id.
    first = live.open("leave-2:run-1", 2).json()
    again = live.open("leave-2:run-2", 2)
    assert again.status_code == 200 and again.json() == first
    live.past_deadline("leave-2:run-1")
    assert live.expire(first["id"]).json()["outcome"] == "expired" and live.entries() == []


@pytest.mark.parametrize("call", ["expire", "decide"])
def test_expiry_and_decisions_take_the_fence_lock_before_the_review_lock(live, call) -> None:
    """Every path locks the fence row first, so a fence (which then locks the review) and a
    decision or expiry cannot deadlock. Here the fence row is held: the call must wait on it
    without having locked the review."""
    import threading

    assert live.open("leave-2:run", 2).status_code == 201
    live.past_deadline("leave-2:run")
    with psycopg.connect(live.world.db.app_url) as holder:
        holder.execute(
            "SELECT set_config('muistamo.tenant_id', %s, false)", (str(live.world.tenant),)
        )
        holder.execute("SELECT 1 FROM knowledge.leaver_review_fences FOR UPDATE")
        results: list = []

        def run() -> None:
            if call == "expire":
                results.append(live.expire("leave-2:run"))
            else:
                results.append(
                    live.console(MANAGER).post(
                        "/v1/knowledge/leaver-reviews/leave-2:run/decision",
                        json={"decision": "keep", "reason": "still needed"},
                    )
                )

        worker = threading.Thread(target=run)
        worker.start()
        worker.join(timeout=2)
        assert worker.is_alive(), "the call did not wait for the fence row"
        # The review row is free: the waiting call has not locked it.
        holder.execute("SELECT 1 FROM knowledge.leaver_reviews FOR UPDATE NOWAIT")
        holder.rollback()
        worker.join(timeout=30)
    assert results and results[0].status_code == 200, results


def test_a_fence_never_moves_back_and_a_late_fence_leaves_a_newer_review_open(live) -> None:
    assert live.fence(3).status_code == 200
    assert live.open("leave-4:run", 4).status_code == 201  # left again after the rehire
    late = live.fence(3)  # the first rehire's fence, retried late
    assert late.status_code == 200 and late.json() == {"user": P, "generation": 4, "cancelled": []}
    assert live.frozen()
    review = live.console(MANAGER).get("/v1/knowledge/leaver-reviews/leave-4:run").json()
    assert review["status"] == "open"
    # An equal generation does not cancel the review it opened.
    assert live.fence(4).json()["cancelled"] == [] and live.frozen()


def test_a_later_leaving_supersedes_an_earlier_review_even_when_the_rehire_fence_was_lost(
    live,
) -> None:
    assert live.open("leave-2:run", 2).status_code == 201
    # Rehired at 3 (its fence never arrived), then left again at 4.
    later = live.open("leave-4:run", 4)
    assert later.status_code == 201 and later.json()["status"] == "open", later.text
    assert (
        live.console(MANAGER).get("/v1/knowledge/leaver-reviews/leave-2:run").json()["outcome"]
        == "cancelled"
    )
    live.past_deadline("leave-2:run")
    assert live.expire("leave-2:run").json()["outcome"] == "cancelled"
    assert [e["key"] for e in live.entries()] == ["fiscal-year"] and live.frozen()


def test_the_server_role_can_neither_lower_nor_delete_a_fence(live) -> None:
    assert live.fence(5).status_code == 200
    with psycopg.connect(live.world.db.app_url) as conn:
        conn.execute(
            "SELECT set_config('muistamo.tenant_id', %s, false)", (str(live.world.tenant),)
        )
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(
                "UPDATE knowledge.leaver_review_fences SET generation = 4 WHERE person = %s", (P,)
            )
        conn.rollback()
        conn.execute(
            "SELECT set_config('muistamo.tenant_id', %s, false)", (str(live.world.tenant),)
        )
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(
                "UPDATE knowledge.leaver_review_fences SET person = 'entra:x' WHERE person = %s",
                (P,),
            )
        conn.rollback()
        conn.execute(
            "SELECT set_config('muistamo.tenant_id', %s, false)", (str(live.world.tenant),)
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM knowledge.leaver_review_fences")
    assert live.owner_sql("SELECT generation FROM knowledge.leaver_review_fences")[0][0] == 5


def test_only_a_live_person_has_a_review_generation(live) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        live.owner_sql(
            "INSERT INTO knowledge.leaver_reviews (tenant_id, id, person, decider_kind, status,"
            " deadline, entry_count, generation)"
            " VALUES (%s, 'legacy:run', 'dev:a@example.invalid', 'privacy-officers', 'open',"
            " now(), 1, 2)",
            (live.world.tenant,),
        )


def test_erasure_removes_the_fence_with_the_person(live) -> None:
    from muistamo_knowledge.privacy import rows_mentioning

    assert live.fence(3).status_code == 200
    with psycopg.connect(live.world.db.app_url) as conn, conn.transaction():
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(live.world.tenant),))
        # An access request exports the fence as the person's data.
        with conn.cursor() as cur:
            exported = rows_mentioning(cur, "leaver_review_fences", [P])
        assert [(r["person"], r["generation"]) for r in exported] == [(P, 3)]
        counts = conn.execute(
            "SELECT knowledge.erase_subject(%s, %s, %s)", ([P], f"erased:{uuid.uuid4()}", [])
        ).fetchone()[0]
        with conn.cursor() as cur:
            assert rows_mentioning(cur, "leaver_review_fences", [P]) == []
    assert counts["leaver_review_fences"] == 1
    assert live.owner_sql("SELECT count(*) FROM knowledge.leaver_review_fences")[0][0] == 0


@pytest.mark.parametrize(
    "body",
    [
        # Live person without a generation, and a generation without a live person.
        {"id": "x", "person": {"user": P}, "deciders": []},
        {"id": "x", "generation": 2, "person": {"email": "a@example.invalid"}, "deciders": []},
        # Both identities for one person, or neither.
        {
            "id": "x",
            "generation": 2,
            "person": {"user": P, "email": "a@example.invalid"},
            "deciders": [],
        },
        {"id": "x", "generation": 2, "person": {}, "deciders": []},
        # A live leaver's deciders are named by user; a legacy one's by email.
        {
            "id": "x",
            "generation": 2,
            "person": {"user": P},
            "deciders": [{"email": "m@example.invalid", "kind": "manager"}],
        },
        {
            "id": "x",
            "person": {"email": "a@example.invalid"},
            "deciders": [{"user": M, "kind": "manager"}],
        },
        {
            "id": "x",
            "generation": 2,
            "person": {"user": P},
            "deciders": [{"user": M, "email": "m@example.invalid", "kind": "manager"}],
        },
        {"id": "x", "generation": 0, "person": {"user": P}, "deciders": []},
        {"id": "x", "generation": 2, "person": {"user": "entra:not-an-object-id"}, "deciders": []},
    ],
)
def test_mixed_or_incomplete_review_requests_are_refused(live, body) -> None:
    res = live.post("/v1/knowledge/internal/leaver-reviews", body)
    assert res.status_code == 422, (body, res.text)
    # The control plane may record the answer: it never echoes the identities sent.
    assert P not in res.text and M not in res.text and "not-an-object-id" not in res.text, res.text
    assert not live.frozen()


def test_a_live_review_is_not_cancelled_by_id(live) -> None:
    assert live.open("leave-2:run", 2).status_code == 201
    res = live.post("/v1/knowledge/internal/leaver-reviews/leave-2:run/cancel")
    assert res.status_code == 422 and live.frozen()


# Private entries (D59) on live, generation-ordered reviews ----------------------------------

PRIVATE = {
    "key": "private-note",
    "type": "fact",
    "title": "Private",
    "body": "Only mine: d59-live-body.",
    "private": True,
}


def private_purges(live) -> list[dict]:
    return [a for name, a in live.actions() if name == "knowledge.personal.private-purged"]


def keys(live) -> set[str]:
    return {e["key"] for e in live.entries()}


@pytest.fixture
def private_live(live) -> Live:
    live.world.knowledge.private_entries = True
    res = live.person(PERSON).post("/v1/knowledge/personal/entries", json=PRIVATE)
    assert res.status_code == 201 and res.json()["private"] is True, res.text
    return live


def test_a_superseded_open_never_purges_private_entries(private_live) -> None:
    """A late open from an old leaving, after a rehire, must not delete notes the rehired person
    keeps: the purge runs only once the open is known to be current."""
    live = private_live
    assert live.fence(2).status_code == 200
    late = live.open("leave-1:run-1", 1)
    assert late.status_code == 409 and late.json()["type"] == SUPERSEDED
    assert keys(live) == {"fiscal-year", "private-note"}
    assert private_purges(live) == []


def test_another_run_of_the_same_leaving_purges_nothing_more(private_live) -> None:
    live = private_live
    assert live.open("leave-2:run-1", 2).status_code == 201
    assert keys(live) == {"fiscal-year"}
    # A private row that appeared since (inserted directly: the layer is frozen) is left to the
    # review that already holds the layer; the takeover returns before any purge.
    entry = live.owner_sql(
        "SELECT entry_id FROM knowledge.personal_entries WHERE owner = %s", (P,)
    )[0][0]
    live.owner_sql(
        "UPDATE knowledge.personal_entries SET private = true WHERE entry_id = %s", (entry,)
    )
    assert live.open("leave-2:run-2", 2).status_code == 200
    assert private_purges(live) == [{"review": "leave-2:run-1", "purgedPrivateEntries": 1}]
    assert live.owner_sql(
        "SELECT private FROM knowledge.personal_entries WHERE entry_id = %s", (entry,)
    ) == [(True,)]


def test_after_a_rehire_the_person_finds_only_their_shared_entries(private_live) -> None:
    live = private_live
    assert live.open("leave-2:run-1", 2).status_code == 201
    assert live.fence(3).status_code == 200  # rehired: the review is cancelled
    assert not live.frozen()
    assert keys(live) == {"fiscal-year"}  # private notes went at leaving (D59)
