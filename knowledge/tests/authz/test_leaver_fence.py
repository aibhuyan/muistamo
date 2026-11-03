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
from muistamo_knowledge import auth
from muistamo_knowledge.leavers import set_service_secret

pytestmark = pytest.mark.authz

SECRET = b"mks_test-only-not-a-secret-0123456789abcdef"
SUPERSEDED = "https://muistamo.dev/problems/superseded"
PERSON = uuid.UUID("7a000000-0000-4000-8000-00000000000a")
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

    def post(self, path: str, body: dict | None = None):
        raw = json.dumps(body).encode() if body is not None else b""
        return self.service.post(
            path,
            content=raw,
            headers={
                "X-Muistamo-Tenant": str(self.world.tenant),
                "X-Muistamo-Signature": auth.sign(SECRET, raw),
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
        events = self.world.knowledge.events(self.world.actor("auditor@example.invalid"), 0, 1000)
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
    got = live.person(MANAGER).get("/v1/knowledge/leaver-reviews/leave-2:run")
    assert got.status_code == 200 and [e["key"] for e in got.json()["entries"]] == ["fiscal-year"]
    assert live.person(OTHER).get("/v1/knowledge/leaver-reviews/leave-2:run").status_code == 404
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
    assert live.person(MANAGER).get("/v1/knowledge/leaver-reviews").json()["items"] == []
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
    decision = live.person(MANAGER).post(
        "/v1/knowledge/leaver-reviews/leave-2:run/decision",
        json={"decision": "purge", "reason": "late"},
    )
    assert decision.status_code in (404, 409) and [e["key"] for e in live.entries()] == [
        "fiscal-year"
    ]
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
    decision = live.person(MANAGER).post(
        "/v1/knowledge/leaver-reviews/leave-2:run/decision",
        json={"decision": "purge", "reason": "the layer is not needed"},
    )
    assert superseded(decision), decision.text
    assert [e["key"] for e in live.entries()] == ["fiscal-year"]


def test_a_fence_never_moves_back_and_a_late_fence_leaves_a_newer_review_open(live) -> None:
    assert live.fence(3).status_code == 200
    assert live.open("leave-4:run", 4).status_code == 201  # left again after the rehire
    late = live.fence(3)  # the first rehire's fence, retried late
    assert late.status_code == 200 and late.json() == {"user": P, "generation": 4, "cancelled": []}
    assert live.frozen()
    review = live.person(MANAGER).get("/v1/knowledge/leaver-reviews/leave-4:run").json()
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
        live.person(MANAGER).get("/v1/knowledge/leaver-reviews/leave-2:run").json()["outcome"]
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


def test_erasure_removes_the_fence_with_the_person(live) -> None:
    assert live.fence(3).status_code == 200
    with psycopg.connect(live.world.db.app_url) as conn, conn.transaction():
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(live.world.tenant),))
        counts = conn.execute(
            "SELECT knowledge.erase_subject(%s, %s, %s)", ([P], f"erased:{uuid.uuid4()}", [])
        ).fetchone()[0]
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
    assert not live.frozen()


def test_a_live_review_is_not_cancelled_by_id(live) -> None:
    assert live.open("leave-2:run", 2).status_code == 201
    res = live.post("/v1/knowledge/internal/leaver-reviews/leave-2:run/cancel")
    assert res.status_code == 422 and live.frozen()
