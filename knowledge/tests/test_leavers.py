"""Leaver personal-layer reviews (E4.2): freeze, decider, decisions, expiry, cancel, signatures."""

from __future__ import annotations

import json
import time
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient
from muistamo_knowledge import auth
from muistamo_knowledge.app import create_app
from muistamo_knowledge.leavers import Leavers, set_service_secret
from muistamo_knowledge.privacy import replace_officers
from muistamo_knowledge.service import Invalid

A, M, R, S, DPO, X = (
    "person-a@example.invalid",
    "manager-m@example.invalid",
    "reviewer-r@example.invalid",
    "sponsor-s@example.invalid",
    "dpo@example.invalid",
    "someone-x@example.invalid",
)
SECRET = b"mks_test-only-not-a-secret-0123456789abcdef"
PACK = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "KnowledgePack",
    "metadata": {"name": "basics"},
    "spec": {
        "layer": "role",
        "reviewers": ["dev:" + R, "dev:" + M],
        "mergePolicy": {"requires": ["review"]},
    },
}


class Service:
    """Signed calls as the control plane's leaver workflow makes them."""

    def __init__(self, world, tenant=None, secret=SECRET):
        self.client = TestClient(
            create_app(world.knowledge, auth.insecure_dev_headers), raise_server_exceptions=False
        )
        self.tenant, self.secret = tenant or world.tenant, secret

    def post(
        self,
        path: str,
        body: dict | None = None,
        at: float | None = None,
        headers: dict | None = None,
    ):
        raw = json.dumps(body).encode() if body is not None else b""
        h = {
            "X-Muistamo-Tenant": str(self.tenant),
            "X-Muistamo-Signature": auth.sign(self.secret, raw, at),
            "Content-Type": "application/json",
        }
        h.update(headers or {})
        return self.client.post(path, content=raw, headers=h)

    def open(self, review_id: str, person: str = A, deciders: list | None = None):
        deciders = [{"email": M, "kind": "manager"}] if deciders is None else deciders
        return self.post(
            "/v1/knowledge/internal/leaver-reviews",
            {"id": review_id, "person": {"email": person}, "deciders": deciders},
        )


@pytest.fixture
def svc(world):
    set_service_secret(world.db.owner_url, world.tenant, SECRET)
    return Service(world)


def capture(world, person: str, key: str) -> str:
    res = world.client(person).post(
        "/v1/knowledge/personal/entries",
        json={"key": key, "type": "fact", "title": key, "body": f"{key} body"},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def personal(world, person: str) -> list:
    return world.client(person).get("/v1/knowledge/personal/entries").json()["items"]


def test_open_freezes_the_layer_and_only_the_decider_sees_it(world, svc) -> None:
    fiscal = capture(world, A, "fiscal-year")
    capture(world, A, "private-note")
    opened = svc.open("leaver-1:run-1")
    assert opened.status_code == 201, opened.text
    review = opened.json()
    assert review["status"] == "open" and review["deciderKind"] == "manager"
    assert review["decider"] == "dev:" + M and review["entryCount"] == 2
    assert svc.open("leaver-1:run-1").json() == review  # idempotent

    a = world.client(A)
    assert (
        a.post(
            "/v1/knowledge/personal/entries",
            json={"key": "k", "type": "fact", "title": "t", "body": "b"},
        ).status_code
        == 409
    )
    assert a.delete(f"/v1/knowledge/personal/entries/{fiscal}").status_code == 409
    assert len(personal(world, A)) == 2  # still readable by the owner

    m = world.client(M)
    assert [r["id"] for r in m.get("/v1/knowledge/leaver-reviews").json()["items"]] == [
        "leaver-1:run-1"
    ]
    got = m.get("/v1/knowledge/leaver-reviews/leaver-1:run-1")
    assert got.status_code == 200 and {e["key"] for e in got.json()["entries"]} == {
        "fiscal-year",
        "private-note",
    }
    for other in (A, R, X):
        assert (
            world.client(other).get("/v1/knowledge/leaver-reviews/leaver-1:run-1").status_code
            == 404
        ), other
        assert world.client(other).get("/v1/knowledge/leaver-reviews").json()["items"] == []
    reads = [
        e
        for e in world.knowledge.events(world.actor(M), 0, 1000)
        if e.action == "knowledge.leaver-review.read"
    ]
    assert len(reads) == 1 and reads[0].actor == "dev:" + M


def test_merge_proposes_for_the_leaver_and_purges_the_rest(world, svc) -> None:
    assert world.client(R).put("/v1/knowledge/packs/basics", json=PACK).status_code == 201
    keep = capture(world, A, "fiscal-year")
    capture(world, A, "private-note")
    svc.open("leaver-1:run-1")
    m = world.client(M)
    res = m.post(
        "/v1/knowledge/leaver-reviews/leaver-1:run-1/decision",
        json={
            "decision": "merge",
            "reason": "useful",
            "pack": "basics",
            "entryIds": [keep],
            "summary": "from A",
        },
    )
    assert res.status_code == 200, res.text
    review = res.json()
    assert review["status"] == "closed" and review["outcome"] == "merged"
    assert personal(world, A) == []

    proposal = world.client(R).get(f"/v1/knowledge/proposals/{review['proposalId']}").json()
    assert proposal["contributor"] == "dev:" + A and proposal["proposedBy"] == "dev:" + M
    assert [e["key"] for e in proposal["entries"]] == ["fiscal-year"]
    # The manager is a reviewer of the pack, but proposed it, so cannot decide it.
    assert (
        m.post(
            f"/v1/knowledge/proposals/{proposal['id']}/decision",
            json={"decision": "approve", "reason": "x"},
        ).status_code
        == 403
    )
    approved = world.client(R).post(
        f"/v1/knowledge/proposals/{proposal['id']}/decision",
        json={"decision": "approve", "reason": "ok"},
    )
    assert approved.status_code == 200, approved.text
    resolved = (
        world.client(R).get("/v1/knowledge/resolve", params={"packs": "basics"}).json()["items"]
    )
    assert [(i["entry"]["key"], i["entry"]["contributor"]) for i in resolved] == [
        ("fiscal-year", "dev:" + A)
    ]
    # FR-307: proposing for a leaver cannot become self-approval through later confirmation
    # or an extension of the pack's decay policy.
    verify = "/v1/knowledge/packs/basics/entries/fiscal-year/verification"
    body = {"entryId": resolved[0]["entry"]["id"], "reason": "still useful"}
    assert m.post(verify, json=body).status_code == 403
    changed = {**PACK, "spec": {**PACK["spec"], "decay": {"reviewEveryDays": 1000}}}
    assert m.put("/v1/knowledge/packs/basics", json=changed).status_code == 403
    assert world.client(R).post(verify, json=body).status_code == 200

    # A closed review takes no further decisions.
    assert (
        m.post(
            "/v1/knowledge/leaver-reviews/leaver-1:run-1/decision",
            json={"decision": "purge", "reason": "x"},
        ).status_code
        == 409
    )


def test_keep_once_then_purge(world, svc) -> None:
    capture(world, A, "note")
    first = svc.open("leaver-1:run-1").json()
    m = world.client(M)
    kept = m.post(
        "/v1/knowledge/leaver-reviews/leaver-1:run-1/decision",
        json={"decision": "keep", "reason": "busy"},
    )
    assert kept.status_code == 200 and kept.json()["kept"] and kept.json()["status"] == "open"
    assert kept.json()["deadline"] > first["deadline"]
    again = m.post(
        "/v1/knowledge/leaver-reviews/leaver-1:run-1/decision",
        json={"decision": "keep", "reason": "x"},
    )
    assert again.status_code == 409
    purged = m.post(
        "/v1/knowledge/leaver-reviews/leaver-1:run-1/decision",
        json={"decision": "purge", "reason": "done"},
    )
    assert purged.json()["outcome"] == "purged" and personal(world, A) == []
    # Unfrozen once closed.
    capture(world, A, "after")


def test_expire_purges_only_after_the_deadline(world, svc) -> None:
    capture(world, A, "note")
    svc.open("leaver-1:run-1")
    early = svc.post("/v1/knowledge/internal/leaver-reviews/leaver-1:run-1/expire")
    assert early.status_code == 200 and early.json()["status"] == "open"
    assert len(personal(world, A)) == 1
    with psycopg.connect(world.db.owner_url) as conn:
        conn.execute("UPDATE knowledge.leaver_reviews SET deadline = now() - interval '1 second'")
    done = svc.post("/v1/knowledge/internal/leaver-reviews/leaver-1:run-1/expire")
    assert done.json()["outcome"] == "expired" and personal(world, A) == []
    assert (
        svc.post("/v1/knowledge/internal/leaver-reviews/leaver-1:run-1/expire").json()["outcome"]
        == "expired"
    )
    assert svc.post("/v1/knowledge/internal/leaver-reviews/nope/expire").status_code == 404


def test_cancel_unfreezes(world, svc) -> None:
    capture(world, A, "note")
    svc.open("leaver-1:run-1")
    cancelled = svc.post("/v1/knowledge/internal/leaver-reviews/leaver-1:run-1/cancel")
    assert cancelled.json()["outcome"] == "cancelled"
    assert len(personal(world, A)) == 1
    capture(world, A, "back-again")
    # A later leaving opens a new review under a new run id.
    assert svc.open("leaver-1:run-2").json()["status"] == "open"


def test_nothing_to_review_closes_empty(world, svc) -> None:
    review = svc.open("leaver-1:run-1").json()
    assert review["status"] == "closed" and review["outcome"] == "empty"
    capture(world, A, "not-frozen")


def test_decider_fallback(world, svc) -> None:
    capture(world, A, "note")
    # The leaver is never their own decider: the sponsor is next.
    r1 = svc.open(
        "w:1", deciders=[{"email": A, "kind": "manager"}, {"email": S, "kind": "sponsor"}]
    ).json()
    assert (r1["deciderKind"], r1["decider"]) == ("sponsor", "dev:" + S)
    svc.post("/v1/knowledge/internal/leaver-reviews/w:1/cancel")
    # Nobody named: any privacy officer, and only officers.
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    r2 = svc.open("w:2", deciders=[]).json()
    assert r2["deciderKind"] == "privacy-officers" and "decider" not in r2
    assert world.client(DPO).get("/v1/knowledge/leaver-reviews/w:2").status_code == 200
    assert world.client(X).get("/v1/knowledge/leaver-reviews/w:2").status_code == 404


def test_service_calls_need_a_valid_signature(world, svc) -> None:
    capture(world, A, "note")
    body = {"id": "w:1", "person": {"email": A}, "deciders": []}
    path = "/v1/knowledge/internal/leaver-reviews"
    raw = json.dumps(body).encode()
    plain = TestClient(
        create_app(world.knowledge, auth.insecure_dev_headers), raise_server_exceptions=False
    )
    cases = {
        "user headers only": plain.post(
            path, json=body, headers={"X-Muistamo-Tenant": str(world.tenant), "X-Muistamo-Actor": M}
        ),
        "stale": svc.post(path, body, at=time.time() - 600),
        "wrong secret": Service(world, secret=b"mks_wrong-secret-also-test-only-000000").post(
            path, body
        ),
        "other tenant's header": Service(world, tenant=world.other_tenant).post(path, body),
        "tampered body": svc.client.post(
            path,
            content=raw.replace(
                b'"deciders": []', b'"deciders": [{"email": "x@x", "kind": "manager"}]'
            ),
            headers={
                "X-Muistamo-Tenant": str(world.tenant),
                "X-Muistamo-Signature": auth.sign(SECRET, raw),
                "Content-Type": "application/json",
            },
        ),
        "no signature": svc.post(path, body, headers={"X-Muistamo-Signature": ""}),
    }
    for name, res in cases.items():
        assert res.status_code == 401, (name, res.status_code, res.text)
    assert (
        personal(world, A)
        and not world.client(M).get("/v1/knowledge/leaver-reviews").json()["items"]
    )
    # A service signature never authenticates a user route.
    assert (
        svc.client.get(
            "/v1/knowledge/leaver-reviews",
            headers={
                "X-Muistamo-Tenant": str(world.tenant),
                "X-Muistamo-Signature": auth.sign(SECRET, b""),
            },
        ).status_code
        == 401
    )


def test_no_identity_mapping_opens_nothing(world) -> None:
    leavers = Leavers(world.knowledge, auth.no_identity_map)
    with pytest.raises(Invalid):
        leavers.open(world.tenant, {"id": "w:1", "person": {"email": A}, "deciders": []})
    with psycopg.connect(world.db.owner_url) as conn:
        assert conn.execute("SELECT count(*) FROM knowledge.leaver_reviews").fetchone()[0] == 0


def test_erasure_reaches_reviews(world, svc) -> None:
    capture(world, A, "note")
    svc.open("w:1", deciders=[{"email": M, "kind": "manager"}])
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    res = world.client(DPO).post(
        "/v1/knowledge/privacy/erasures",
        json={
            "id": str(uuid.uuid4()),
            "reason": "DSR",
            "subject": {"identities": ["dev:" + M], "email": M},
        },
    )
    assert res.status_code == 201, res.text
    assert res.json()["counts"]["leaver_reviews.decider"] == 1
    # The erased manager's review passes to the privacy officers.
    assert world.client(DPO).get("/v1/knowledge/leaver-reviews/w:1").status_code == 200


RFC3339 = r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$"


def test_timestamps_are_rfc3339_on_the_wire(world, svc) -> None:
    """The control plane parses these strictly; str(datetime) has a space and broke it."""
    import re

    capture(world, A, "note")
    review = svc.open("w:1").json()
    for field in ("deadline", "openedAt"):
        assert re.match(RFC3339, review[field]), (field, review[field])
    entry = personal(world, A)[0]
    assert re.match(RFC3339, entry["createdAt"]), entry["createdAt"]
