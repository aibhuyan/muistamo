"""Erasure and access requests (FR-309): the data map, completeness, proof and idempotency."""

from __future__ import annotations

import uuid

import psycopg
from muistamo_knowledge import evidence
from muistamo_knowledge.privacy import PERSONAL_DATA_TABLES, replace_officers, rows_mentioning

A, B, C, DPO = (
    "person-a@example.invalid",
    "reviewer-b@example.invalid",
    "person-c@example.invalid",
    "dpo@example.invalid",
)
PACK = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "KnowledgePack",
    "metadata": {"name": "basics", "owner": "dev:" + A},
    "spec": {
        "layer": "role",
        "reviewers": ["dev:" + B, "dev:" + A],
        "mergePolicy": {"requires": ["review"]},
    },
}


def subject(**extra) -> dict:
    return {"identities": ["dev:" + A], "email": A, **extra}


def capture(client, key: str, body: str) -> str:
    res = client.post(
        "/v1/knowledge/personal/entries",
        json={"key": key, "type": "fact", "title": key, "body": body},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def merge(contributor, reviewer, ids: list[str]) -> dict:
    p = contributor.post(
        "/v1/knowledge/proposals", json={"pack": "basics", "entryIds": ids, "summary": "teach"}
    )
    assert p.status_code == 201, p.text
    d = reviewer.post(
        f"/v1/knowledge/proposals/{p.json()['id']}/decision",
        json={"decision": "approve", "reason": "ok"},
    )
    assert d.status_code == 200, d.text
    return d.json()


def remaining(world, values: list[str]) -> dict[str, int]:
    """Per table, the tenant's rows still holding one of values, read as the server's role."""
    out = {}
    with world.knowledge.db.in_tenant(world.tenant) as cur:
        for table in PERSONAL_DATA_TABLES:
            if n := len(rows_mentioning(cur, table, values)):
                out[table] = n
    return out


def seed(world) -> dict:
    """Person A as pack owner and reviewer, contributor of merged entries, reviewer of C's
    entry, holder of a personal entry and a reader."""
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    a, b, c = world.client(A), world.client(B), world.client(C)
    assert a.put("/v1/knowledge/packs/basics", json=PACK).status_code == 201
    fiscal = capture(a, "fiscal-year", "Our fiscal year ends on 30 June.")
    phone = capture(a, "desk-phone", "Call Person A on +358 40 000 0000 for approvals.")
    merge(a, b, [fiscal, phone])
    merge(c, a, [capture(c, "close", "Books close on day 5.")])
    capture(a, "private-note", "Remind me about the dentist.")
    r = a.get("/v1/knowledge/retrieve", params={"q": "fiscal", "packs": "basics"})
    assert r.status_code == 200, r.text
    return {"phone": phone}


def erase(world, request_id: uuid.UUID, redact: list[str] | None = None, reason: str = "DSR-7"):
    body = {"id": str(request_id), "reason": reason, "subject": subject()}
    if redact:
        body["redactEntries"] = redact
    return world.client(DPO).post("/v1/knowledge/privacy/erasures", json=body)


def test_erasure_leaves_only_retained_evidence(world) -> None:
    ids = seed(world)
    values = ["dev:" + A, A]
    before = remaining(world, values)
    for table in (
        "entries",
        "personal_entries",
        "proposals",
        "pack_versions",
        "pack_version_entries",
        "packs",
        "reads",
        "evidence_events",
    ):
        assert before.get(table), f"seed left {table} without the person; the test proves nothing"

    request_id = uuid.uuid4()
    res = erase(world, request_id, redact=[ids["phone"]])
    assert res.status_code == 201, res.text
    proof = res.json()
    assert A not in res.text and proof["pseudonym"] == f"erased:{request_id}"
    for key in (
        "entries.redacted",
        "personal_entries",
        "reads",
        "entries.contributor",
        "proposals.contributor",
        "proposals.reviewer",
        "pack_version_entries.reviewer",
        "packs",
    ):
        assert proof["counts"][key] >= 1, key
    assert {r["data"] for r in proof["retained"]} >= {"evidence_events", "documents", "backups"}
    assert "warnings" not in proof  # B is still a reviewer

    # Nothing but the retained evidence still names the person.
    assert remaining(world, values) == {"evidence_events": before["evidence_events"]}

    # Merged knowledge still resolves, attributed to the pseudonym; the named entry and the
    # proposal copy derived from it are redacted; the private note is gone.
    resolved = {
        i["entry"]["key"]: i["entry"]
        for i in world.client(B)
        .get("/v1/knowledge/resolve", params={"packs": "basics"})
        .json()["items"]
    }
    assert resolved["fiscal-year"]["body"] == "Our fiscal year ends on 30 June."
    assert resolved["fiscal-year"]["contributor"] == f"erased:{request_id}"
    assert (
        resolved["desk-phone"]["body"] == "[erased]"
        and resolved["desk-phone"]["title"] == "[erased]"
    )
    with psycopg.connect(world.db.owner_url) as conn:
        bodies = [
            r[0]
            for r in conn.execute(
                "SELECT body FROM knowledge.entries WHERE tenant_id = %s", (world.tenant,)
            )
        ]
    assert not any("+358" in b or "dentist" in b for b in bodies), bodies

    # The proof is evidenced and the chain still verifies.
    events = world.knowledge.events(world.actor(DPO), 0, 1000)
    evidence.verify(events, {world.key.key_id: world.key.public})
    assert [e.subject_name for e in events if e.action == "privacy.erasure.completed"] == [
        str(request_id)
    ]

    # Repeating returns the stored proof and changes nothing; reusing the id for someone else is
    # a conflict.
    again = erase(world, request_id, redact=[ids["phone"]])
    assert again.status_code == 200 and again.json() == proof
    assert len(world.knowledge.events(world.actor(DPO), 0, 1000)) == len(events)
    other = world.client(DPO).post(
        "/v1/knowledge/privacy/erasures",
        json={
            "id": str(request_id),
            "reason": "x",
            "subject": {"identities": ["dev:" + C], "email": C},
        },
    )
    assert other.status_code == 409
    got = world.client(DPO).get(f"/v1/knowledge/privacy/erasures/{request_id}")
    assert got.status_code == 200 and got.json() == proof


def test_last_reviewer_erased_is_warned(world) -> None:
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    solo = {**PACK, "spec": {**PACK["spec"], "reviewers": ["dev:" + A]}}
    assert world.client(A).put("/v1/knowledge/packs/basics", json=solo).status_code == 201
    res = erase(world, uuid.uuid4())
    assert res.status_code == 201, res.text
    assert res.json()["warnings"] == [
        "pack basics has no reviewer left; assign one before its next proposal"
    ]


def test_only_officers_erase_and_never_themselves(world) -> None:
    seed(world)
    for person in (A, B):
        res = world.client(person).post(
            "/v1/knowledge/privacy/erasures",
            json={"id": str(uuid.uuid4()), "reason": "x", "subject": subject()},
        )
        assert res.status_code == 403, person
        assert (
            world.client(person).get(f"/v1/knowledge/privacy/erasures/{uuid.uuid4()}").status_code
            == 403
        )
    me = {
        "id": str(uuid.uuid4()),
        "reason": "x",
        "subject": {"identities": ["dev:" + DPO], "email": DPO},
    }
    assert world.client(DPO).post("/v1/knowledge/privacy/erasures", json=me).status_code == 403
    assert erase(world, uuid.uuid4(), reason=f"asked by {A}").status_code == 422
    assert erase(world, uuid.uuid4(), redact=[str(uuid.uuid4())]).status_code == 422
    # None of the refusals erased anything.
    assert remaining(world, ["dev:" + A, A]).get("personal_entries") == 3


def test_access_export(world) -> None:
    seed(world)
    own = world.client(A).post("/v1/knowledge/privacy/access", json={"subject": subject()})
    assert own.status_code == 200, own.text
    sections = own.json()["sections"]
    assert len(sections["personal_entries"]) == 3 and len(sections["reads"]) == 1
    assert sections["evidence_events"], "the person's evidence events belong in their export"
    # Anyone else's data needs an officer; an officer sees everything erasure would act on.
    other = world.client(B).post("/v1/knowledge/privacy/access", json={"subject": subject()})
    assert other.status_code == 403
    full = world.client(DPO).post("/v1/knowledge/privacy/access", json={"subject": subject()})
    assert full.status_code == 200
    for table, n in remaining(world, ["dev:" + A, A]).items():
        assert len(full.json()["sections"][table]) >= n, table
    # The access record carries counts, never the person.
    last = world.knowledge.events(world.actor(DPO), 0, 1000)[-1]
    assert last.action == "privacy.access.exported" and A not in str(last.after)
