"""The knowledge core end to end over HTTP: capture, propose, review, merge, roll back, resolve."""

import psycopg
from muistamo_knowledge import evidence

PACK = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "KnowledgePack",
    "metadata": {"name": "equity-research-basics"},
    "spec": {
        "layer": "role",
        "reviewers": ["dev:reviewer-b@example.invalid"],
        "mergePolicy": {"requires": ["review"]},
    },
}
A, B = "person-a@example.invalid", "reviewer-b@example.invalid"


def entry(key: str, body: str = "Our fiscal year ends on 30 June.", **extra) -> dict:
    return {"key": key, "type": "fact", "title": key.replace("-", " "), "body": body, **extra}


def capture(client, key: str, body: str = "Our fiscal year ends on 30 June.") -> str:
    res = client.post("/v1/knowledge/personal/entries", json=entry(key, body))
    assert res.status_code == 201, res.text
    return res.json()["id"]


def propose(client, ids: list[str], pack: str = "equity-research-basics") -> dict:
    res = client.post(
        "/v1/knowledge/proposals", json={"pack": pack, "entryIds": ids, "summary": "teach the team"}
    )
    assert res.status_code == 201, res.text
    return res.json()


def test_capture_propose_review_merge_rollback(world) -> None:
    a, b = world.client(A), world.client(B)
    created = a.put("/v1/knowledge/packs/equity-research-basics", json=PACK)
    assert created.status_code == 201 and created.json()["latestVersion"] == "0.0.0"
    assert a.put("/v1/knowledge/packs/equity-research-basics", json=PACK).status_code == 200

    fiscal = capture(a, "fiscal-year")
    first = propose(a, [fiscal])
    assert first["status"] == "in-review" and first["checks"] == []

    # The contributor cannot approve, even if listed as a reviewer elsewhere.
    assert (
        a.post(
            f"/v1/knowledge/proposals/{first['id']}/decision",
            json={"decision": "approve", "reason": "mine"},
        ).status_code
        == 403
    )
    inbox = b.get("/v1/knowledge/proposals", params={"role": "reviewer"}).json()["items"]
    assert [p["id"] for p in inbox] == [first["id"]]

    approved = b.post(
        f"/v1/knowledge/proposals/{first['id']}/decision",
        json={
            "decision": "approve",
            "reason": "correct",
            "edits": [
                {
                    "key": "fiscal-year",
                    "body": "Our fiscal year ends on 30 June (FY = July to June).",
                }
            ],
        },
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved" and approved.json()["mergedVersion"] == "0.1.0"

    v1 = b.get("/v1/knowledge/packs/equity-research-basics/versions/0.1.0").json()
    assert [e["entry"]["body"] for e in v1["entries"]] == [
        "Our fiscal year ends on 30 June (FY = July to June)."
    ]
    lineage = v1["entries"][0]
    assert lineage["proposal"] == first["id"] and lineage["reviewer"] == "dev:" + B
    assert lineage["entry"]["contributor"] == "dev:" + A

    second = propose(
        a,
        [
            capture(
                a,
                "report-deadline",
                "Quarterly reports are due ten working days after quarter end.",
            )
        ],
    )
    assert (
        b.post(
            f"/v1/knowledge/proposals/{second['id']}/decision",
            json={"decision": "approve", "reason": "ok"},
        ).json()["mergedVersion"]
        == "0.2.0"
    )
    v2 = b.get("/v1/knowledge/packs/equity-research-basics/versions/0.2.0").json()
    assert sorted(e["entry"]["key"] for e in v2["entries"]) == ["fiscal-year", "report-deadline"]

    # Rollback never rewrites history: it publishes a new version with the old content.
    assert (
        a.post(
            "/v1/knowledge/packs/equity-research-basics/rollback",
            json={"toVersion": "0.1.0", "reason": "x"},
        ).status_code
        == 403
    )
    rolled = b.post(
        "/v1/knowledge/packs/equity-research-basics/rollback",
        json={"toVersion": "0.1.0", "reason": "deadline was wrong"},
    )
    assert rolled.status_code == 201 and rolled.json()["version"] == "0.3.0"
    assert [e["entry"]["key"] for e in rolled.json()["entries"]] == ["fiscal-year"]
    assert b.get("/v1/knowledge/packs/equity-research-basics/versions/0.2.0").status_code == 200
    versions = [
        v["version"]
        for v in b.get("/v1/knowledge/packs/equity-research-basics/versions").json()["items"]
    ]
    assert versions[0] == "0.3.0" and set(versions) == {"0.1.0", "0.2.0", "0.3.0"}

    # Every write is in the chain, and the chain verifies.
    events = world.knowledge.events(world.actor(A), 0, 1000)
    evidence.verify(events, {world.key.key_id: world.key.public})
    actions = [e.action for e in events]
    for want in (
        "knowledge.pack.applied",
        "knowledge.entry.captured",
        "knowledge.proposal.created",
        "knowledge.proposal.approved",
        "knowledge.pack.version.published",
    ):
        assert want in actions
    assert actions.count("knowledge.pack.applied") == 1  # the identical re-apply wrote nothing


def test_personal_layer_wins_and_is_immediately_visible(world) -> None:
    a, b = world.client(A), world.client(B)
    a.put("/v1/knowledge/packs/equity-research-basics", json=PACK)
    company = dict(
        PACK,
        metadata={"name": "company-basics"},
        spec={**PACK["spec"], "layer": "company", "mandatory": True},
    )
    a.put("/v1/knowledge/packs/company-basics", json=company)
    for pack, body in (
        ("company-basics", "Company says 31 December."),
        ("equity-research-basics", "Role says 30 June."),
    ):
        p = propose(a, [capture(a, "fiscal-year", body)], pack)
        b.post(
            f"/v1/knowledge/proposals/{p['id']}/decision",
            json={"decision": "approve", "reason": "ok"},
        )
    # Captured entries used for proposals stay personal; clear them to test layering cleanly.
    for e in a.get("/v1/knowledge/personal/entries").json()["items"]:
        assert a.delete(f"/v1/knowledge/personal/entries/{e['id']}").status_code == 204

    resolved = {
        i["entry"]["key"]: i
        for i in a.get("/v1/knowledge/resolve", params={"packs": "equity-research-basics"}).json()[
            "items"
        ]
    }
    assert (
        resolved["fiscal-year"]["layer"] == "role" and resolved["fiscal-year"]["version"] == "0.1.0"
    )
    # Mandatory packs are included even when not asked for.
    only_company = a.get("/v1/knowledge/resolve").json()["items"]
    assert [(i["layer"], i["entry"]["body"]) for i in only_company] == [
        ("company", "Company says 31 December.")
    ]

    capture(a, "fiscal-year", "For me: 30 June, and remind me in May.")
    mine = {
        i["entry"]["key"]: i
        for i in a.get("/v1/knowledge/resolve", params={"packs": "equity-research-basics"}).json()[
            "items"
        ]
    }
    assert mine["fiscal-year"]["layer"] == "personal"
    theirs = {
        i["entry"]["key"]: i
        for i in b.get("/v1/knowledge/resolve", params={"packs": "equity-research-basics"}).json()[
            "items"
        ]
    }
    assert theirs["fiscal-year"]["layer"] == "role"


def test_blocked_checks_and_evaluation_gate(world) -> None:
    a, b = world.client(A), world.client(B)
    a.put("/v1/knowledge/packs/equity-research-basics", json=PACK)
    bad = propose(
        a, [capture(a, "contact", "Ask person-c@example.invalid for the password = hunter2-longer")]
    )
    assert bad["status"] == "checks-failed"
    assert {c["ruleId"] for c in bad["checks"]} >= {"pii.email", "secret.assignment"}
    assert "hunter2" not in str(bad["checks"])
    assert (
        b.post(
            f"/v1/knowledge/proposals/{bad['id']}/decision",
            json={"decision": "approve", "reason": "x"},
        ).status_code
        == 409
    )

    gated = dict(
        PACK,
        metadata={"name": "skills"},
        spec={**PACK["spec"], "mergePolicy": {"requires": ["review", "evaluation"]}},
    )
    a.put("/v1/knowledge/packs/skills", json=gated)
    p = propose(a, [capture(a, "dcf-skill")], "skills")
    res = b.post(
        f"/v1/knowledge/proposals/{p['id']}/decision", json={"decision": "approve", "reason": "x"}
    )
    assert res.status_code == 409 and "evaluation" in res.json()["detail"]
    assert b.get("/v1/knowledge/packs/skills").json()["latestVersion"] == "0.0.0"


def test_delete_removes_the_entry_and_leaves_evidence(world) -> None:
    a = world.client(A)
    entry_id = capture(a, "temp-note", "Something I no longer want stored.")
    assert a.delete(f"/v1/knowledge/personal/entries/{entry_id}").status_code == 204
    assert a.get("/v1/knowledge/personal/entries").json()["items"] == []
    with psycopg.connect(world.db.owner_url) as conn:
        assert (
            conn.execute(
                "SELECT count(*) FROM knowledge.entries WHERE id = %s", (entry_id,)
            ).fetchone()[0]
            == 0
        )
        assert (
            conn.execute(
                "SELECT count(*) FROM knowledge.evidence_events WHERE action = 'knowledge.entry.deleted'"
            ).fetchone()[0]
            == 1
        )
        # Evidence never holds the content it would then fail to delete (invariant 5).
        assert (
            conn.execute(
                "SELECT count(*) FROM knowledge.evidence_events WHERE after::text LIKE '%no longer want%'"
            ).fetchone()[0]
            == 0
        )


def test_contract_violations_and_unknown_callers(world) -> None:
    a = world.client(A)
    assert (
        a.post("/v1/knowledge/personal/entries", json={**entry("x"), "surprise": 1}).status_code
        == 422
    )
    assert a.post("/v1/knowledge/personal/entries", json=entry("Bad Key")).status_code == 422
    stranger = world.client(A, tenant=__import__("uuid").uuid4())
    assert stranger.get("/v1/knowledge/personal/entries").status_code == 401
    anonymous = world.client(A)
    anonymous.headers.pop("X-Muistamo-Actor")
    assert anonymous.get("/v1/knowledge/personal/entries").status_code == 401
