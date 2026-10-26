"""Mandatory company packs (FR-1708, E20.3): always in scope, never shadowed, set by compliance."""

from __future__ import annotations

import psycopg
import pytest
from muistamo_knowledge.privacy import replace_officers

A, R, DPO = "person-a@example.invalid", "reviewer-r@example.invalid", "dpo@example.invalid"


def pack(name: str, layer: str, mandatory: bool | None = None) -> dict:
    spec: dict = {
        "layer": layer,
        "reviewers": ["dev:" + R],
        "mergePolicy": {"requires": ["review"]},
    }
    if mandatory is not None:
        spec["mandatory"] = mandatory
    return {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgePack",
        "metadata": {"name": name},
        "spec": spec,
    }


def entry(key: str, body: str) -> dict:
    return {"key": key, "type": "fact", "title": key, "body": body}


def merge(world, pack_name: str, key: str, body: str) -> None:
    a = world.client(A)
    captured = a.post("/v1/knowledge/personal/entries", json=entry(key, body)).json()
    p = a.post(
        "/v1/knowledge/proposals",
        json={"pack": pack_name, "entryIds": [captured["id"]], "summary": "s"},
    ).json()
    d = world.client(R).post(
        f"/v1/knowledge/proposals/{p['id']}/decision", json={"decision": "approve", "reason": "ok"}
    )
    assert d.status_code == 200, d.text
    assert a.delete(f"/v1/knowledge/personal/entries/{captured['id']}").status_code == 204


@pytest.fixture
def mandatory(world):
    """A mandatory company pack and a team pack, both holding data-handling."""
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    dpo = world.client(DPO)
    assert (
        dpo.put(
            "/v1/knowledge/packs/company-rules", json=pack("company-rules", "company", True)
        ).status_code
        == 201
    )
    assert (
        dpo.put("/v1/knowledge/packs/team-notes", json=pack("team-notes", "team")).status_code
        == 201
    )
    merge(world, "company-rules", "data-handling", "Client data stays in the EU vault, always.")
    merge(
        world, "team-notes", "data-handling", "Team shortcut: email client files freely anywhere."
    )
    return world


def resolved(world, packs: str = "") -> dict:
    items = world.client(A).get("/v1/knowledge/resolve", params={"packs": packs}).json()["items"]
    return {i["entry"]["key"]: i for i in items}


def test_mandatory_entries_cannot_be_shadowed(mandatory) -> None:
    world = mandatory
    a = world.client(A)
    # Without a personal entry: the mandatory company entry beats the team pack's.
    got = resolved(world, "team-notes")["data-handling"]
    assert got["layer"] == "company" and got["mandatory"] is True
    assert got["overrides"] == [{"layer": "team", "pack": "team-notes"}]

    # The person writes their own entry for the same key: it still does not win.
    assert (
        a.post(
            "/v1/knowledge/personal/entries", json=entry("data-handling", "Mine: whatever works.")
        ).status_code
        == 201
    )
    got = resolved(world, "team-notes")["data-handling"]
    assert got["entry"]["body"] == "Client data stays in the EU vault, always."
    assert got["overrides"] == [{"layer": "personal"}, {"layer": "team", "pack": "team-notes"}]

    # Retrieval and the MCP tool see only the entry in force.
    r = a.get(
        "/v1/knowledge/retrieve", params={"q": "freely anywhere whatever", "packs": "team-notes"}
    ).json()
    assert r["items"] == [], r
    r = a.get("/v1/knowledge/retrieve", params={"q": "vault", "packs": "team-notes"}).json()
    assert [i["citation"]["layer"] for i in r["items"]] == ["company"]
    mcp = world.mcp(A, "search_knowledge", {"query": "freely whatever", "packs": ["team-notes"]})
    assert not mcp.is_error and mcp.structured_content["results"] == []
    mcp = world.mcp(A, "search_knowledge", {"query": "vault", "packs": ["team-notes"]})
    assert [h["citation"]["layer"] for h in mcp.structured_content["results"]] == ["company"]


def test_mandatory_packs_are_in_scope_unasked(mandatory) -> None:
    # Named nothing, or another pack only: the mandatory pack is there anyway.
    assert resolved(mandatory)["data-handling"]["pack"] == "company-rules"
    assert resolved(mandatory, "team-notes")["data-handling"]["pack"] == "company-rules"


def test_normal_precedence_is_unchanged_without_mandatory(world) -> None:
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    world.client(A).put("/v1/knowledge/packs/company-plain", json=pack("company-plain", "company"))
    world.client(A).put("/v1/knowledge/packs/team-notes", json=pack("team-notes", "team"))
    merge(world, "company-plain", "k", "company says")
    merge(world, "team-notes", "k", "team says")
    got = resolved(world, "company-plain,team-notes")["k"]
    assert got["layer"] == "team" and "mandatory" not in got and "overrides" not in got


def test_only_privacy_officers_change_the_flag(world) -> None:
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    a, dpo = world.client(A), world.client(DPO)
    # Creating as mandatory, setting and clearing all need an officer.
    assert (
        a.put("/v1/knowledge/packs/rules", json=pack("rules", "company", True)).status_code == 403
    )
    assert a.put("/v1/knowledge/packs/rules", json=pack("rules", "company")).status_code == 201
    assert (
        a.put("/v1/knowledge/packs/rules", json=pack("rules", "company", True)).status_code == 403
    )
    assert (
        dpo.put("/v1/knowledge/packs/rules", json=pack("rules", "company", True)).status_code == 200
    )
    assert (
        a.put("/v1/knowledge/packs/rules", json=pack("rules", "company", False)).status_code == 403
    )
    # Any other change to a mandatory pack is the officers' too: otherwise anyone could make
    # themselves its reviewer and roll it back to empty.
    other = pack("rules", "company", True)
    other["metadata"]["owner"] = "team-compliance"
    assert a.put("/v1/knowledge/packs/rules", json=other).status_code == 403
    assert dpo.put("/v1/knowledge/packs/rules", json=other).status_code == 200
    assert (
        dpo.put("/v1/knowledge/packs/rules", json=pack("rules", "company", False)).status_code
        == 200
    )
    changes = [
        e
        for e in world.knowledge.events(world.actor(DPO), 0, 1000)
        if e.action == "knowledge.pack.mandatory.changed"
    ]
    assert [(e.before, e.after) for e in changes] == [
        ({"mandatory": False}, {"mandatory": True}),
        ({"mandatory": True}, {"mandatory": False}),
    ]
    assert all(e.actor == "dev:" + DPO for e in changes)


def test_only_company_packs_can_be_mandatory(world) -> None:
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    dpo = world.client(DPO)
    assert dpo.put("/v1/knowledge/packs/t", json=pack("t", "team", True)).status_code == 422
    assert dpo.put("/v1/knowledge/packs/c", json=pack("c", "company", True)).status_code == 201
    # A mandatory pack cannot move to another layer either.
    assert dpo.put("/v1/knowledge/packs/c", json=pack("c", "role", True)).status_code == 422
    # And the database refuses it whatever the service does.
    with psycopg.connect(world.db.owner_url) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("UPDATE knowledge.packs SET layer = 'team' WHERE name = 'c'")


def test_a_mandatory_pack_cannot_be_emptied_by_taking_it_over(mandatory) -> None:
    world = mandatory
    a = world.client(A)
    takeover = pack("company-rules", "company", True)
    takeover["spec"]["reviewers"] = ["dev:" + A]
    r = a.put("/v1/knowledge/packs/company-rules", json=takeover)
    assert r.status_code == 403, r.text
    # So A is not a reviewer and cannot roll it back to the empty pack.
    r = a.post(
        "/v1/knowledge/packs/company-rules/rollback",
        json={"toVersion": "0.0.0", "reason": "gone"},
    )
    assert r.status_code == 403, r.text
    got = resolved(world)["data-handling"]
    assert got["entry"]["body"] == "Client data stays in the EU vault, always."
    # Nothing was recorded as applied by A.
    applied = [
        e
        for e in world.knowledge.events(world.actor(DPO), 0, 1000)
        if e.action == "knowledge.pack.applied" and e.actor == "dev:" + A
    ]
    assert applied == []


def test_two_mandatory_packs_with_one_key_resolve_by_pack_name(world) -> None:
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    dpo = world.client(DPO)
    for name in ("b-rules", "a-rules"):
        assert (
            dpo.put(f"/v1/knowledge/packs/{name}", json=pack(name, "company", True)).status_code
            == 201
        )
    merge(world, "b-rules", "k", "b says")
    merge(world, "a-rules", "k", "a says")
    got = resolved(world)["k"]
    assert got["pack"] == "a-rules" and got["entry"]["body"] == "a says"
    assert got["overrides"] == [{"layer": "company", "pack": "b-rules"}]
