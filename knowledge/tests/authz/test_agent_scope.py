"""Adversarial suite: an Entra caller is the person's own agent on every knowledge read (D60,
docs/d60-agent-scope-plan.md). Invariant 2: an agent never sees more than the person it acts for,
and never more than its template allows, on any surface an assistant reaches. Never skip or
weaken.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from muistamo_knowledge.delegation import Delegation, Outcome
from muistamo_knowledge.privacy import replace_officers

pytestmark = pytest.mark.authz

PERSON = uuid.UUID("7d000000-0000-4000-8000-00000000000a")
A, R, DPO = "author-a@example.invalid", "reviewer-r@example.invalid", "dpo@example.invalid"
OUTSIDE = "this assistant's agent scope"


def pack(name: str, layer: str = "role", mandatory: bool | None = None) -> dict:
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


class ControlPlane:
    """The delegation the control plane gives each request; it can change between calls."""

    def __init__(self) -> None:
        self.outcome = issued(["finance"])
        self.calls = 0

    def request(self, tenant, user_token: str, instance=None) -> Outcome:
        self.calls += 1
        return self.outcome


def issued(packs: list[str]) -> Outcome:
    return Outcome(
        Delegation(
            instance="analyst-e-1",
            agent_identity=uuid.uuid4(),
            person="HR",
            packs=packs,
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            graph_token="obviously-fake-graph-token",  # noqa: S106 - a fake fixture
        )
    )


@pytest.fixture
def scoped(entra_world):
    """Three packs with one merged entry each: finance (the agent's template), legal (outside
    it, though the person's own pack rights would read it), and rules (mandatory)."""
    world = entra_world.world
    replace_officers(world.db.owner_url, world.tenant, ["dev:" + DPO])
    assert (
        world.client(R).put("/v1/knowledge/packs/finance", json=pack("finance")).status_code == 201
    )
    assert world.client(R).put("/v1/knowledge/packs/legal", json=pack("legal")).status_code == 201
    dpo = world.client(DPO)
    assert (
        dpo.put("/v1/knowledge/packs/rules", json=pack("rules", "company", True)).status_code == 201
    )
    author = world.client(A)
    for name in ("finance", "legal", "rules"):
        entry = {"key": f"{name}-fact", "type": "fact", "title": name, "body": f"{name} body"}
        captured = author.post("/v1/knowledge/personal/entries", json=entry).json()
        proposal = author.post(
            "/v1/knowledge/proposals",
            json={"pack": name, "entryIds": [captured["id"]], "summary": "s"},
        ).json()
        decided = world.client(R).post(
            f"/v1/knowledge/proposals/{proposal['id']}/decision",
            json={"decision": "approve", "reason": "ok"},
        )
        assert decided.status_code == 200, decided.text
    plane = ControlPlane()
    world.knowledge.delegations = plane
    return entra_world, plane


def person(ew):
    return ew.client(ew.directory.token(PERSON))


def keys(res) -> set[str]:
    return {i["entry"]["key"] for i in res.json()["items"]}


# Resolve and the pack list --------------------------------------------------------------------


def test_resolve_serves_only_the_template_and_mandatory_packs(scoped) -> None:
    ew, _ = scoped
    res = person(ew).get("/v1/knowledge/resolve", params={"packs": "finance,legal"})
    assert res.status_code == 200, res.text
    assert keys(res) == {"finance-fact", "rules-fact"}
    assert res.json()["agentScope"] == {
        "delegation": {"status": "issued", "agent": "analyst-e-1"},
        "packsOutsideAgentScope": ["legal"],
    }


def test_the_pack_list_shows_only_the_agents_packs(scoped) -> None:
    ew, _ = scoped
    res = person(ew).get("/v1/knowledge/packs")
    assert res.status_code == 200, res.text
    names = {p["document"]["metadata"]["name"] for p in res.json()["items"]}
    assert names == {"finance", "rules"}
    assert res.json()["agentScope"]["delegation"]["status"] == "issued"


def test_without_a_delegation_only_mandatory_packs_remain(scoped) -> None:
    ew, plane = scoped
    plane.outcome = Outcome(None, "no-active-agent")  # a leaver
    res = person(ew).get("/v1/knowledge/resolve", params={"packs": "finance"})
    assert res.status_code == 200 and keys(res) == {"rules-fact"}
    assert res.json()["agentScope"] == {
        "delegation": {"status": "refused", "reason": "no-active-agent"},
        "packsOutsideAgentScope": ["finance"],
    }
    names = {
        p["document"]["metadata"]["name"]
        for p in person(ew).get("/v1/knowledge/packs").json()["items"]
    }
    assert names == {"rules"}
    assert person(ew).get("/v1/knowledge/packs/finance").status_code == 403


# One pack, its versions, its skills export ----------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/v1/knowledge/packs/{p}",
        "/v1/knowledge/packs/{p}/versions",
        "/v1/knowledge/packs/{p}/versions/0.1.0",
        "/v1/knowledge/packs/{p}/versions/0.1.0/skills.zip",
    ],
)
def test_a_pack_outside_the_template_is_refused_on_every_read(scoped, path) -> None:
    ew, _ = scoped
    client = person(ew)
    outside = client.get(path.format(p="legal"))
    assert outside.status_code == 403, (path, outside.status_code, outside.text)
    assert OUTSIDE in outside.json()["detail"]
    for allowed in ("finance", "rules"):
        res = client.get(path.format(p=allowed))
        assert res.status_code == 200, (path, allowed, res.status_code, res.text)


def test_a_pack_that_does_not_exist_is_refused_the_same_way(scoped) -> None:
    """Outside scope says nothing about existence: an unknown pack gets the same answer."""
    ew, _ = scoped
    res = person(ew).get("/v1/knowledge/packs/no-such-pack")
    assert res.status_code == 403 and OUTSIDE in res.json()["detail"]


def test_each_read_asks_for_the_delegation_at_that_moment(scoped) -> None:
    """Use-time authorisation (invariant 1): the scope changes as the control plane's answer does."""
    ew, plane = scoped
    client = person(ew)
    assert client.get("/v1/knowledge/packs/finance").status_code == 200
    plane.outcome = issued(["legal"])  # the agent's template changed
    assert client.get("/v1/knowledge/packs/finance").status_code == 403
    assert client.get("/v1/knowledge/packs/legal").status_code == 200
    assert plane.calls >= 3


# Proposals ----------------------------------------------------------------------------------


def test_proposing_outside_the_template_is_refused_and_captures_nothing(scoped) -> None:
    ew, _ = scoped
    client = person(ew)
    entry = {"key": "k", "type": "fact", "title": "t", "body": "b"}
    captured = client.post("/v1/knowledge/personal/entries", json=entry).json()
    for target in ("legal", "rules"):  # outside, and mandatory (privacy-officer owned)
        res = client.post(
            "/v1/knowledge/proposals",
            json={"pack": target, "entryIds": [captured["id"]], "summary": "s"},
        )
        assert res.status_code == 403, (target, res.text)
    ok = client.post(
        "/v1/knowledge/proposals",
        json={"pack": "finance", "entryIds": [captured["id"]], "summary": "s"},
    )
    assert ok.status_code == 201, ok.text


def test_mcp_propose_knowledge_outside_the_template_captures_nothing(scoped) -> None:
    ew, _ = scoped
    token = ew.directory.token(PERSON)
    before = person(ew).get("/v1/knowledge/personal/entries").json()["items"]
    result = ew.mcp(
        token,
        "propose_knowledge",
        {"pack": "legal", "key": "k2", "title": "t", "body": "b", "summary": "s"},
    )
    assert result.is_error, result
    after = person(ew).get("/v1/knowledge/personal/entries").json()["items"]
    assert after == before, "a refused proposal captured an entry"


# Unchanged ----------------------------------------------------------------------------------


def test_development_callers_are_unchanged(scoped) -> None:
    ew, _ = scoped
    res = ew.world.client(A).get("/v1/knowledge/resolve", params={"packs": "finance,legal"})
    assert res.status_code == 200 and keys(res) == {"finance-fact", "legal-fact", "rules-fact"}
    assert "agentScope" not in res.json()
    assert ew.world.client(A).get("/v1/knowledge/packs/legal").status_code == 200
