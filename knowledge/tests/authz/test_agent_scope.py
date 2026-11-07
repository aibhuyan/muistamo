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


@pytest.fixture(autouse=True)
def _pack_creators(world) -> None:
    """This module's pack creators are knowledge administrators (migration 0015)."""
    world.admins(R)


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
    for target in ("legal", "rules"):  # outside, and mandatory (privacy-officer owned)
        result = ew.mcp(
            token,
            "propose_knowledge",
            {"pack": target, "key": "k2", "title": "t", "body": "b", "summary": "s"},
        )
        assert result.is_error, (target, result)
    after = person(ew).get("/v1/knowledge/personal/entries").json()["items"]
    assert after == before, "a refused proposal captured an entry"


# The console ------------------------------------------------------------------------------

CONSOLE = uuid.UUID("7d000000-0000-4000-8000-0000000c0501")


def console_token(ew) -> str:
    from muistamo_knowledge import entra

    world = ew.world
    entra.allow_assistant(world.db.owner_url, world.tenant, CONSOLE, "Muistamo console", "console")
    return ew.directory.token(PERSON, azp=str(CONSOLE))


def test_the_console_reads_packs_as_the_person_not_as_an_agent(scoped) -> None:
    """The console is the person acting as themselves: no agent scope on pack reads."""
    ew, _ = scoped
    console = ew.client(console_token(ew))
    assert console.get("/v1/knowledge/packs/legal").status_code == 200
    res = console.get("/v1/knowledge/packs")
    assert {p["document"]["metadata"]["name"] for p in res.json()["items"]} == {
        "finance",
        "legal",
        "rules",
    }
    assert "agentScope" not in res.json()


def test_a_console_token_over_mcp_is_still_agent_scoped(scoped) -> None:
    """MCP is the assistant surface: a console token presented there (copied into an assistant's
    hands) gets the agent's scope, never the console's."""
    ew, _ = scoped
    token = console_token(ew)
    before = ew.client(token).get("/v1/knowledge/personal/entries").json()["items"]
    result = ew.mcp(
        token,
        "propose_knowledge",
        {"pack": "legal", "key": "k3", "title": "t", "body": "b", "summary": "s"},
    )
    assert result.is_error, result
    after = ew.client(token).get("/v1/knowledge/personal/entries").json()["items"]
    assert after == before, "a refused proposal captured an entry"


# Unchanged ----------------------------------------------------------------------------------


def test_development_callers_are_unchanged(scoped) -> None:
    ew, _ = scoped
    res = ew.world.client(A).get("/v1/knowledge/resolve", params={"packs": "finance,legal"})
    assert res.status_code == 200 and keys(res) == {"finance-fact", "legal-fact", "rules-fact"}
    assert "agentScope" not in res.json()
    assert ew.world.client(A).get("/v1/knowledge/packs/legal").status_code == 200


def test_an_unavailable_control_plane_leaves_only_mandatory_packs(scoped) -> None:
    ew, plane = scoped
    plane.outcome = Outcome(None, "unavailable")
    res = person(ew).get("/v1/knowledge/resolve", params={"packs": "finance,finance"})
    assert keys(res) == {"rules-fact"}
    assert res.json()["agentScope"] == {
        "delegation": {"status": "unavailable", "reason": "unavailable"},
        "packsOutsideAgentScope": ["finance"],  # once, however often it was asked for
    }


def test_a_failing_control_plane_client_fails_closed(scoped) -> None:
    ew, plane = scoped

    def broken(tenant, user_token, instance=None):
        raise RuntimeError("the client broke")

    plane.request = broken
    assert person(ew).get("/v1/knowledge/packs/finance").status_code == 403
    assert keys(person(ew).get("/v1/knowledge/resolve", params={"packs": "finance"})) == {
        "rules-fact"
    }


def test_agent_scope_never_lists_the_template(scoped) -> None:
    ew, _ = scoped
    report = person(ew).get("/v1/knowledge/resolve", params={"packs": "legal"}).json()["agentScope"]
    assert set(report) == {"delegation", "packsOutsideAgentScope"}
    assert set(report["delegation"]) == {"status", "agent"}


def test_sources_outside_scope_are_hidden_and_refused_alike(scoped) -> None:
    ew, _ = scoped
    from muistamo_knowledge.connectors import InMemoryConnector

    ew.world.knowledge.connectors = {
        "test": lambda s, spec, tenant=None: InMemoryConnector(documents=[])
    }
    for name in ("finance", "legal"):
        source = {
            "apiVersion": "muistamo.dev/v1",
            "kind": "KnowledgeSource",
            "metadata": {"name": f"{name}-site"},
            "spec": {"pack": name, "connector": "test", "test": {"documents": []}},
        }
        assert (
            ew.world.client(R).put(f"/v1/knowledge/sources/{name}-site", json=source).status_code
            == 201
        )
    client = person(ew)
    listed = {
        s["document"]["metadata"]["name"]
        for s in client.get("/v1/knowledge/sources").json()["items"]
    }
    assert listed == {"finance-site"}
    assert client.get("/v1/knowledge/sources/finance-site").status_code == 200
    for name in ("legal-site", "no-such-site"):  # outside, or absent: the same answer
        assert client.get(f"/v1/knowledge/sources/{name}").status_code == 403, name


def test_the_evidence_export_is_not_for_assistants(scoped) -> None:
    ew, _ = scoped
    assert person(ew).get("/v1/knowledge/events").status_code == 403
    assert ew.world.client(DPO).get("/v1/knowledge/events").status_code == 200
    assert ew.world.client(A).get("/v1/knowledge/events").status_code == 403  # officers only
