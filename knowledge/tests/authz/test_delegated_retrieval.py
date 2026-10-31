"""Invariant 2 for Entra callers: retrieval as the person's own agent, never more (PR D).

Never skip or weaken (CLAUDE.md).
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from muistamo_knowledge.connectors import InMemoryConnector
from muistamo_knowledge.delegation import Delegation, Outcome

pytestmark = pytest.mark.authz

A = uuid.UUID("6f1c2a3b-0000-4000-8000-00000000000a")
B = uuid.UUID("6f1c2a3b-0000-4000-8000-00000000000b")
REVIEWER = "reviewer-r@example.invalid"


class ControlPlane:
    """Decides by the token's user, as the real one does; outcomes can change between calls."""

    def __init__(self, entra_world) -> None:
        self.directory = entra_world.directory
        self.outcomes: dict[uuid.UUID, Outcome] = {}
        self.tokens: dict[str, uuid.UUID] = {}

    def token(self, user: uuid.UUID) -> str:
        token = self.directory.token(user, jti=str(uuid.uuid4()))
        self.tokens[token] = user
        return token

    def request(self, tenant, user_token: str, instance=None) -> Outcome:
        return self.outcomes.get(self.tokens[user_token], Outcome(None, "user-unlinked"))


def issued(packs: list[str]) -> Outcome:
    return Outcome(
        Delegation(
            instance="agent",
            agent_identity=uuid.uuid4(),
            person="HR",
            packs=packs,
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            graph_token="obviously-fake-graph-token",  # noqa: S106 - a fake fixture
        )
    )


def setup(entra_world) -> ControlPlane:
    world = entra_world.world
    docs = {
        "finance": [
            {
                "id": "finance-doc",
                "title": "Quarterly finance",
                "body": "Quarterly.",
                "readers": [f"entra:{A}", f"entra:{B}"],
            }
        ],
        "legal": [
            {
                "id": "legal-doc",
                "title": "Quarterly legal",
                "body": "Quarterly.",
                "readers": [f"entra:{A}", f"entra:{B}"],
            }
        ],
    }
    connectors = {name: InMemoryConnector(documents=d) for name, d in docs.items()}
    world.knowledge.connectors = {"test": lambda source, spec: connectors[spec["pack"]]}
    r = world.client(REVIEWER)
    for name, d in docs.items():
        p = {
            "apiVersion": "muistamo.dev/v1",
            "kind": "KnowledgePack",
            "metadata": {"name": name},
            "spec": {
                "layer": "role",
                "reviewers": ["dev:" + REVIEWER],
                "mergePolicy": {"requires": ["review"]},
            },
        }
        assert r.put(f"/v1/knowledge/packs/{name}", json=p).status_code == 201
        s = {
            "apiVersion": "muistamo.dev/v1",
            "kind": "KnowledgeSource",
            "metadata": {"name": f"{name}-site"},
            "spec": {"pack": name, "connector": "test", "test": {"documents": d}},
        }
        assert r.put(f"/v1/knowledge/sources/{name}-site", json=s).status_code == 201
        assert r.post(f"/v1/knowledge/sources/{name}-site/sync").status_code == 200
    plane = ControlPlane(entra_world)
    world.knowledge.delegations = plane
    return plane


def found(entra_world, token: str, packs: str) -> set[str]:
    res = entra_world.client(token).get(
        "/v1/knowledge/retrieve", params={"q": "quarterly", "packs": packs, "limit": 50}
    )
    assert res.status_code == 200, res.text
    return {
        i["citation"]["externalId"]
        for i in res.json()["items"]
        if i["citation"]["type"] == "document"
    }


def test_packs_outside_the_agents_template_never_leak(entra_world) -> None:
    plane = setup(entra_world)
    plane.outcomes[A] = issued(["finance"])
    token = plane.token(A)
    assert found(entra_world, token, "finance,legal") == {"finance-doc"}
    assert found(entra_world, token, "legal") == set()
    result = entra_world.mcp(token, "search_knowledge", {"query": "quarterly", "packs": ["legal"]})
    assert result.structured_content["results"] == []


def test_one_persons_delegation_never_serves_another(entra_world) -> None:
    plane = setup(entra_world)
    plane.outcomes[A] = issued(["finance", "legal"])
    assert found(entra_world, plane.token(A), "finance,legal") == {"finance-doc", "legal-doc"}
    # B can open both documents at the source, but has no agent: nothing from A's carries over.
    assert found(entra_world, plane.token(B), "finance,legal") == set()


def test_a_suspended_or_departed_agent_gets_nothing_at_the_next_call(entra_world) -> None:
    plane = setup(entra_world)
    plane.outcomes[A] = issued(["finance"])
    token = plane.token(A)
    assert found(entra_world, token, "finance") == {"finance-doc"}
    for reason in ("no-active-agent", "user-unlinked", "identity-not-ready"):
        plane.outcomes[A] = Outcome(None, reason)
        assert found(entra_world, token, "finance") == set(), reason


def test_an_unreachable_control_plane_never_widens_access(entra_world) -> None:
    plane = setup(entra_world)

    def down(tenant, user_token, instance=None) -> Outcome:
        return Outcome(None, "unavailable")

    plane.request = down
    assert found(entra_world, plane.token(A), "finance,legal") == set()


def test_without_a_delegation_pack_knowledge_and_every_source_stay_closed(entra_world) -> None:
    """Only the caller's own layer and mandatory pack entries: no pack outside them, and no
    source at all, the mandatory pack's own included."""
    from muistamo_knowledge.privacy import replace_officers

    world = entra_world.world
    plane = setup(entra_world)
    replace_officers(world.db.owner_url, world.tenant, ["dev:dpo@example.invalid"])
    rules = {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgePack",
        "metadata": {"name": "company-rules"},
        "spec": {
            "layer": "company",
            "mandatory": True,
            "reviewers": ["dev:" + REVIEWER],
            "mergePolicy": {"requires": ["review"]},
        },
    }
    dpo = world.client("dpo@example.invalid")
    assert dpo.put("/v1/knowledge/packs/company-rules", json=rules).status_code == 201
    rules_doc = [
        {
            "id": "rules-doc",
            "title": "Quarterly rules",
            "body": "Quarterly.",
            "readers": [f"entra:{A}"],
        }
    ]
    rules_connector = InMemoryConnector(documents=rules_doc)
    previous = world.knowledge.connectors["test"]
    world.knowledge.connectors = {
        "test": lambda source, spec: (
            rules_connector if spec["pack"] == "company-rules" else previous(source, spec)
        )
    }
    r = world.client(REVIEWER)
    source = {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgeSource",
        "metadata": {"name": "rules-site"},
        "spec": {"pack": "company-rules", "connector": "test", "test": {"documents": rules_doc}},
    }
    assert r.put("/v1/knowledge/sources/rules-site", json=source).status_code == 201
    assert r.post("/v1/knowledge/sources/rules-site/sync").status_code == 200
    for pack_name, key in (("finance", "finance-entry"), ("company-rules", "rules-entry")):
        a = world.client("a@example.invalid")
        captured = a.post(
            "/v1/knowledge/personal/entries",
            json={"key": key, "type": "fact", "title": key, "body": "Quarterly."},
        ).json()
        p = a.post(
            "/v1/knowledge/proposals",
            json={"pack": pack_name, "entryIds": [captured["id"]], "summary": "s"},
        ).json()
        assert (
            r.post(
                f"/v1/knowledge/proposals/{p['id']}/decision",
                json={"decision": "approve", "reason": "ok"},
            ).status_code
            == 200
        )
    rules_connector.calls.clear()

    token = plane.token(A)
    plane.outcomes[A] = Outcome(None, "no-active-agent")
    res = entra_world.client(token).get(
        "/v1/knowledge/retrieve", params={"q": "quarterly", "packs": "finance", "limit": 50}
    )
    body = res.json()
    keys = {
        i["citation"].get("entryKey") for i in body["items"] if i["citation"]["type"] == "entry"
    }
    assert keys == {"rules-entry"}, "only the mandatory pack's entry, never finance's"
    assert not [i for i in body["items"] if i["citation"]["type"] == "document"]
    assert "rules-site" in body["coverage"]["sourcesUnavailable"]
    assert rules_connector.calls == [], "no source is asked without a delegation"
    # With a delegation, the mandatory pack's source is asked as the agent.
    plane.outcomes[A] = issued(["finance"])
    assert found(entra_world, token, "finance") == {"finance-doc", "rules-doc"}
