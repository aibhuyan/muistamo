"""Invariant 1: retrieval never returns a document the acting person cannot open.

Runs against every registered connector. Today that is only the in-memory test connector, so a
green run proves the retrieval layer, not SharePoint. The real SharePoint connector must be added
to CONNECTORS and pass this same suite against a test tenant before release.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from muistamo_knowledge import retrieval
from muistamo_knowledge.connectors import InMemoryConnector

pytestmark = pytest.mark.authz

A, B, R = "person-a@example.invalid", "person-b@example.invalid", "reviewer-r@example.invalid"
PACK = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "KnowledgePack",
    "metadata": {"name": "equity-research-basics"},
    "spec": {"layer": "role", "reviewers": ["dev:" + R], "mergePolicy": {"requires": ["review"]}},
}
# Every document matches the query; only the readers differ.
DOCUMENTS = [
    {
        "id": "doc-allowed",
        "title": "Quarterly report Q1",
        "body": "Quarterly revenue grew.",
        "url": "https://example.invalid/allowed",
        "readers": ["dev:" + A],
    },
    {
        "id": "doc-secret",
        "title": "Quarterly board memo",
        "body": "Quarterly plans, restricted.",
        "readers": [],
    },
    {
        "id": "doc-other",
        "title": "Quarterly notes of B",
        "body": "Quarterly thoughts by B.",
        "readers": ["dev:" + B],
    },
]


@dataclass
class Harness:
    """What the suite needs from a connector: control over its source-side permissions."""

    connector: InMemoryConnector

    def revoke(self, person: str, doc_id: str) -> None:
        for d in self.connector.documents:
            if d["id"] == doc_id:
                d["readers"] = [r for r in d["readers"] if r != "dev:" + person]

    def outage(self, on: bool) -> None:
        self.connector.unavailable = on

    def people_asked(self) -> set[str]:
        return {person for person, _ in self.connector.calls}


def in_memory(world) -> Harness:
    instance = InMemoryConnector(documents=[dict(d, readers=list(d["readers"])) for d in DOCUMENTS])
    world.knowledge.connectors = {"test": lambda source, spec: instance}
    return Harness(instance)


# Every connector the product ships must be listed here and pass the whole suite.
CONNECTORS: dict[str, Callable] = {"test": in_memory}


def setup_source(world, connector: str, tenant=None) -> Harness:
    harness = CONNECTORS[connector](world)
    r = world.client(R, tenant=tenant)
    assert r.put("/v1/knowledge/packs/equity-research-basics", json=PACK).status_code in (200, 201)
    source = {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgeSource",
        "metadata": {"name": "finance-site"},
        "spec": {
            "pack": "equity-research-basics",
            "connector": connector,
            "test": {"documents": DOCUMENTS},
        },
    }
    res = r.put("/v1/knowledge/sources/finance-site", json=source)
    assert res.status_code in (200, 201), res.text
    assert r.post("/v1/knowledge/sources/finance-site/sync").status_code == 200
    harness.connector.calls.clear()
    return harness


def documents_for(world, person: str, tenant=None) -> tuple[set[str], dict]:
    res = world.client(person, tenant=tenant).get(
        "/v1/knowledge/retrieve",
        params={"q": "quarterly", "packs": "equity-research-basics", "limit": 50},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    ids = {
        i["citation"]["externalId"] for i in body["items"] if i["citation"]["type"] == "document"
    }
    return ids, body


def test_every_shipped_connector_is_under_test() -> None:
    assert CONNECTORS, (
        "no connector is registered with the adversarial suite; it would prove nothing"
    )


@pytest.fixture(params=sorted(CONNECTORS))
def connector(request) -> str:
    return request.param


def test_retrieval_never_returns_a_document_the_person_cannot_open(world, connector) -> None:
    setup_source(world, connector)
    ids, body = documents_for(world, A)
    assert ids == {"doc-allowed"}, f"A got {ids}"
    cited = next(i for i in body["items"] if i["citation"].get("externalId") == "doc-allowed")
    assert (
        cited["citation"]["url"] == "https://example.invalid/allowed"
        and cited["citation"]["source"] == "finance-site"
    )
    assert body["coverage"]["sourcesQueried"] == ["finance-site"]
    assert body["coverage"]["testConnectors"] == [
        "finance-site"
    ]  # never presented as a real system


def test_revocation_takes_effect_at_the_next_call(world, connector) -> None:
    harness = setup_source(world, connector)
    assert documents_for(world, A)[0] == {"doc-allowed"}
    harness.revoke(A, "doc-allowed")  # at the source; the index is not touched
    assert documents_for(world, A)[0] == set()


def test_source_outage_withholds_its_documents(world, connector) -> None:
    harness = setup_source(world, connector)
    harness.outage(True)
    ids, body = documents_for(world, A)
    assert ids == set()
    assert body["coverage"]["sourcesUnavailable"] == ["finance-site"]


def test_slow_source_is_withheld_not_waited_for(world, connector, monkeypatch) -> None:
    harness = setup_source(world, connector)
    monkeypatch.setattr(retrieval, "AUTHORISE_TIMEOUT_SECONDS", 0.2)
    original = harness.connector.authorise

    def slow(person, ids):
        time.sleep(1.0)
        return original(person, ids)

    harness.connector.authorise = slow
    ids, body = documents_for(world, A)
    assert ids == set() and body["coverage"]["sourcesUnavailable"] == ["finance-site"]


def test_connector_is_asked_as_the_acting_person(world, connector) -> None:
    harness = setup_source(world, connector)
    documents_for(world, A)
    documents_for(world, B)
    assert harness.people_asked() == {"dev:" + A, "dev:" + B}, (
        "authorisation must run as the person, never a service identity"
    )
    assert documents_for(world, B)[0] == {"doc-other"}


def test_documents_never_cross_tenants(world, connector) -> None:
    setup_source(world, connector)
    # The same person name in another tenant with no source sees nothing.
    other = world.client(A, tenant=world.other_tenant)
    assert other.put("/v1/knowledge/packs/equity-research-basics", json=PACK).status_code == 201
    res = other.get(
        "/v1/knowledge/retrieve", params={"q": "quarterly", "packs": "equity-research-basics"}
    )
    assert (
        res.status_code == 200
        and res.json()["items"] == []
        and res.json()["coverage"]["sourcesQueried"] == []
    )


def test_other_peoples_personal_entries_never_appear(world, connector) -> None:
    setup_source(world, connector)
    b = world.client(B)
    res = b.post(
        "/v1/knowledge/personal/entries",
        json={
            "key": "b-note",
            "type": "fact",
            "title": "Quarterly hunch",
            "body": "Quarterly numbers look odd.",
        },
    )
    assert res.status_code == 201
    _, body = documents_for(world, A)
    assert all(i["citation"].get("entryKey") != "b-note" for i in body["items"])
    _, mine = documents_for(world, B)
    assert any(i["citation"].get("entryKey") == "b-note" for i in mine["items"])
