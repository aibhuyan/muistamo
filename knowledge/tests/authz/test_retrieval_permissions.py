"""Invariant 1: retrieval never returns a document the acting person cannot open.

Runs against every registered connector: the in-memory test connector, and the real SharePoint
connector against a strict fake of Microsoft Graph (indexed with its indexer app, authorised per
person with the token delegated to them). A green run proves the connector's logic, not a real
tenant; live acceptance against one is a separate, recorded step.
"""

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from muistamo_knowledge import retrieval, sharepoint
from muistamo_knowledge.connectors import InMemoryConnector, Principal

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

    def external_id(self, doc_id: str) -> str:
        return doc_id

    def url(self, doc_id: str) -> str | None:
        return next(d.get("url") for d in DOCUMENTS if d["id"] == doc_id)

    is_test = True
    spec: dict | None = None


def in_memory(world) -> Harness:
    instance = InMemoryConnector(documents=[dict(d, readers=list(d["readers"])) for d in DOCUMENTS])
    world.knowledge.connectors = {"test": lambda source, spec, tenant=None: instance}
    return Harness(instance)


class Delegated:
    """The real SharePoint connector, asked with the token the control plane would delegate to
    the acting person (the delegation itself is tested in test_delegated_retrieval.py)."""

    def __init__(self, inner: sharepoint.SharePointConnector) -> None:
        self.inner, self.calls = inner, []
        self.name, self.is_test = inner.name, inner.is_test

    def list_documents(self):
        return self.inner.list_documents()

    def authorise(self, principal: Principal, ids: list[str]) -> set[str]:
        self.calls.append((principal.person, tuple(ids)))
        return self.inner.authorise(
            Principal(principal.person, "delegated:" + principal.person), ids
        )


@dataclass
class SharePointHarness:
    graph: object
    connector: Delegated
    is_test = False

    def revoke(self, person: str, doc_id: str) -> None:
        for d in self.graph.documents:
            if d["id"] == doc_id:
                d["readers"] = [r for r in d["readers"] if r != "dev:" + person]

    def outage(self, on: bool) -> None:
        self.graph.unavailable = on

    def people_asked(self) -> set[str]:
        return set(self.graph.tokens_asked)

    def external_id(self, doc_id: str) -> str:
        return self.graph.external_id(doc_id)

    def url(self, doc_id: str) -> str | None:
        return self.graph.web_url(doc_id)

    spec = {"siteUrl": "https://contoso.sharepoint.com/sites/finance", "libraries": ["Documents"]}


def sharepoint_connector(world) -> SharePointHarness:
    directory, client = uuid.uuid4(), uuid.uuid4()
    graph = world.fake_graph(
        [dict(d, readers=list(d["readers"])) for d in DOCUMENTS], directory, client
    )
    indexer = sharepoint.Indexer(directory, client, "obviously-fake-indexer-secret")
    build = sharepoint.factory_for(
        lambda tenant: indexer if tenant == world.tenant else None, graph
    )
    instances: dict = {}

    def factory(source, spec, tenant=None):
        if tenant not in instances:
            instances[tenant] = Delegated(build(source, spec, tenant))
        return instances[tenant]

    world.knowledge.connectors = {"sharepoint": factory}
    harness = SharePointHarness(graph, None)
    harness.connector = factory(None, {"sharepoint": SharePointHarness.spec}, world.tenant)
    return harness


# Every connector the product ships must be listed here and pass the whole suite.
CONNECTORS: dict[str, Callable] = {"test": in_memory, "sharepoint": sharepoint_connector}


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
        },
    }
    if harness.spec is None:
        source["spec"]["test"] = {"documents": DOCUMENTS}
    else:
        source["spec"]["sharepoint"] = harness.spec
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
    harness = setup_source(world, connector)
    allowed = harness.external_id("doc-allowed")
    ids, body = documents_for(world, A)
    assert ids == {allowed}, f"A got {ids}"
    cited = next(i for i in body["items"] if i["citation"].get("externalId") == allowed)
    assert (
        cited["citation"]["url"] == harness.url("doc-allowed")
        and cited["citation"]["source"] == "finance-site"
    )
    assert body["coverage"]["sourcesQueried"] == ["finance-site"]
    # The test connector is never presented as a real system, and a real one never as a test.
    assert body["coverage"]["testConnectors"] == (["finance-site"] if harness.is_test else [])


def test_revocation_takes_effect_at_the_next_call(world, connector) -> None:
    harness = setup_source(world, connector)
    assert documents_for(world, A)[0] == {harness.external_id("doc-allowed")}
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
    assert documents_for(world, B)[0] == {harness.external_id("doc-other")}


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
