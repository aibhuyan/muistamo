"""Sources, sync and retrieval behaviour (the adversarial cases live in tests/authz)."""

import psycopg
from muistamo_knowledge import evidence
from muistamo_knowledge.connectors import InMemoryConnector, default_factories

A, R = "person-a@example.invalid", "reviewer-r@example.invalid"
PACK = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "KnowledgePack",
    "metadata": {"name": "finance"},
    "spec": {"layer": "role", "reviewers": ["dev:" + R], "mergePolicy": {"requires": ["review"]}},
}


def source(connector: str = "test", documents: list | None = None) -> dict:
    spec = {"pack": "finance", "connector": connector}
    if connector == "test":
        spec["test"] = {"documents": documents or []}
    if connector == "sharepoint":
        spec["sharepoint"] = {"siteUrl": "https://example.invalid/sites/finance"}
    return {
        "apiVersion": "muistamo.dev/v1",
        "kind": "KnowledgeSource",
        "metadata": {"name": "fin-docs"},
        "spec": spec,
    }


def doc(i: str, readers: list[str]) -> dict:
    return {
        "id": i,
        "title": f"Budget {i}",
        "body": f"Budget guidance {i}.",
        "readers": ["dev:" + p for p in readers],
    }


def test_sync_indexes_and_removes_vanished_documents(world) -> None:
    instance = InMemoryConnector(documents=[doc("d1", [A]), doc("d2", [A])])
    world.knowledge.connectors = {"test": lambda s, spec, tenant=None: instance}
    r = world.client(R)
    r.put("/v1/knowledge/packs/finance", json=PACK)
    assert r.put("/v1/knowledge/sources/fin-docs", json=source()).status_code == 201
    assert r.post("/v1/knowledge/sources/fin-docs/sync").json() == {
        "source": "fin-docs",
        "indexed": 2,
        "removed": 0,
        "total": 2,
    }

    instance.documents.pop(1)  # d2 disappears at the source
    assert r.post("/v1/knowledge/sources/fin-docs/sync").json()["removed"] == 1
    record = r.get("/v1/knowledge/sources/fin-docs").json()
    assert record["documentCount"] == 1 and "lastSyncedAt" in record

    with psycopg.connect(world.db.owner_url) as conn:
        ids = [r[0] for r in conn.execute("SELECT external_id FROM knowledge.documents")]
        assert ids == ["d1"]
        # Evidence records counts, never document content.
        bodies = conn.execute(
            "SELECT count(*) FROM knowledge.evidence_events WHERE after::text LIKE '%Budget guidance%'"
        ).fetchone()[0]
        assert bodies == 0
    evidence.verify(
        world.knowledge.events(world.actor(A), 0, 1000), {world.key.key_id: world.key.public}
    )


def test_retrieve_cites_entries_and_documents(world) -> None:
    instance = InMemoryConnector(documents=[doc("d1", [A])])
    world.knowledge.connectors = {"test": lambda s, spec, tenant=None: instance}
    r, a = world.client(R), world.client(A)
    r.put("/v1/knowledge/packs/finance", json=PACK)
    r.put("/v1/knowledge/sources/fin-docs", json=source())
    r.post("/v1/knowledge/sources/fin-docs/sync")
    entry = a.post(
        "/v1/knowledge/personal/entries",
        json={
            "key": "budget-owner",
            "type": "fact",
            "title": "Budget owner",
            "body": "The CFO owns the budget.",
        },
    ).json()
    proposal = a.post(
        "/v1/knowledge/proposals",
        json={"pack": "finance", "entryIds": [entry["id"]], "summary": "s"},
    ).json()
    r.post(
        f"/v1/knowledge/proposals/{proposal['id']}/decision",
        json={"decision": "approve", "reason": "ok"},
    )

    body = a.get("/v1/knowledge/retrieve", params={"q": "budget", "packs": "finance"}).json()
    citations = sorted(
        (i["citation"]["type"], i["citation"].get("layer"), i["citation"].get("externalId"))
        for i in body["items"]
    )
    # A's personal entry wins over the merged pack entry with the same key, as in resolve.
    assert citations == [("document", None, "d1"), ("entry", "personal", None)]
    assert all(i["snippet"] for i in body["items"])
    assert len(instance.calls) == 1, "one authorisation call per source per query"

    as_reviewer = r.get("/v1/knowledge/retrieve", params={"q": "budget", "packs": "finance"}).json()
    pack_hit = next(i for i in as_reviewer["items"] if i["citation"]["type"] == "entry")
    assert pack_hit["citation"] == {
        "type": "entry",
        "layer": "role",
        "entryKey": "budget-owner",
        "pack": "finance",
        "version": "0.1.0",
    }


def test_misconfigured_and_disabled_connectors_are_refused(world) -> None:
    r = world.client(R)
    r.put("/v1/knowledge/packs/finance", json=PACK)
    world.knowledge.connectors = default_factories(enable_test=False)
    sharepoint = r.put("/v1/knowledge/sources/fin-docs", json=source("sharepoint"))
    assert sharepoint.status_code == 422 and "siteUrl" in sharepoint.json()["detail"]
    disabled = r.put("/v1/knowledge/sources/fin-docs", json=source("test"))
    assert disabled.status_code == 422 and "not enabled" in disabled.json()["detail"]
    world.knowledge.connectors = default_factories(enable_test=True)
    assert r.put("/v1/knowledge/sources/fin-docs", json=source("test")).status_code == 201


def test_only_reviewers_manage_sources(world) -> None:
    world.knowledge.connectors = default_factories(enable_test=True)
    r, a = world.client(R), world.client(A)
    r.put("/v1/knowledge/packs/finance", json=PACK)
    assert a.put("/v1/knowledge/sources/fin-docs", json=source()).status_code == 403
    assert r.put("/v1/knowledge/sources/fin-docs", json=source()).status_code == 201
    assert a.post("/v1/knowledge/sources/fin-docs/sync").status_code == 403
    assert (
        r.put("/v1/knowledge/sources/fin-docs", json=source()).status_code == 200
    )  # identical: no-op
    moved = source()
    moved["spec"]["pack"] = "elsewhere"
    r.put("/v1/knowledge/packs/elsewhere", json={**PACK, "metadata": {"name": "elsewhere"}})
    assert r.put("/v1/knowledge/sources/fin-docs", json=moved).status_code == 422
