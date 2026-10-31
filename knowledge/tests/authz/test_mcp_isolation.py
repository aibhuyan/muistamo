"""Adversarial suite for the MCP knowledge server. Never skip or weaken (CLAUDE.md).

The MCP path must enforce exactly what the REST path enforces: the caller's own permissions at
use time, private personal layers, tenant isolation, and refusal without an identity.
"""

import uuid

import anyio
import httpx2
import pytest
from muistamo_knowledge import auth
from muistamo_knowledge.app import create_app
from muistamo_knowledge.connectors import InMemoryConnector

pytestmark = pytest.mark.authz

A, B, R = "person-a@example.invalid", "person-b@example.invalid", "reviewer-r@example.invalid"
PACK = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "KnowledgePack",
    "metadata": {"name": "finance"},
    "spec": {"layer": "role", "reviewers": ["dev:" + R], "mergePolicy": {"requires": ["review"]}},
}


def setup(world) -> None:
    docs = [
        {
            "id": "only-a",
            "title": "Salary review",
            "body": "Salary review notes for A.",
            "readers": ["dev:" + A],
        },
        {
            "id": "only-b",
            "title": "Salary bands",
            "body": "Salary bands visible to B.",
            "readers": ["dev:" + B],
        },
    ]
    instance = InMemoryConnector(documents=docs)
    world.knowledge.connectors = {"test": lambda s, spec, tenant=None: instance}
    r = world.client(R)
    r.put("/v1/knowledge/packs/finance", json=PACK)
    r.put(
        "/v1/knowledge/sources/hr-docs",
        json={
            "apiVersion": "muistamo.dev/v1",
            "kind": "KnowledgeSource",
            "metadata": {"name": "hr-docs"},
            "spec": {"pack": "finance", "connector": "test", "test": {"documents": []}},
        },
    )
    r.post("/v1/knowledge/sources/hr-docs/sync")
    world.mcp(
        A,
        "remember",
        {
            "key": "a-salary-note",
            "title": "My salary note",
            "body": "Salary talk with manager in May.",
        },
    )


def cited(result) -> set[str]:
    assert not result.is_error, result
    return {
        r["citation"].get("externalId") or r["citation"].get("entryKey")
        for r in result.structured_content["results"]
    }


def test_mcp_search_enforces_the_callers_own_permissions(world) -> None:
    setup(world)
    assert cited(world.mcp(A, "search_knowledge", {"query": "salary", "packs": ["finance"]})) == {
        "only-a",
        "a-salary-note",
    }
    # B never sees A's document or A's personal entry, only what B may open.
    assert cited(world.mcp(B, "search_knowledge", {"query": "salary", "packs": ["finance"]})) == {
        "only-b"
    }


def test_mcp_search_never_crosses_tenants(world) -> None:
    setup(world)
    other = world.mcp(A, "search_knowledge", {"query": "salary"}, tenant=world.other_tenant)
    assert cited(other) == set()
    assert other.structured_content["coverage"]["sourcesQueried"] == []


def test_mcp_refuses_requests_without_a_resolvable_caller(world) -> None:
    async def post(headers: dict, knowledge, resolver=auth.insecure_dev_headers) -> int:
        app = create_app(knowledge, resolver)
        async with app.router.lifespan_context(app):
            transport = httpx2.ASGITransport(app=app)
            async with httpx2.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8001", headers=headers
            ) as http:
                res = await http.post(
                    "/mcp/knowledge/",
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Accept": "application/json, text/event-stream"},
                )
                return res.status_code

    good = {"X-Muistamo-Tenant": str(world.tenant), "X-Muistamo-Actor": A}
    assert anyio.run(post, {}, world.knowledge) == 401
    assert anyio.run(post, {"X-Muistamo-Tenant": str(world.tenant)}, world.knowledge) == 401
    assert anyio.run(post, {**good, "X-Muistamo-Tenant": str(uuid.uuid4())}, world.knowledge) == 401
    assert anyio.run(post, good, world.knowledge, auth.deny_all) == 401, (
        "deny_all must refuse even valid-looking headers"
    )
    assert anyio.run(post, good, None) == 401, "an unconfigured service refuses everything"
    assert anyio.run(post, good, world.knowledge) == 200


def test_mcp_cannot_propose_someone_elses_entries_or_approve_its_own(world) -> None:
    setup(world)
    sent = world.mcp(
        B,
        "propose_knowledge",
        {
            "pack": "finance",
            "key": "b-fact",
            "title": "B fact",
            "body": "Bonuses are paid in March.",
            "summary": "s",
        },
    ).structured_content
    assert sent["status"] == "in-review"
    # The reviewer sees it; A (neither contributor nor reviewer) cannot.
    assert world.client(A).get(f"/v1/knowledge/proposals/{sent['proposalId']}").status_code == 404
    assert (
        world.client(B)
        .post(
            f"/v1/knowledge/proposals/{sent['proposalId']}/decision",
            json={"decision": "approve", "reason": "x"},
        )
        .status_code
        == 403
    )
