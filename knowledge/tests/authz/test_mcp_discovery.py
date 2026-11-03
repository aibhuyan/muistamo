"""Adversarial suite: a tenant's MCP endpoint and its sign-in discovery (docs/assistants-plan.md).

An assistant (Claude, Copilot, ...) is configured with a tenant's MCP URL. From a 401 it learns
where the person signs in (RFC 9728), and the endpoint serves only that tenant's people. Never
skip or weaken.
"""

from __future__ import annotations

import uuid

import anyio
import httpx2
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from muistamo_knowledge import entra
from muistamo_knowledge.app import create_app

pytestmark = pytest.mark.authz

PUBLIC = "https://knowledge.example.invalid"
PERSON = uuid.UUID("8b000000-0000-4000-8000-00000000000a")


@pytest.fixture
def public(monkeypatch) -> str:
    monkeypatch.setenv("MUISTAMO_KNOWLEDGE_PUBLIC_URL", PUBLIC)
    return PUBLIC


def mcp_path(tenant) -> str:
    return f"/mcp/t/{tenant}/knowledge"


def metadata_path(tenant) -> str:
    return f"/.well-known/oauth-protected-resource/mcp/t/{tenant}/knowledge"


async def _tools(ew, path: str, token: str | None):
    app = create_app(ew.world.knowledge, ew.resolver)
    headers = {"Authorization": "Bearer " + token} if token else {}
    async with app.router.lifespan_context(app):
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8001", headers=headers
        ) as http:
            async with streamable_http_client(
                f"http://127.0.0.1:8001{path}/", http_client=http
            ) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    return sorted(t.name for t in (await session.list_tools()).tools)


def raw_post(ew, path: str, token: str | None = None):
    client = ew.client(token)
    return client.post(
        path + "/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )


def test_the_metadata_names_the_tenants_directory_and_scope(entra_world, public) -> None:
    DIRECTORY = entra_world.directory.directory
    AUDIENCE = entra_world.directory.claims(PERSON)["aud"]
    tenant = entra_world.world.tenant
    res = entra_world.client(None).get(metadata_path(tenant))
    assert res.status_code == 200, res.text
    assert res.json() == {
        "resource": f"{PUBLIC}{mcp_path(tenant)}",
        "authorization_servers": [f"https://login.microsoftonline.com/{DIRECTORY}/v2.0"],
        "scopes_supported": [f"api://{AUDIENCE}/Knowledge.Read"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Muistamo knowledge",
    }


@pytest.mark.parametrize("which", ["unknown", "no-entra", "malformed", "not-canonical"])
def test_no_metadata_for_a_tenant_without_a_directory(entra_world, public, which) -> None:
    tenant = {
        "unknown": uuid.uuid4(),
        "no-entra": entra_world.world.other_tenant,  # registered, but with no Entra directory
        "malformed": "not-a-tenant",
        # One URL per tenant: the canonical (lower-case) id only.
        "not-canonical": str(entra_world.world.tenant).upper(),
    }[which]
    assert entra_world.client(None).get(metadata_path(tenant)).status_code == 404


def test_no_metadata_without_a_public_url(entra_world, monkeypatch) -> None:
    monkeypatch.delenv("MUISTAMO_KNOWLEDGE_PUBLIC_URL", raising=False)
    res = entra_world.client(None).get(metadata_path(entra_world.world.tenant))
    assert res.status_code == 404


def test_a_401_tells_the_assistant_where_the_person_signs_in(entra_world, public) -> None:
    AUDIENCE = entra_world.directory.claims(PERSON)["aud"]
    tenant = entra_world.world.tenant
    res = raw_post(entra_world, mcp_path(tenant))
    assert res.status_code == 401
    challenge = res.headers["WWW-Authenticate"]
    assert challenge.startswith("Bearer "), challenge
    assert f'resource_metadata="{PUBLIC}{metadata_path(tenant)}"' in challenge, challenge
    assert f'scope="api://{AUDIENCE}/Knowledge.Read"' in challenge, challenge


def test_the_tenants_own_people_reach_its_endpoint(entra_world, public) -> None:
    token = entra_world.directory.token(PERSON)
    tools = anyio.run(_tools, entra_world, mcp_path(entra_world.world.tenant), token)
    assert tools == ["propose_knowledge", "remember", "search_knowledge"]


def test_a_token_for_one_tenant_is_refused_at_anothers_endpoint(
    entra_world, new_directory, public
) -> None:
    world = entra_world.world
    second = new_directory(directory=uuid.uuid4(), kid="second-key")
    entra.register(world.db.owner_url, world.other_tenant, second.directory, uuid.uuid4())
    # A valid token of tenant one, at tenant two's endpoint: refused before the MCP layer.
    res = raw_post(entra_world, mcp_path(world.other_tenant), entra_world.directory.token(PERSON))
    assert res.status_code == 401, res.text
    # And at an unknown tenant's, or a malformed one.
    # Even the tenant's own token is refused at a non-canonical spelling of its endpoint: one URL
    # per tenant, as its metadata names.
    upper = mcp_path(str(world.tenant).upper())
    assert raw_post(entra_world, upper, entra_world.directory.token(PERSON)).status_code == 401
    for path in (mcp_path(uuid.uuid4()), mcp_path("not-a-tenant")):
        assert raw_post(entra_world, path, entra_world.directory.token(PERSON)).status_code == 401


def test_the_shared_endpoint_is_unchanged(entra_world, public) -> None:
    res = raw_post(entra_world, "/mcp/knowledge")
    assert res.status_code == 401 and "resource_metadata" not in res.headers["WWW-Authenticate"]
    token = entra_world.directory.token(PERSON)
    assert anyio.run(_tools, entra_world, "/mcp/knowledge", token) == [
        "propose_knowledge",
        "remember",
        "search_knowledge",
    ]
