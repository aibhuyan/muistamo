"""Fixtures: a freshly migrated throwaway database and API clients acting as fake people.

The database fixture fails, never skips, when PostgreSQL is unreachable (run make dev).
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import anyio
import httpx2
import psycopg
import pytest
from fastapi.testclient import TestClient
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from muistamo_knowledge import auth, evidence
from muistamo_knowledge.app import create_app
from muistamo_knowledge.db import Database
from muistamo_knowledge.migrate import migrate
from muistamo_knowledge.service import Actor, Knowledge

ADMIN_URL = os.environ.get(
    "MUISTAMO_TEST_DATABASE_URL",
    "postgres://muistamo:dev-only-not-a-secret@127.0.0.1:5432/muistamo",
)
APP_USER, APP_PASSWORD = "muistamo_knowledge_test", "test-only-not-a-secret"


def _with_db(url: str, database: str, user: str | None = None, password: str | None = None) -> str:
    parts = urlsplit(url)
    netloc = parts.netloc
    if user:
        netloc = f"{user}:{password}@{parts.hostname}:{parts.port or 5432}"
    return urlunsplit((parts.scheme, netloc, "/" + database, parts.query, parts.fragment))


@dataclass
class TestDB:
    owner_url: str
    app_url: str


@pytest.fixture
def testdb() -> Iterator[TestDB]:
    try:
        admin = psycopg.connect(ADMIN_URL, autocommit=True)
    except psycopg.OperationalError as exc:
        pytest.fail(f"PostgreSQL unreachable at MUISTAMO_TEST_DATABASE_URL (run make dev): {exc}")
    name = "muistamo_ktest_" + secrets.token_hex(6)
    with admin:
        admin.execute("SELECT pg_advisory_lock(727002)")
        try:
            for stmt in (
                "CREATE ROLE muistamo_knowledge_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE",
                f"CREATE ROLE {APP_USER} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{APP_PASSWORD}' IN ROLE muistamo_knowledge_app",
                # The control plane's role exists so cross-service privileges can be checked.
                "CREATE ROLE muistamo_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE",
            ):
                try:
                    admin.execute(stmt)
                except psycopg.errors.DuplicateObject:
                    pass
        finally:
            admin.execute("SELECT pg_advisory_unlock(727002)")
        admin.execute(f"CREATE DATABASE {name}")
    db = TestDB(
        owner_url=_with_db(ADMIN_URL, name),
        app_url=_with_db(ADMIN_URL, name, APP_USER, APP_PASSWORD),
    )
    migrate(db.owner_url)
    try:
        yield db
    finally:
        with psycopg.connect(ADMIN_URL, autocommit=True) as c:
            c.execute(f"DROP DATABASE {name} WITH (FORCE)")


@dataclass
class World:
    db: TestDB
    key: evidence.LocalKey
    knowledge: Knowledge
    tenant: uuid.UUID
    other_tenant: uuid.UUID

    def register_tenant(self) -> uuid.UUID:
        tenant = uuid.uuid4()
        with psycopg.connect(self.db.owner_url) as conn:
            conn.execute("INSERT INTO knowledge.tenants (id) VALUES (%s)", (tenant,))
        return tenant

    def actor(self, person: str, tenant: uuid.UUID | None = None) -> Actor:
        return Actor(tenant=tenant or self.tenant, name="dev:" + person, request_id="req-" + person)

    def mcp(
        self,
        person: str | None,
        tool: str | None = None,
        args: dict | None = None,
        tenant: uuid.UUID | None = None,
    ):
        """Call an MCP tool through a real SDK client session over streamable HTTP, in-process.

        With tool=None, returns the tool names. person=None sends no identity headers.
        """
        return anyio.run(self._mcp, person, tool, args or {}, tenant)

    async def _mcp(self, person, tool, args, tenant):
        app = create_app(self.knowledge, auth.insecure_dev_headers)
        headers = {}
        if person is not None:
            headers = {"X-Muistamo-Tenant": str(tenant or self.tenant), "X-Muistamo-Actor": person}
        async with app.router.lifespan_context(app):
            transport = httpx2.ASGITransport(app=app)
            async with httpx2.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8001", headers=headers
            ) as http:
                async with streamable_http_client(
                    "http://127.0.0.1:8001/mcp/knowledge/", http_client=http
                ) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await session.initialize()
                        if tool is None:
                            return sorted(t.name for t in (await session.list_tools()).tools)
                        return await session.call_tool(tool, args)

    def client(self, person: str, tenant: uuid.UUID | None = None) -> TestClient:
        client = TestClient(
            create_app(self.knowledge, auth.insecure_dev_headers), raise_server_exceptions=False
        )
        client.headers.update(
            {"X-Muistamo-Tenant": str(tenant or self.tenant), "X-Muistamo-Actor": person}
        )
        return client


@pytest.fixture
def world(testdb: TestDB) -> Iterator[World]:
    key, _ = evidence.LocalKey.generate()
    with psycopg.connect(testdb.owner_url) as conn:
        conn.execute(
            "INSERT INTO knowledge.evidence_signing_keys (key_id, algorithm, public_key) VALUES (%s, 'ed25519', %s)",
            (key.key_id, key.public_raw()),
        )
    database = Database(testdb.app_url)
    w = World(
        db=testdb,
        key=key,
        knowledge=Knowledge(database, key),
        tenant=uuid.uuid4(),
        other_tenant=uuid.uuid4(),
    )
    w.tenant, w.other_tenant = w.register_tenant(), w.register_tenant()
    w.fake_graph = FakeGraph  # for connector harnesses that build their own
    try:
        yield w
    finally:
        database.close()


# Entra callers (PR C): a fake directory that publishes its key and signs people's tokens.
DIRECTORY = uuid.UUID("33333333-3333-4333-8333-333333333333")
AUDIENCE = uuid.UUID("44444444-4444-4444-8444-444444444444")


class FakeDirectory:
    def __init__(self, directory: uuid.UUID = DIRECTORY, kid: str = "test-signing-key") -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.directory, self.kid = directory, kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.fetches = 0

    def claims(self, user: uuid.UUID, **changes) -> dict:
        import time

        now = int(time.time())
        claims = {
            "iss": f"https://login.microsoftonline.com/{self.directory}/v2.0",
            "aud": str(AUDIENCE),
            "tid": str(self.directory),
            "oid": str(user),
            "sub": "obviously-fake-subject",
            "ver": "2.0",
            "scp": "openid Knowledge.Read",
            "iat": now,
            "nbf": now - 60,
            "exp": now + 1800,
        }
        for name, value in changes.items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        return claims

    def token(self, user: uuid.UUID, key=None, kid: str | None = None, **changes) -> str:
        import jwt

        return jwt.encode(
            self.claims(user, **changes),
            key or self.key,
            algorithm="RS256",
            headers={"kid": kid or self.kid},
        )

    def fetch(self, directory: uuid.UUID) -> bytes:
        import json

        import jwt

        assert directory == self.directory, "keys fetched for another directory"
        self.fetches += 1
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return json.dumps({"keys": [jwk]}).encode()


@dataclass
class EntraWorld:
    world: World
    directory: FakeDirectory
    resolver: object

    def client(self, token: str | None) -> TestClient:
        client = TestClient(
            create_app(self.world.knowledge, self.resolver), raise_server_exceptions=False
        )
        if token is not None:
            client.headers.update({"Authorization": "Bearer " + token})
        return client

    def mcp_refusal(self, token: str | None) -> tuple[int, str | None]:
        """A raw MCP request's status and WWW-Authenticate challenge."""

        async def post() -> tuple[int, str | None]:
            app = create_app(self.world.knowledge, self.resolver)
            headers = {"Authorization": "Bearer " + token} if token else {}
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
                    return res.status_code, res.headers.get("WWW-Authenticate")

        return anyio.run(post)

    def mcp(self, token: str | None, tool: str | None = None, args: dict | None = None):
        return anyio.run(self._mcp, token, tool, args or {})

    async def _mcp(self, token, tool, args):
        app = create_app(self.world.knowledge, self.resolver)
        headers = {"Authorization": "Bearer " + token} if token else {}
        async with app.router.lifespan_context(app):
            transport = httpx2.ASGITransport(app=app)
            async with httpx2.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8001", headers=headers
            ) as http:
                async with streamable_http_client(
                    "http://127.0.0.1:8001/mcp/knowledge/", http_client=http
                ) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await session.initialize()
                        if tool is None:
                            return sorted(t.name for t in (await session.list_tools()).tools)
                        return await session.call_tool(tool, args)


@pytest.fixture
def entra_world(world: World) -> EntraWorld:
    from muistamo_knowledge import entra

    directory = FakeDirectory()
    entra.register(world.db.owner_url, world.tenant, DIRECTORY, AUDIENCE)
    resolver = entra.EntraBearer(entra.registrations(world.knowledge.db), fetch=directory.fetch)
    return EntraWorld(world=world, directory=directory, resolver=resolver)


@pytest.fixture
def new_directory():
    """Makes fake Entra directories (FakeDirectory)."""
    return FakeDirectory


class FakeGraph:
    """A strict fake of Microsoft Graph and the token endpoint for one SharePoint site.

    The indexer authenticates with its client secret; people are asked about only with a token
    the control plane delegated for them ("delegated:<person>"). Any other request, host, method,
    header or token is a test failure or a 401.
    """

    HOST = "contoso.sharepoint.com"
    SITE = "https://contoso.sharepoint.com/sites/finance"
    DRIVE = "b!drive-1"

    def __init__(self, documents: list[dict], directory: uuid.UUID, client_id: uuid.UUID) -> None:
        self.documents = documents
        self.directory, self.client_id = directory, client_id
        self.unavailable = False
        self.batch_status: int | None = None  # every item answers this, when set
        self.tokens_asked: list[str] = []
        self.calls: list[tuple[str, str]] = []

    def external_id(self, doc_id: str) -> str:
        return f"{self.DRIVE}/{doc_id}"

    def web_url(self, doc_id: str) -> str:
        return f"{self.SITE}/Shared%20Documents/{doc_id}.txt"

    def __call__(self, method, url, headers, body, timeout):
        import json
        from urllib.parse import parse_qs, urlsplit

        self.calls.append((method, url))
        parts = urlsplit(url)
        assert parts.scheme == "https", url
        if parts.hostname == "login.microsoftonline.com":
            assert method == "POST" and parts.path == f"/{self.directory}/oauth2/v2.0/token"
            form = parse_qs(body.decode())
            assert form["client_id"] == [str(self.client_id)] and form["grant_type"] == [
                "client_credentials"
            ]
            assert form["client_secret"] == ["obviously-fake-indexer-secret"]
            return 200, json.dumps(
                {"access_token": "indexer-token", "token_type": "Bearer", "expires_in": 3600}
            ).encode()
        if parts.hostname == self.HOST:
            # A pre-authenticated download link: never sent a token.
            assert method == "GET" and "Authorization" not in headers, "download sent a token"
            doc_id = parts.path.rsplit("/", 1)[-1]
            doc = next(d for d in self.documents if d["id"] == doc_id)
            return 200, doc["body"].encode()
        assert parts.hostname == "graph.microsoft.com", url
        token = headers.get("Authorization", "").removeprefix("Bearer ")
        path = parts.path.removeprefix("/v1.0")
        if path == "/$batch":
            assert method == "POST"
            if token == "indexer-token" or not token.startswith("delegated:"):  # noqa: S105 - fake tokens
                return 401, b'{"error":{"code":"InvalidAuthenticationToken"}}'
            person = token.removeprefix("delegated:")
            self.tokens_asked.append(person)
            if self.unavailable:
                return 503, b'{"error":{"code":"serviceNotAvailable"}}'
            responses = []
            for request in json.loads(body)["requests"]:
                assert request["method"] == "GET" and request["url"].endswith("?$select=id")
                item = request["url"].split("/items/", 1)[1].split("?", 1)[0]
                doc = next((d for d in self.documents if d["id"] == item), None)
                status = 404 if doc is None else 200 if person in doc["readers"] else 403
                responses.append(
                    {"id": request["id"], "status": self.batch_status or status, "body": {}}
                )
            return 200, json.dumps({"responses": responses[::-1]}).encode()
        assert method == "GET" and token == "indexer-token", f"{method} {path} with {token[:12]}"  # noqa: S105 - fake tokens
        if path == "/sites/contoso.sharepoint.com:/sites/finance":
            return 200, b'{"id":"contoso.sharepoint.com,1111,2222"}'
        if path == "/sites/contoso.sharepoint.com%2C1111%2C2222/drives":
            return 200, json.dumps(
                {
                    "value": [
                        {"id": self.DRIVE, "name": "Documents"},
                        {"id": "b!other", "name": "Archive"},
                    ]
                }
            ).encode()
        if path == f"/drives/{self.DRIVE}/root/delta":
            page = int(parse_qs(parts.query).get("page", ["0"])[0])
            items = [
                {
                    "id": d["id"],
                    "name": d["id"] + ".txt",
                    "file": {},
                    "size": len(d["body"]),
                    "webUrl": self.web_url(d["id"]),
                    "lastModifiedDateTime": "2026-10-30T09:00:00Z",
                    "@microsoft.graph.downloadUrl": f"https://{self.HOST}/download/{d['id']}",
                }
                for d in self.documents
            ]
            half = len(items) // 2
            if page == 0:
                return 200, json.dumps(
                    {
                        "value": [{"id": "root", "name": "root", "folder": {}}, *items[:half]],
                        "@odata.nextLink": f"https://graph.microsoft.com/v1.0/drives/{self.DRIVE}/root/delta?page=1",
                    }
                ).encode()
            return 200, json.dumps(
                {"value": items[half:], "@odata.deltaLink": "https://graph.microsoft.com/v1.0/x"}
            ).encode()
        if path == "/drives/b!other/root/delta":
            raise AssertionError("a library outside spec.sharepoint.libraries was listed")
        raise AssertionError(f"unexpected Graph call {method} {url}")


@pytest.fixture
def fake_graph():
    """Makes strict fake Graphs (FakeGraph)."""
    return FakeGraph
