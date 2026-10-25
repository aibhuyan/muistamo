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
    try:
        yield w
    finally:
        database.close()
