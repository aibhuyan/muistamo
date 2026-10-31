"""Separate-binary end-to-end run of per-person retrieval (docs/obo-retrieval-plan.md). Test use only.

Real binaries and services: the control plane (built with -tags e2e) serving the API and running
the Entra lifecycle worker on Temporal, the knowledge service (started through knowledge_e2e.py),
PostgreSQL, and a loopback fake of Entra, Graph and SharePoint over verified TLS. The journey:

1. An HR joiner links the person to their Entra user and activates their agent.
2. An MCP search with the person's Entra token returns a cited SharePoint document they can open,
   and not one they cannot.
3. Revoking the person's access at SharePoint hides the document at the next call.
4. A pack outside the agent's template returns nothing.
5. An HR leaver suspends the agent, so the next search gets no delegation.
6. Evidence verifies in both services.

Needs MUISTAMO_TEST_DATABASE_URL (a superuser) and Temporal on 127.0.0.1:7233 (make dev).
Run: uv run --no-sync python deploy/dev/e2e/run_obo.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import anyio
import httpx2
import psycopg
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
import fake_microsoft  # noqa: E402

ADMIN = os.environ.get(
    "MUISTAMO_TEST_DATABASE_URL",
    "postgres://muistamo:dev-only-not-a-secret@127.0.0.1:5432/muistamo",
)
PERSON, OTHER, REVIEWER = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
TEMPLATE = {
    "apiVersion": "muistamo.dev/v1",
    "kind": "AgentTemplate",
    "metadata": {"name": "analyst"},
    "spec": {
        "purpose": "e2e analyst",
        "modelAlias": "reasoning-default",
        "riskTier": "low",
        "knowledgePacks": [{"name": "finance"}],
        "assignment": {"hrJobCodes": ["ANALYST"]},
    },
}


def step(message: str) -> None:
    print(f"--- {message}", flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# The servers connect as these login roles, members of the roles the migrations grant, so row-level
# security holds exactly as in production; only migrations and operator commands use ADMIN.
# Obviously fake passwords, as in the Go and Python test fixtures.
SERVER_ROLES = {
    "muistamo_app": ("muistamo_server_test", "test-only-not-a-secret"),
    "muistamo_knowledge_app": ("muistamo_knowledge_test", "test-only-not-a-secret"),
}


def database(name: str) -> str:
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        for group, (user, password) in SERVER_ROLES.items():
            for statement in (
                f"CREATE ROLE {group} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE",
                f"CREATE ROLE {user} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' IN ROLE {group}",
            ):
                try:
                    conn.execute(statement)
                except psycopg.errors.DuplicateObject:
                    pass
        conn.execute(f"CREATE DATABASE {name}")
    return _url(name)


def _url(name: str, role: str | None = None) -> str:
    parts = urlsplit(ADMIN)
    netloc = parts.netloc
    if role is not None:
        user, password = SERVER_ROLES[role]
        netloc = f"{user}:{password}@{parts.hostname}:{parts.port or 5432}"
    return urlunsplit((parts.scheme, netloc, "/" + name, parts.query, parts.fragment))


def run(args: list[str], env: dict[str, str], stdin: str | None = None) -> str:
    done = subprocess.run(
        args, env=env, input=stdin, capture_output=True, text=True, timeout=300, cwd=ROOT
    )
    if done.returncode != 0:
        raise SystemExit(f"{' '.join(args[:3])} failed:\n{done.stderr}")
    return done.stdout.strip()


def http(
    method: str, url: str, body: object = None, headers: dict[str, str] | None = None
) -> tuple[int, dict]:
    data = (
        None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    )
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else {}


CHILDREN: list[tuple[subprocess.Popen, Path]] = []


def wait_for(what: str, check, timeout: float = 60) -> object:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for child, log in CHILDREN:
            if child.poll() is not None:
                tail = "\n".join(log.read_text(errors="replace").splitlines()[-20:])
                raise SystemExit(
                    f"{log.stem} exited ({child.returncode}) while waiting for {what}:\n{tail}"
                )
        value = check()
        if value:
            return value
        time.sleep(0.5)
    raise SystemExit(f"timed out waiting for {what}")


def start(args: list[str], env: dict[str, str], log: Path, stdin: str | None = None) -> None:
    with log.open("w") as out:
        child = subprocess.Popen(
            args,
            env=env,
            stdin=subprocess.PIPE,
            stdout=out,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=ROOT,
        )
    if stdin is not None:
        child.stdin.write(stdin)
    child.stdin.close()
    CHILDREN.append((child, log))


async def mcp_search(url: str, token: str, packs: list[str]) -> dict:
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token}, timeout=30
    ) as client:
        async with streamable_http_client(url, http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool(
                    "search_knowledge", {"query": "quarterly", "packs": packs}
                )
                return result.structured_content


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="muistamo-e2e-"))
    passed = False
    suffix = secrets.token_hex(4)
    try:
        step("fake Microsoft over TLS")
        ca, cert, key = fake_microsoft.write_certificates(str(work))
        directory, blueprint, indexer = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        blueprint_secret, indexer_secret = (
            "obviously-fake-blueprint-" + suffix,
            "obviously-fake-indexer-" + suffix,
        )
        ms = fake_microsoft.Microsoft(
            directory, blueprint, blueprint_secret, indexer, indexer_secret
        )
        server = fake_microsoft.serve(ms, cert, key)
        e2e = {
            "MUISTAMO_E2E_MICROSOFT_ADDR": f"127.0.0.1:{server.server_address[1]}",
            "MUISTAMO_E2E_MICROSOFT_CA": ca,
        }
        ms.users = [
            {"id": str(PERSON), "employeeId": "E-1001"},
            {"id": str(OTHER), "employeeId": "E-2002"},
        ]
        ms.libraries["Documents"] = [
            {
                "id": "plan-open",
                "body": "Quarterly plan the person can open.",
                "readers": [str(PERSON)],
            },
            {
                "id": "plan-closed",
                "body": "Quarterly plan for someone else.",
                "readers": [str(OTHER)],
            },
        ]
        ms.libraries["Legal"] = [
            {"id": "legal-open", "body": "Quarterly legal note.", "readers": [str(PERSON)]}
        ]

        step("build the control plane with -tags e2e")
        binary = str(work / ("control-plane.exe" if os.name == "nt" else "control-plane"))
        run(
            ["go", "build", "-tags", "e2e", "-o", binary, "./control-plane/cmd/control-plane"],
            dict(os.environ),
        )

        step("control plane: database, keys, tenant, secrets, Entra enrollment")
        cpdb = database(f"muistamo_e2e_cp_{suffix}")
        base = {
            **os.environ,
            **e2e,
            "MUISTAMO_MIGRATE_DATABASE_URL": cpdb,
            "MUISTAMO_DATABASE_URL": _url(f"muistamo_e2e_cp_{suffix}", "muistamo_app"),
        }
        run([binary, "migrate"], base)
        cp_key = str(work / "cp-evidence.key")
        run([binary, "evidence", "keygen", "--out", cp_key], base)
        base["MUISTAMO_EVIDENCE_KEY_FILE"] = cp_key
        tenant = run([binary, "tenant", "create", "acme"], base).splitlines()[-1].strip()
        hr_secret = run([binary, "tenant", "hr-secret", tenant], base).splitlines()[-1].strip()
        knowledge_secret = (
            run([binary, "tenant", "knowledge-secret", tenant], base).splitlines()[-1].strip()
        )
        binding = {
            "tenantId": tenant,
            "bindingVersion": str(uuid.uuid4()),
            "entraTenantId": str(directory),
            "blueprintAppId": str(blueprint),
            "blueprintObjectId": str(uuid.uuid4()),
            "blueprintPrincipalId": str(uuid.uuid4()),
            "sponsorUserIds": [str(uuid.uuid4())],
            "credentialRef": "e2e-blueprint",
            "credentialVersion": "1",
        }
        binding_file = work / "binding.json"
        binding_file.write_text(json.dumps(binding))
        run(
            [
                binary,
                "entra",
                "enroll",
                "--tenant",
                tenant,
                "--actor",
                "operator:e2e",
                "--binding",
                str(binding_file),
            ],
            base,
        )
        with psycopg.connect(cpdb) as conn, conn.transaction():
            conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (tenant,))
            conn.execute(
                """INSERT INTO model_catalogue (tenant_id, name, revision, digest, document, approval_status,
                decided_by, decision_reason, decided_at, updated_by)
                VALUES (%s, 'e2e-model', 1, 'seed', jsonb_build_object('apiVersion', 'muistamo.dev/v1', 'kind', 'ModelCatalogueItem',
                  'metadata', jsonb_build_object('name', 'e2e-model'),
                  'spec', jsonb_build_object('provider', 'test', 'model', 'test-model', 'region', 'eu-test', 'termsRef', 'test-terms',
                    'priceSheet', jsonb_build_object('currency', 'EUR', 'inputPerMTok', 0, 'outputPerMTok', 0))),
                  'approved', 'seed:privacy-officer', 'e2e fixture', now(), 'seed:operator')""",
                (tenant,),
            )
            conn.execute(
                """INSERT INTO model_aliases (tenant_id, name, target, revision, digest, document, updated_by)
                VALUES (%s, 'reasoning-default', 'e2e-model', 1, 'seed', jsonb_build_object('apiVersion', 'muistamo.dev/v1',
                'kind', 'ModelAlias', 'metadata', jsonb_build_object('name', 'reasoning-default'),
                'spec', jsonb_build_object('target', 'e2e-model')), 'seed:operator')""",
                (tenant,),
            )

        step("control plane: worker and API")
        cp_port = free_port()
        live = {
            **base,
            "TEMPORAL_ADDRESS": "127.0.0.1:7233",
            "CONTROL_PLANE_ADDR": f"127.0.0.1:{cp_port}",
            "MUISTAMO_INSECURE_DEV_TENANT_HEADER": "true",
        }
        for command in ("worker", "serve"):
            start(
                [binary, command, "--entra-binding", str(binding_file), "--credential-stdin"],
                live,
                work / f"{command}.log",
                blueprint_secret + "\n",
            )
        cp = f"http://127.0.0.1:{cp_port}"
        operator = {"X-Muistamo-Tenant": tenant, "X-Muistamo-Actor": "operator@example.invalid"}
        wait_for("the control plane", lambda: _up(cp + "/healthz"))
        status, body = http("PUT", cp + "/v1/templates/analyst", TEMPLATE, operator)
        assert status in (200, 201), (status, body)
        status, body = http(
            "POST", cp + "/v1/templates/analyst/versions/1/publication", None, operator
        )
        assert status in (200, 201), (status, body)

        step("knowledge: database, tenant, secrets, Entra registration, SharePoint indexer")
        kdb = database(f"muistamo_e2e_k_{suffix}")
        kenv = {
            **os.environ,
            **e2e,
            "MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL": kdb,
            "MUISTAMO_KNOWLEDGE_DATABASE_URL": _url(
                f"muistamo_e2e_k_{suffix}", "muistamo_knowledge_app"
            ),
        }
        python = [sys.executable, "-m", "muistamo_knowledge"]
        run(python + ["migrate"], kenv)
        run(python + ["tenant", "register", tenant], kenv)
        run(python + ["tenant", "service-secret", tenant], kenv, stdin=knowledge_secret + "\n")
        run(python + ["tenant", "entra", tenant, str(directory), str(blueprint)], kenv)
        k_key = str(work / "k-evidence.key")
        run(python + ["evidence", "keygen", "--out", k_key], kenv)
        (work / "indexer.secret").write_text(indexer_secret)
        (work / "indexers.json").write_text(
            json.dumps(
                {
                    tenant: {
                        "directory": str(directory),
                        "clientId": str(indexer),
                        "secretFile": str(work / "indexer.secret"),
                    }
                }
            )
        )
        k_port = free_port()
        kenv |= {
            "MUISTAMO_KNOWLEDGE_EVIDENCE_KEY_FILE": k_key,
            "KNOWLEDGE_ADDR": f"127.0.0.1:{k_port}",
            "MUISTAMO_KNOWLEDGE_ENTRA": "true",
            "MUISTAMO_CONTROL_PLANE_URL": cp,
            "MUISTAMO_KNOWLEDGE_CONTROL_PLANE_PLAINTEXT": "true",
            "MUISTAMO_SHAREPOINT_INDEXERS": str(work / "indexers.json"),
        }
        start([sys.executable, str(HERE / "knowledge_e2e.py")], kenv, work / "knowledge.log")
        kn = f"http://127.0.0.1:{k_port}"
        wait_for("the knowledge service", lambda: _up(kn + "/healthz"))

        step("knowledge: packs and SharePoint sources, indexed by the indexer app")
        reviewer = {"Authorization": "Bearer " + ms.user_token(REVIEWER)}
        for name, library in (("finance", "Documents"), ("legal", "Legal")):
            pack = {
                "apiVersion": "muistamo.dev/v1",
                "kind": "KnowledgePack",
                "metadata": {"name": name},
                "spec": {
                    "layer": "role",
                    "reviewers": [f"entra:{REVIEWER}"],
                    "mergePolicy": {"requires": ["review"]},
                },
            }
            status, body = http("PUT", f"{kn}/v1/knowledge/packs/{name}", pack, reviewer)
            assert status == 201, (status, body)
            source = {
                "apiVersion": "muistamo.dev/v1",
                "kind": "KnowledgeSource",
                "metadata": {"name": f"{name}-site"},
                "spec": {
                    "pack": name,
                    "connector": "sharepoint",
                    "sharepoint": {"siteUrl": fake_microsoft.SITE, "libraries": [library]},
                },
            }
            status, body = http("PUT", f"{kn}/v1/knowledge/sources/{name}-site", source, reviewer)
            assert status == 201, (status, body)
            status, body = http(
                "POST", f"{kn}/v1/knowledge/sources/{name}-site/sync", None, reviewer
            )
            assert status == 200 and body["indexed"] >= 1, (status, body)

        step("1. HR joiner: the person is linked and their agent activated")
        hr_event(cp, tenant, hr_secret, "join-1", "joiner", 0)
        instance = wait_for("an active agent", lambda: _active(cp, operator), timeout=90)
        print(f"    agent {instance} active; agent identities at the fake: {len(ms.identities)}")

        step("2. MCP search as the person: their document, cited, and not another's")
        token = ms.user_token(PERSON)
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", token, ["finance"])
        ids = {r["citation"]["externalId"] for r in found["results"]}
        assert ids == {"b!documents/plan-open"}, found
        assert found["coverage"]["delegation"] == {"status": "issued", "agent": instance}, found[
            "coverage"
        ]
        assert found["results"][0]["citation"]["url"].startswith(fake_microsoft.SITE)
        assert ms.exchanges and ms.exchanges[-1][1] == str(PERSON)

        step("3. Revoked at SharePoint: hidden at the next call")
        ms.libraries["Documents"][0]["readers"] = []
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", token, ["finance"])
        assert found["results"] == [], found

        step("4. A pack outside the agent's template returns nothing")
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", token, ["legal"])
        assert found["results"] == [] and found["coverage"]["packsOutsideAgentScope"] == [
            "legal"
        ], found

        step("5. HR leaver: the agent is suspended, and the next search gets no delegation")
        ms.libraries["Documents"][0]["readers"] = [str(PERSON)]
        hr_event(cp, tenant, hr_secret, "leave-1", "leaver", 60)
        wait_for(
            "the agent suspended", lambda: _state(cp, operator, instance) == "suspended", timeout=90
        )
        exchanges = len(ms.exchanges)
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", token, ["finance"])
        assert found["results"] == [] and found["coverage"]["delegation"]["status"] == "refused", (
            found
        )
        # The control plane refused: Entra was never asked to exchange the leaver's token.
        assert len(ms.exchanges) == exchanges, "a leaver's token reached the exchange"
        assert not any(i["accountEnabled"] for i in ms.identities.values()), ms.identities

        step("6. Evidence verifies in both services")
        export = work / "cp-evidence.jsonl"
        mst = {
            **os.environ,
            "MST_SERVER": cp,
            "MST_TENANT": tenant,
            "MST_ACTOR": "operator@example.invalid",
        }
        run(["go", "run", "./cli/cmd/mst", "evidence", "export", "-o", str(export)], mst)
        run(
            [
                "go",
                "run",
                "./cli/cmd/mst",
                "evidence",
                "verify",
                "-f",
                str(export),
                "--public-key",
                cp_key + ".pub",
            ],
            mst,
        )
        actions = [json.loads(line)["action"] for line in export.read_text().splitlines()]
        for action in (
            "identity.user.linked",
            "knowledge.delegation.issued",
            "knowledge.delegation.refused",
        ):
            assert action in actions, (action, sorted(set(actions)))
        verify_knowledge(kdb, tenant, k_key + ".pub")
        print(f"OK: {len(actions)} control-plane events and the knowledge chain verified")
        passed = True
    finally:
        for child, _ in CHILDREN:
            child.terminate()
        for child, _ in CHILDREN:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
        try:
            with psycopg.connect(ADMIN, autocommit=True) as conn:
                # Only the two databases this run created.
                for name in (f"muistamo_e2e_cp_{suffix}", f"muistamo_e2e_k_{suffix}"):
                    conn.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        except psycopg.Error as exc:
            print(f"could not drop this run's databases: {exc}", file=sys.stderr)
        if passed:
            # Throwaway keys, certificates and secrets only; kept for a failed run's logs.
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"logs and throwaway keys in {work}")


def _up(url: str) -> bool:
    try:
        return http("GET", url)[0] == 200
    except OSError:
        return False


def hr_event(cp: str, tenant: str, secret: str, event_id: str, kind: str, offset: int) -> None:
    occurred = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 120 + offset))
    body = json.dumps(
        {
            "id": event_id,
            "type": kind,
            "occurredAt": occurred,
            "person": {"id": "E-1001", "email": "person@example.invalid", "jobCode": "ANALYST"},
        }
    ).encode()
    ts = str(int(time.time()))
    mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    status, answer = http(
        "POST",
        cp + "/v1/hr/events",
        body,
        {"X-Muistamo-Tenant": tenant, "X-Muistamo-Signature": f"t={ts},v1={mac}"},
    )
    assert status == 202, (status, answer)


def _active(cp: str, operator: dict) -> str | None:
    status, body = http("GET", cp + "/v1/instances", None, operator)
    for item in body.get("items", []) if status == 200 else []:
        if item["document"]["spec"]["state"] == "active":
            return item["document"]["metadata"]["name"]
    return None


def _state(cp: str, operator: dict, name: str) -> str | None:
    status, body = http("GET", f"{cp}/v1/instances/{name}", None, operator)
    return body["document"]["spec"]["state"] if status == 200 else None


def verify_knowledge(url: str, tenant: str, public_key: str) -> None:
    from muistamo_knowledge import evidence

    key = load_pem_public_key(Path(public_key).read_bytes())
    with psycopg.connect(url) as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (tenant,))
        events = evidence.list_events(cur, 0, 100000)
    evidence.verify(events, {evidence.key_id(key): key})
    assert events, "the knowledge chain is empty"


if __name__ == "__main__":
    main()
