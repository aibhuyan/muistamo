"""Separate-binary end-to-end run of per-person retrieval (docs/obo-retrieval-plan.md). Test use only.

Real binaries and services: the control plane (built with -tags e2e) serving the API and running
the Entra lifecycle worker on Temporal, the knowledge service (started through knowledge_e2e.py),
PostgreSQL, and a loopback fake of Entra, Graph and SharePoint over verified TLS. The journey:

1. An HR joiner links the person to their Entra user and activates their agent, which is issued a
   gateway virtual key.
2. An MCP search with the person's Entra token returns a cited SharePoint document they can open,
   and not one they cannot.
3. A correction the person proposes through MCP is merged only on a pack reviewer's approval,
   and the next search answers with it, cited to the pack version.
4. Revoking the person's access at SharePoint hides the document at the next call.
5. A pack outside the agent's template returns nothing.
6. An HR leaver suspends the agent and revokes its key, so the next search gets no delegation,
   and opens the review
   of the person's personal layer: frozen, and shown to their manager (by the manager's own
   Entra token) and no one else (docs/live-review-plan.md).
7. A rehire fences the review: the layer is unfrozen, and a replayed open or expiry from the old
   leaving changes nothing.
8. A second leaving runs its grace period to the end: the agent is retired and the undecided
   layer purged at the review deadline (both shortened in these test builds only), while the
   correction merged in step 3 still answers the colleague: the company keeps it.
9. Evidence verifies in both services.

Together this is the release 1 slice end to end (AGENTS.md), against fakes of Microsoft's services.

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
PERSON, OTHER, REVIEWER, MANAGER = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
# The AI platform team: the one knowledge administrator, who creates packs for their owners.
PLATFORM = uuid.uuid4()
# Test builds only: the leaver grace period (control plane, -tags e2e) and the review period
# (knowledge_e2e.py). The grace period outlasts steps 5 and 6, and the review its deadline.
GRACE_SECONDS, REVIEW_SECONDS = 60, 5
# The leaver's personal layer: this note only (their copy of the step 3 correction was retired
# when it merged).
NOTES = ["e2e-note"]
NOTE = {"key": "e2e-note", "type": "fact", "title": "A note", "body": "Close the books in April."}
# D59: a private note is never shown to the decider and is deleted when the review opens.
PRIVATE_NOTE = {
    "key": "e2e-private-note",
    "type": "fact",
    "title": "A private note",
    "body": "Only for me: prepare the handover.",
    "private": True,
}
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


async def mcp_call(url: str, token: str, tool: str, args: dict) -> dict:
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token}, timeout=30
    ) as client:
        async with streamable_http_client(url, http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool(tool, args)
                assert not result.is_error, result
                return result.structured_content


async def mcp_search(url: str, token: str, packs: list[str]) -> dict:
    return await mcp_call(url, token, "search_knowledge", {"query": "quarterly", "packs": packs})


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
            "MUISTAMO_E2E_GRACE_SECONDS": str(GRACE_SECONDS),
        }
        ms.users = [
            {"id": str(PERSON), "employeeId": "E-1001"},
            {"id": str(OTHER), "employeeId": "E-2002"},
            {"id": str(MANAGER), "employeeId": "E-3003"},
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
        cp_port, k_port = free_port(), free_port()
        live = {
            **base,
            "TEMPORAL_ADDRESS": "127.0.0.1:7233",
            "CONTROL_PLANE_ADDR": f"127.0.0.1:{cp_port}",
            "MUISTAMO_INSECURE_DEV_TENANT_HEADER": "true",
            # The worker opens leavers' reviews in the knowledge service started below.
            "MUISTAMO_KNOWLEDGE_URL": f"http://127.0.0.1:{k_port}",
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
            "MUISTAMO_KNOWLEDGE_PRIVATE_ENTRIES": "true",
            "MUISTAMO_KNOWLEDGE_DATABASE_URL": _url(
                f"muistamo_e2e_k_{suffix}", "muistamo_knowledge_app"
            ),
        }
        python = [sys.executable, "-m", "muistamo_knowledge"]
        run(python + ["migrate"], kenv)
        run(python + ["tenant", "register", tenant], kenv)
        run(python + ["tenant", "service-secret", tenant], kenv, stdin=knowledge_secret + "\n")
        run(python + ["tenant", "entra", tenant, str(directory), str(blueprint)], kenv)
        # The assistant the tenant allows: tokens from any other client app are refused.
        run(
            python
            + ["tenant", "assistant", "add", tenant, str(fake_microsoft.ASSISTANT), "Claude"],
            kenv,
        )
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
        kenv |= {
            "MUISTAMO_E2E_REVIEW_SECONDS": str(REVIEW_SECONDS),
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
        # Reviewers act through the console as themselves, never through an assistant.
        run(
            python
            + ["tenant", "assistant", "add", tenant, str(fake_microsoft.CONSOLE), "Console"]
            + ["--kind", "console"],
            kenv,
        )
        reviewer = {
            "Authorization": "Bearer " + ms.user_token(REVIEWER, azp=fake_microsoft.CONSOLE)
        }
        platform = bearer(ms.user_token(PLATFORM, azp=fake_microsoft.CONSOLE))
        run(python + ["tenant", "knowledge-admins", tenant, f"entra:{PLATFORM}"], kenv)
        # The same reviewer through their assistant cannot change a pack.
        status, _ = http(
            "GET",
            f"{kn}/v1/knowledge/proposals?role=reviewer",
            None,
            bearer(ms.user_token(REVIEWER)),
        )
        assert status == 403, status
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
            # Only the knowledge administrator creates a pack, even one naming its owner.
            status, _ = http("PUT", f"{kn}/v1/knowledge/packs/{name}", pack, reviewer)
            assert status == 403, status
            status, body = http("PUT", f"{kn}/v1/knowledge/packs/{name}", pack, platform)
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
        (identity,) = ms.identities  # the person's agent identity
        # The manager joins too (no template matches their job), so their own link stands.
        hr_event(cp, tenant, hr_secret, "mgr-join", "joiner", 10, MANAGER_HR)
        wait_for(
            "the manager linked", lambda: _link(cpdb, tenant, "E-3003") == "matched", timeout=90
        )
        # The agent's gateway key, issued by a gateway administrator; the leaver must revoke it.
        run(
            [binary, "gateway", "admins", "set", "--tenant", tenant, "--actor", "operator:e2e"]
            + ["dev:operator@example.invalid"],
            base,
        )
        key_request = {
            "instance": instance,
            "aliases": ["reasoning-default"],
            "monthlyBudget": {"amount": "5", "currency": "EUR"},
        }
        status, issued = http("POST", cp + "/v1/virtual-keys", key_request, operator)
        assert status == 201 and issued["key"]["status"] == "active", (status, issued)
        key_id = issued["key"]["id"]
        # A colleague in the same role gets their own agent of the same template.
        hr_event(cp, tenant, hr_secret, "colleague-join", "joiner", 5, COLLEAGUE_HR)
        wait_for(
            "the colleague's agent active",
            lambda: _state(cp, operator, "analyst-e-2002") == "active",
            timeout=90,
        )

        step("2. MCP search as the person: their document, cited, and not another's")
        token = ms.user_token(PERSON)
        # The same person through an assistant the tenant has not allowed: refused outright.
        unlisted = ms.user_token(PERSON, azp=uuid.uuid4())
        status, _ = http("GET", f"{kn}/v1/knowledge/personal/entries", None, bearer(unlisted))
        assert status == 401, status
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", token, ["finance"])
        ids = {r["citation"]["externalId"] for r in found["results"]}
        assert ids == {"b!documents/plan-open"}, found
        assert found["coverage"]["delegation"] == {"status": "issued", "agent": instance}, found[
            "coverage"
        ]
        assert found["results"][0]["citation"]["url"].startswith(fake_microsoft.SITE)
        assert ms.exchanges and ms.exchanges[-1][1] == str(PERSON)

        step(
            "3. A correction through MCP, merged on a reviewer's approval, answers the next search"
        )
        correction = {
            "pack": "finance",
            "key": "quarterly-close",
            "title": "Quarterly close",
            "body": "The quarterly close is on the fifth working day.",
            "summary": "The close moved to the fifth working day.",
        }
        proposed = anyio.run(
            mcp_call, f"{kn}/mcp/knowledge/", token, "propose_knowledge", correction
        )
        assert proposed["status"] == "in-review", proposed
        colleague = ms.user_token(OTHER)
        # Nothing reaches a colleague before review (the author sees their own copy at once).
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", colleague, ["finance"])
        assert "Quarterly close" not in [r["title"] for r in found["results"]], (
            "merged before review"
        )
        # The person cannot approve their own correction; the pack's reviewer can.
        decision = {"decision": "approve", "reason": "Confirmed with the controller."}
        path = f"{kn}/v1/knowledge/proposals/{proposed['proposalId']}/decision"
        status, _ = http("POST", path, decision, bearer(token))
        assert status in (403, 404), status
        status, body = http("POST", path, decision, reviewer)
        assert status == 200 and body["status"] == "approved" and body["mergedVersion"], (
            status,
            body,
        )
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", colleague, ["finance"])
        merged = [r for r in found["results"] if r["title"] == "Quarterly close"]
        assert merged and merged[0]["citation"] == {
            "type": "entry",
            "layer": "role",
            "entryKey": "quarterly-close",
            "pack": "finance",
            "version": body["mergedVersion"],
        }, found
        # The author's personal copy is retired on merge, so they read the pack's version too.
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", token, ["finance"])
        mine = [r for r in found["results"] if r["title"] == "Quarterly close"]
        assert [r["citation"].get("version") for r in mine] == [body["mergedVersion"]], found

        step("4. Revoked at SharePoint: hidden at the next call")
        ms.libraries["Documents"][0]["readers"] = []
        checks = len(ms.checks)
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", token, ["finance"])
        assert documents(found) == [], found
        # Delegated as before, so the empty result is SharePoint's answer, asked at this call.
        assert found["coverage"]["delegation"] == {"status": "issued", "agent": instance}, found[
            "coverage"
        ]
        assert (str(PERSON), "plan-open", 403) in ms.checks[checks:], ms.checks[checks:]

        step("5. A pack outside the agent's template returns nothing")
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", token, ["legal"])
        assert documents(found) == [] and found["coverage"]["packsOutsideAgentScope"] == [
            "legal"
        ], found
        # And on every other read an assistant can make (D60): not listed, not resolved, refused.
        me = bearer(token)
        status, body = http("GET", f"{kn}/v1/knowledge/packs", None, me)
        listed = {p["document"]["metadata"]["name"] for p in body["items"]}
        assert status == 200 and "legal" not in listed and "finance" in listed, body
        status, body = http("GET", f"{kn}/v1/knowledge/resolve?packs=legal", None, me)
        assert status == 200 and body["agentScope"]["packsOutsideAgentScope"] == ["legal"], body
        for path in ("legal", "legal/versions"):
            status, _ = http("GET", f"{kn}/v1/knowledge/packs/{path}", None, me)
            assert status == 403, (path, status)

        step("6. HR leaver: agent suspended, key revoked, no delegation, the layer is reviewed")
        ms.libraries["Documents"][0]["readers"] = [str(PERSON)]
        status, body = http("POST", f"{kn}/v1/knowledge/personal/entries", NOTE, bearer(token))
        assert status == 201, (status, body)
        status, body = http(
            "POST", f"{kn}/v1/knowledge/personal/entries", PRIVATE_NOTE, bearer(token)
        )
        assert status == 201 and body["private"] is True, (status, body)
        hr_event(cp, tenant, hr_secret, "leave-1", "leaver", 60)
        wait_for(
            "the agent suspended", lambda: _state(cp, operator, instance) == "suspended", timeout=90
        )
        revoked = wait_for(
            "the key revoked",
            lambda: (
                (k := http("GET", f"{cp}/v1/virtual-keys/{key_id}", None, operator)[1])
                and k.get("status") == "revoked"
                and k
            ),
            timeout=60,
        )
        assert revoked["revokeReason"] == "leaver", revoked
        attempts = ms.exchange_attempts
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", token, ["finance"])
        # The leaver is now the person's latest HR event, so their Entra link no longer stands:
        # refused at the link, before the suspended agent is even looked up.
        assert documents(found) == [] and found["coverage"]["delegation"] == {
            "status": "refused",
            "reason": "user-unlinked",
        }, found["coverage"]
        # The control plane refused: Entra was never asked to exchange the leaver's token, not even
        # in an attempt the fake would have rejected for the disabled identity.
        assert ms.exchange_attempts == attempts, "a leaver's token reached the exchange"
        # The leaver's agent identity is disabled; the colleague's stays enabled.
        assert not ms.identities[identity]["accountEnabled"], ms.identities
        assert [i["accountEnabled"] for k, i in ms.identities.items() if k != identity] == [True]
        manager = bearer(ms.user_token(MANAGER, azp=fake_microsoft.CONSOLE))
        # Not through the manager's assistant: deciding a leaver review is the console's.
        status, _ = http(
            "GET", f"{kn}/v1/knowledge/leaver-reviews", None, bearer(ms.user_token(MANAGER))
        )
        assert status == 403, status
        review = wait_for("the review opened", lambda: _review(kn, manager), timeout=60)
        assert review["status"] == "open" and review["person"] == f"entra:{PERSON}", review
        assert review["decider"] == f"entra:{MANAGER}" and review["generation"] == 2, review
        status, body = http(
            "GET", f"{kn}/v1/knowledge/leaver-reviews/{review['id']}", None, manager
        )
        assert status == 200 and sorted(e["key"] for e in body["entries"]) == NOTES, (status, body)
        assert review["entryCount"] == len(NOTES), review  # the private note is not counted
        assert PRIVATE_NOTE["body"] not in json.dumps(body), "the decider saw a private note"
        status, mine = http("GET", f"{kn}/v1/knowledge/personal/entries", None, bearer(token))
        assert status == 200 and PRIVATE_NOTE["key"] not in {e["key"] for e in mine["items"]}, (
            "the private note survived the leaving"
        )
        other = bearer(ms.user_token(OTHER, azp=fake_microsoft.CONSOLE))
        status, _ = http("GET", f"{kn}/v1/knowledge/leaver-reviews/{review['id']}", None, other)
        assert status == 404, status
        assert _frozen(kn, bearer(token)), "the leaver's layer is not frozen"
        # In the console the leaver acts no more, though their Entra account still works.
        leaver_console = bearer(ms.user_token(PERSON, azp=fake_microsoft.CONSOLE))
        status, body = http("GET", f"{kn}/v1/knowledge/personal/entries", None, leaver_console)
        assert status == 403 and "has left" in body.get("detail", ""), (status, body)

        step("7. Rehire: the review is fenced; replayed calls from the old leaving change nothing")
        hr_event(cp, tenant, hr_secret, "join-2", "joiner", 90)
        wait_for(
            "the agent active again", lambda: _state(cp, operator, instance) == "active", timeout=90
        )
        fenced = wait_for(
            "the review cancelled", lambda: _review(kn, manager, status="closed"), timeout=60
        )
        rehired = bearer(ms.user_token(PERSON, azp=fake_microsoft.CONSOLE))
        status, _ = http("GET", f"{kn}/v1/knowledge/personal/entries", None, rehired)
        assert status == 200, status  # rehired: the console acts for them again
        assert fenced["id"] == review["id"] and fenced["outcome"] == "cancelled", fenced
        assert not _frozen(kn, bearer(token)), "the rehired person's layer is still frozen"
        old = {
            "id": review["id"],
            "generation": 2,
            "person": {"user": f"entra:{PERSON}"},
            "deciders": [{"user": f"entra:{MANAGER}", "kind": "manager"}],
        }
        status, body = signed(
            kn, tenant, knowledge_secret, "/v1/knowledge/internal/leaver-reviews", old
        )
        assert status == 409 and body.get("type") == SUPERSEDED, (status, body)
        expire = f"/v1/knowledge/internal/leaver-reviews/{review['id']}/expire"
        status, body = signed(kn, tenant, knowledge_secret, expire, None)
        assert status == 200 and body["outcome"] == "cancelled", (status, body)
        assert sorted(_notes(kn, bearer(token))) == NOTES, "a replayed call touched the layer"
        assert not _frozen(kn, bearer(token))

        step("8. A second leaving ends its grace period: agent retired, undecided layer purged")
        left = time.monotonic()
        hr_event(cp, tenant, hr_secret, "leave-2", "leaver", 110)
        second = wait_for(
            "the second review opened",
            lambda: (r := _review(kn, manager)) and r["id"] != review["id"] and r,
            timeout=90,
        )
        assert second["generation"] == 4 and second["status"] == "open", second
        wait_for(
            "the layer purged", lambda: _notes(kn, bearer(token)) == [], timeout=GRACE_SECONDS + 90
        )
        # By the workflow's expiry after the grace period, not earlier.
        assert time.monotonic() - left >= GRACE_SECONDS, time.monotonic() - left
        closed = _review(kn, manager, status="closed", review_id=second["id"])
        assert closed and closed["outcome"] == "expired", closed
        wait_for(
            "the agent retired", lambda: _state(cp, operator, instance) == "retired", timeout=60
        )
        # The leaver's layer is gone, and what they taught that was merged stays with the company.
        found = anyio.run(mcp_search, f"{kn}/mcp/knowledge/", colleague, ["finance"])
        kept = [r for r in found["results"] if r["title"] == "Quarterly close"]
        assert [r["citation"].get("pack") for r in kept] == ["finance"], found

        # Every read the person made was recorded with the assistant it came through.
        with psycopg.connect(kdb) as conn, conn.transaction():
            conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (tenant,))
            via = {r[0] for r in conn.execute("SELECT assistant FROM knowledge.reads").fetchall()}
        assert via == {"Claude"}, via

        step("9. Evidence verifies in both services")
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
            "personal-layer.review-opened",
            "personal-layer.review-fenced",
            "personal-layer.review-closed",
            "gateway.key.issued",
            "gateway.key.revoked",
            "credentials.revoked",
        ):
            assert action in actions, (action, sorted(set(actions)))
        assert "personal-layer.review-not-opened" not in actions, "a live review was not opened"
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


PERSON_HR = {
    "id": "E-1001",
    "email": "person@example.invalid",
    "jobCode": "ANALYST",
    "managerEmail": "Manager@example.invalid",
}
COLLEAGUE_HR = {"id": "E-2002", "email": "colleague@example.invalid", "jobCode": "ANALYST"}
MANAGER_HR = {"id": "E-3003", "email": "manager@example.invalid", "jobCode": "MANAGER"}
SUPERSEDED = "https://muistamo.dev/problems/superseded"


def hr_event(
    cp: str, tenant: str, secret: str, event_id: str, kind: str, offset: int, person=PERSON_HR
) -> None:
    occurred = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 120 + offset))
    body = json.dumps(
        {"id": event_id, "type": kind, "occurredAt": occurred, "person": person}
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


def documents(found: dict) -> list[dict]:
    """The SharePoint results of a search: what per-person source authorisation decides."""
    return [r for r in found["results"] if r["citation"]["type"] == "document"]


def bearer(token: str) -> dict:
    return {"Authorization": "Bearer " + token}


def _link(url: str, tenant: str, person: str) -> str | None:
    with psycopg.connect(url) as conn, conn.transaction():
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (tenant,))
        row = conn.execute(
            "SELECT status FROM person_entra_links WHERE person_id = %s", (person,)
        ).fetchone()
    return row[0] if row else None


def _review(kn: str, decider: dict, status: str = "open", review_id: str | None = None):
    """The decider's newest review with this status (and id), if any."""
    code, body = http("GET", f"{kn}/v1/knowledge/leaver-reviews", None, decider)
    assert code == 200, (code, body)
    for item in body["items"]:
        if item["status"] == status and review_id in (None, item["id"]):
            return item
    return None


def _notes(kn: str, person: dict) -> list[str]:
    code, body = http("GET", f"{kn}/v1/knowledge/personal/entries", None, person)
    assert code == 200, (code, body)
    return [e["key"] for e in body["items"]]


def _frozen(kn: str, person: dict) -> bool:
    """Whether the person's layer refuses a new entry (it is under review)."""
    probe = {"key": f"probe-{secrets.token_hex(4)}", "type": "fact", "title": "p", "body": "b"}
    code, body = http("POST", f"{kn}/v1/knowledge/personal/entries", probe, person)
    assert code in (201, 409), (code, body)
    if code == 201:
        gone, _ = http("DELETE", f"{kn}/v1/knowledge/personal/entries/{body['id']}", None, person)
        assert gone == 204, gone
    return code == 409


def signed(kn: str, tenant: str, secret: str, path: str, body: dict | None):
    """A service call signed as the control plane signs it, to replay one by hand."""
    from muistamo_knowledge import auth

    raw = json.dumps(body).encode() if body is not None else b""
    return http(
        "POST",
        kn + path,
        raw,
        {
            "X-Muistamo-Tenant": tenant,
            "X-Muistamo-Signature": auth.sign(secret.encode(), raw, method="POST", path=path),
            "Content-Type": "application/json",
        },
    )


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
