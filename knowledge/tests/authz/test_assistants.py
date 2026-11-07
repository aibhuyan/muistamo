"""Adversarial suite: which assistants may reach a tenant's knowledge (docs/assistants-plan.md,
PR 2). An Entra token names the client app that obtained it (azp); only an app the tenant's
operator allowed is accepted, at sign-in and on every call, and each read records it by name.
Never skip or weaken.
"""

from __future__ import annotations

import subprocess
import sys
import uuid

import psycopg
import pytest
from muistamo_knowledge import entra, oauth

pytestmark = pytest.mark.authz

PERSON = uuid.UUID("9a000000-0000-4000-8000-00000000000a")
OTHER_APP = uuid.UUID("9a000000-0000-4000-8000-0000000000ff")
NOTE = {"key": "k", "type": "fact", "title": "Quarterly close", "body": "Quarterly close day 5."}


def allowed(ew) -> uuid.UUID:
    return uuid.UUID(ew.directory.claims(PERSON)["azp"])


def test_a_token_from_an_assistant_the_tenant_did_not_allow_is_refused(entra_world) -> None:
    ew = entra_world
    for token in (
        ew.directory.token(PERSON, azp=str(OTHER_APP)),  # a real client, not on the list
        ew.directory.token(PERSON, azp=None),  # no client named at all
        ew.directory.token(PERSON, azp="not-a-uuid"),
    ):
        res = ew.client(token).get("/v1/knowledge/personal/entries")
        assert res.status_code == 401, res.text
        assert ew.mcp_refusal(token)[0] == 401
    assert (
        ew.client(ew.directory.token(PERSON)).get("/v1/knowledge/personal/entries").status_code
        == 200
    )


def test_removing_an_assistant_refuses_its_next_call(entra_world) -> None:
    ew = entra_world
    token = ew.directory.token(PERSON)
    client = ew.client(token)
    assert client.get("/v1/knowledge/personal/entries").status_code == 200
    assert entra.remove_assistant(ew.world.db.owner_url, ew.world.tenant, allowed(ew))
    assert client.get("/v1/knowledge/personal/entries").status_code == 401  # not cached


def test_an_assistant_allowed_in_another_tenant_is_not_allowed_here(entra_world) -> None:
    ew = entra_world
    entra.allow_assistant(ew.world.db.owner_url, ew.world.other_tenant, OTHER_APP, "Elsewhere")
    token = ew.directory.token(PERSON, azp=str(OTHER_APP))
    assert ew.client(token).get("/v1/knowledge/personal/entries").status_code == 401


def test_each_read_records_the_assistant_by_name(entra_world) -> None:
    ew = entra_world
    entra.allow_assistant(ew.world.db.owner_url, ew.world.tenant, allowed(ew), "Claude")
    client = ew.client(ew.directory.token(PERSON))
    assert client.post("/v1/knowledge/personal/entries", json=NOTE).status_code == 201
    assert client.get("/v1/knowledge/retrieve", params={"q": "quarterly"}).status_code == 200
    with psycopg.connect(ew.world.db.owner_url) as conn, conn.transaction():
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(ew.world.tenant),))
        rows = conn.execute("SELECT person, assistant FROM knowledge.reads").fetchall()
    assert rows == [(f"entra:{PERSON}", "Claude")], rows


def test_the_server_role_cannot_read_or_change_the_allowlist(entra_world) -> None:
    world = entra_world.world
    with psycopg.connect(world.db.app_url) as conn:
        conn.execute("SELECT set_config('muistamo.tenant_id', %s, false)", (str(world.tenant),))
        for sql in (
            "SELECT * FROM knowledge.assistants",
            "INSERT INTO knowledge.assistants (tenant_id, client_app, name)"
            f" VALUES ('{world.tenant}', '{OTHER_APP}', 'Sneaky')",
            "DELETE FROM knowledge.assistants",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql)
            conn.rollback()
            conn.execute("SELECT set_config('muistamo.tenant_id', %s, false)", (str(world.tenant),))
        # Only the lookup function, which names one app's assistant for one tenant.
        found = conn.execute(
            "SELECT name, kind FROM knowledge.entra_client(%s, %s)",
            (world.tenant, allowed(entra_world)),
        ).fetchall()
        assert found == [("Test assistant", "assistant")]
        other = conn.execute(
            "SELECT name, kind FROM knowledge.entra_client(%s, %s)",
            (world.other_tenant, allowed(entra_world)),
        ).fetchall()
        assert other == []


@pytest.mark.parametrize("name", ["", "x" * 101, "bad\nname"])
def test_an_assistant_name_must_be_printable(entra_world, name) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        entra.allow_assistant(
            entra_world.world.db.owner_url, entra_world.world.tenant, OTHER_APP, name
        )


def test_sign_in_refuses_an_assistant_the_tenant_did_not_allow(entra_world, monkeypatch) -> None:
    monkeypatch.setenv("MUISTAMO_KNOWLEDGE_PUBLIC_URL", "https://knowledge.example.invalid")
    calls = []
    monkeypatch.setattr(
        oauth, "entra_transport", lambda url, form: calls.append(url) or (200, b"{}")
    )
    ew, tenant = entra_world, entra_world.world.tenant
    resource = f"https://knowledge.example.invalid/mcp/t/{tenant}/knowledge"
    authorize = ew.client(None).get(
        f"/oauth/t/{tenant}/authorize",
        params={
            "response_type": "code",
            "client_id": str(OTHER_APP),
            "redirect_uri": "https://assistant.example.invalid/callback",
            "scope": "Knowledge.Read",
            "code_challenge": "c" * 43,
            "code_challenge_method": "S256",
            "resource": resource,
        },
        follow_redirects=False,
    )
    assert authorize.status_code == 400 and authorize.json()["error"] == "unauthorized_client"
    token = ew.client(None).post(
        f"/oauth/t/{tenant}/token",
        data={
            "grant_type": "refresh_token",
            "client_id": str(OTHER_APP),
            "refresh_token": "x",
            "resource": resource,
        },
    )
    assert token.status_code == 400 and token.json()["error"] == "unauthorized_client"
    assert calls == []


def test_the_operator_command_manages_the_allowlist(entra_world, monkeypatch) -> None:
    world = entra_world.world
    env = {"MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL": world.db.owner_url}

    def cli(*args: str) -> subprocess.CompletedProcess:
        import os

        return subprocess.run(  # noqa: S603 - this test's own fixed command
            [sys.executable, "-m", "muistamo_knowledge", "tenant", "assistant", *args],
            env={**os.environ, **env},
            capture_output=True,
            text=True,
            timeout=60,
        )

    tenant = str(world.tenant)
    assert cli("add", tenant, str(OTHER_APP), "Copilot").returncode == 0
    listed = cli("list", tenant)
    assert f"{OTHER_APP}\tCopilot" in listed.stdout, listed.stdout
    assert cli("add", tenant, str(OTHER_APP).upper(), "Copilot").returncode != 0  # canonical only
    assert cli("add", tenant, "not-a-uuid", "Copilot").returncode != 0
    assert cli("add", tenant, str(uuid.uuid4()), "bad\tname").returncode != 0
    assert cli("remove", tenant, str(OTHER_APP)).returncode == 0
    assert cli("remove", tenant, str(OTHER_APP)).returncode != 0  # was not allowed any more
    assert f"{OTHER_APP}" not in cli("list", tenant).stdout


def test_a_refused_assistant_is_logged_for_the_operator_without_the_token(
    entra_world, caplog
) -> None:
    """After an upgrade, a tenant with no assistants added refuses every Entra caller: the log
    says why (tenant and client app), and never carries the token."""
    import logging

    token = entra_world.directory.token(PERSON, azp=str(OTHER_APP))
    with caplog.at_level(logging.WARNING, logger="muistamo_knowledge.entra"):
        assert entra_world.client(token).get("/v1/knowledge/personal/entries").status_code == 401
    refused = [r for r in caplog.records if "assistant is not allowed" in r.getMessage()]
    assert refused and refused[0].client_app == str(OTHER_APP)
    assert refused[0].tenant == str(entra_world.world.tenant)
    assert all(token not in r.getMessage() and token not in str(r.__dict__) for r in caplog.records)
