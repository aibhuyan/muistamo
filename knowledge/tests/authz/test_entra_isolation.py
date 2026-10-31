"""Adversarial suite for Entra callers (PR C). Never skip or weaken (CLAUDE.md)."""

import uuid

import psycopg
import pytest
from muistamo_knowledge import entra
from muistamo_knowledge.__main__ import caller_modes
from muistamo_knowledge.auth import Unauthenticated

pytestmark = pytest.mark.authz

PERSON = uuid.UUID("6f1c2a3b-0000-4000-8000-00000000000a")
NOTE = {"key": "a-note", "type": "fact", "title": "A note", "body": "Tenant one's note."}


def test_a_token_reaches_only_its_directorys_tenant(entra_world, new_directory) -> None:
    world = entra_world.world
    # Tenant two has its own directory; the same object id there is another person's token.
    second = new_directory(directory=uuid.uuid4(), kid="second-key")
    entra.register(world.db.owner_url, world.other_tenant, second.directory, uuid.uuid4())
    keys = {entra_world.directory.directory: entra_world.directory, second.directory: second}
    resolver = entra.EntraBearer(
        entra.registrations(world.knowledge.db), fetch=lambda d: keys[d].fetch(d)
    )
    one = entra_world.client(entra_world.directory.token(PERSON))
    assert one.post("/v1/knowledge/personal/entries", json=NOTE).status_code == 201
    # A token of directory one, presented with tenant two's audience or directory, is refused.
    with pytest.raises(Unauthenticated):
        resolver(
            {
                "Authorization": "Bearer "
                + entra_world.directory.token(PERSON, tid=str(second.directory))
            }
        )
    with pytest.raises(Unauthenticated):
        resolver({"Authorization": "Bearer " + second.token(PERSON)})  # wrong audience for two
    # Development headers naming tenant two are ignored: the token decides the tenant.
    res = one.get(
        "/v1/knowledge/personal/entries",
        headers={
            "X-Muistamo-Tenant": str(world.other_tenant),
            "X-Muistamo-Actor": "x@example.invalid",
        },
    )
    assert [e["key"] for e in res.json()["items"]] == ["a-note"]


def test_directories_sharing_entra_signing_keys_stay_apart(entra_world, new_directory) -> None:
    """Entra publishes the same keys at every directory's endpoint, so only the issuer, tenant and
    audience keep one directory's tokens out of another tenant."""
    world = entra_world.world
    one = entra_world.directory
    two_id, two_audience = uuid.uuid4(), uuid.uuid4()
    entra.register(world.db.owner_url, world.other_tenant, two_id, two_audience)
    two = new_directory(directory=two_id, kid=one.kid)
    two.key = one.key
    resolver = entra.EntraBearer(
        entra.registrations(world.knowledge.db), fetch=lambda d: one.fetch(one.directory)
    )
    issuer_one = f"https://login.microsoftonline.com/{one.directory}/v2.0"
    for name, token in {
        "tenant two, issuer one": one.token(PERSON, tid=str(two_id), aud=str(two_audience)),
        "directory two, audience one": two.token(PERSON),
        "directory one, audience two": one.token(PERSON, aud=str(two_audience)),
        "issuer one claims tenant two": two.token(PERSON, iss=issuer_one, aud=str(two_audience)),
        "an ID token for the blueprint": one.token(PERSON, scp=None),
    }.items():
        with pytest.raises(Unauthenticated):
            resolver({"Authorization": "Bearer " + token})
        assert name
    # Each directory's own token still resolves to its own tenant.
    assert resolver({"Authorization": "Bearer " + one.token(PERSON)})[0] == world.tenant
    assert (
        resolver({"Authorization": "Bearer " + two.token(PERSON, aud=str(two_audience))})[0]
        == world.other_tenant
    )


def test_app_only_and_unregistered_tokens_never_act_for_anyone(entra_world) -> None:
    d = entra_world.directory
    for token in (
        d.token(PERSON, scp=None, roles=["Knowledge.Read"], idtyp="app"),
        d.token(PERSON, tid=str(uuid.uuid4())),
    ):
        assert entra_world.client(token).get("/v1/knowledge/personal/entries").status_code == 401
        assert entra_world.mcp_refusal(token)[0] == 401


def test_the_server_role_reads_registrations_only_by_directory(entra_world) -> None:
    world = entra_world.world
    with psycopg.connect(world.db.app_url) as conn:
        for sql in (
            "SELECT count(*) FROM knowledge.entra_tenants",
            "INSERT INTO knowledge.entra_tenants (tenant_id, entra_tenant_id, audience) VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid())",
            "UPDATE knowledge.entra_tenants SET audience = gen_random_uuid()",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute(sql)
        row = conn.execute(
            "SELECT * FROM knowledge.entra_tenant(%s)", (entra_world.directory.directory,)
        ).fetchone()
        assert row[0] == world.tenant
        assert (
            conn.execute(
                "SELECT count(*) FROM knowledge.entra_tenant(%s)", (uuid.uuid4(),)
            ).fetchone()[0]
            == 0
        )


def test_entra_and_development_headers_are_never_combined(monkeypatch) -> None:
    monkeypatch.setenv("MUISTAMO_INSECURE_DEV_TENANT_HEADER", "true")
    monkeypatch.setenv("MUISTAMO_KNOWLEDGE_ENTRA", "true")
    with pytest.raises(SystemExit):
        caller_modes()
    monkeypatch.setenv("MUISTAMO_INSECURE_DEV_TENANT_HEADER", "false")
    assert caller_modes() == (False, True)
