"""Entra authentication of knowledge callers (PR C). HUMAN REVIEW REQUIRED: token validation."""

from __future__ import annotations

import http.client
import json
import time
import uuid

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from muistamo_knowledge import entra
from muistamo_knowledge.auth import Unauthenticated

PERSON = uuid.UUID("6f1c2a3b-0000-4000-8000-00000000000a")
OTHER = uuid.UUID("6f1c2a3b-0000-4000-8000-00000000000b")
TENANT = uuid.UUID("11111111-1111-4111-8111-111111111111")
# As registered by the entra_world fixture (conftest.py).
DIRECTORY = uuid.UUID("33333333-3333-4333-8333-333333333333")
AUDIENCE = uuid.UUID("44444444-4444-4444-8444-444444444444")


def resolver(directory, clock=time.time) -> entra.EntraBearer:
    registered = {DIRECTORY: entra.Registration(TENANT, AUDIENCE)}
    return entra.EntraBearer(registered.get, fetch=directory.fetch, clock=clock)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": "Bearer " + token}


def test_a_persons_token_resolves_to_their_tenant_and_user(new_directory) -> None:
    directory = new_directory()
    assert resolver(directory)(bearer(directory.token(PERSON))) == (TENANT, f"entra:{PERSON}")
    # Header names are case-insensitive, and so is the scheme.
    assert resolver(directory)({"authorization": "bearer " + directory.token(PERSON)})[0] == TENANT


def _symmetric(directory) -> str:
    return jwt.encode(
        directory.claims(PERSON),
        "obviously-fake-hmac-key-0123456789abcdef",
        algorithm="HS256",
        headers={"kid": directory.kid},
    )


def _unsigned(directory) -> str:
    head, body, _ = directory.token(PERSON).split(".")
    return f"{head}.{body}."


def _tampered(directory) -> str:
    head, _, sig = directory.token(PERSON).split(".")
    other = directory.token(OTHER).split(".")[1]
    return f"{head}.{other}.{sig}"


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(
            lambda d: d.token(
                PERSON, key=rsa.generate_private_key(public_exponent=65537, key_size=2048)
            ),
            id="another key, same id",
        ),
        pytest.param(lambda d: d.token(PERSON, kid="unknown-key"), id="unknown key id"),
        pytest.param(_symmetric, id="symmetric algorithm"),
        pytest.param(_unsigned, id="unsigned"),
        pytest.param(_tampered, id="tampered claims"),
        pytest.param(lambda d: d.token(PERSON, exp=int(time.time()) - 120), id="expired"),
        pytest.param(lambda d: d.token(PERSON, nbf=int(time.time()) + 300), id="not yet valid"),
        pytest.param(lambda d: d.token(PERSON, exp=None), id="no expiry"),
        pytest.param(lambda d: d.token(PERSON, nbf=None), id="no not-before"),
        pytest.param(
            lambda d: d.token(PERSON, aud="https://graph.microsoft.com"), id="another audience"
        ),
        pytest.param(lambda d: d.token(PERSON, aud=[str(AUDIENCE), "other"]), id="two audiences"),
        pytest.param(
            lambda d: d.token(PERSON, iss=f"https://login.microsoftonline.com/{uuid.uuid4()}/v2.0"),
            id="another issuer",
        ),
        pytest.param(lambda d: d.token(PERSON, tid=str(uuid.uuid4())), id="unregistered directory"),
        pytest.param(
            lambda d: d.token(PERSON, tid="{" + str(DIRECTORY) + "}"), id="directory not canonical"
        ),
        pytest.param(lambda d: d.token(PERSON, ver="1.0"), id="version 1.0"),
        pytest.param(
            lambda d: d.token(PERSON, scp=None, roles=["Knowledge.Read"]), id="no scope (app-only)"
        ),
        pytest.param(
            lambda d: d.token(PERSON, scp="Knowledge.ReadAll User.Read"), id="another scope"
        ),
        pytest.param(lambda d: d.token(PERSON, idtyp="app"), id="app token type"),
        pytest.param(lambda d: d.token(PERSON, oid="not-a-uuid"), id="user id not a uuid"),
        pytest.param(
            lambda d: d.token(PERSON, oid=str(PERSON).upper()), id="user id not canonical"
        ),
        pytest.param(lambda d: d.token(PERSON) + "A" * entra.MAX_TOKEN, id="oversized"),
        pytest.param(lambda d: "obviously-fake-not-a-jwt", id="not a token"),
    ],
)
def test_tokens_that_are_not_a_persons_token_for_muistamo_are_refused(make, new_directory) -> None:
    directory = new_directory()
    with pytest.raises(Unauthenticated):
        resolver(directory)(bearer(make(directory)))


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Basic b2JpdmlvdXNseTpmYWtl"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer a b"},
        # Development headers are never read by the Entra resolver.
        {"X-Muistamo-Tenant": str(TENANT), "X-Muistamo-Actor": "person@example.invalid"},
    ],
)
def test_requests_without_one_bearer_token_are_refused(headers, new_directory) -> None:
    with pytest.raises(Unauthenticated):
        resolver(new_directory())(headers)


def test_a_valid_token_is_accepted_only_as_a_bounded_bearer_credential(new_directory) -> None:
    directory = new_directory()
    r = resolver(directory)
    with pytest.raises(Unauthenticated):
        r({"Authorization": "Basic " + directory.token(PERSON)})
    # Validly signed, but larger than any token Entra issues.
    with pytest.raises(Unauthenticated):
        r(bearer(directory.token(PERSON, padding="x" * entra.MAX_TOKEN)))


def test_signing_keys_are_fetched_at_a_bounded_rate_and_rotate(new_directory) -> None:
    directory = new_directory()
    now = [1000.0]
    r = resolver(directory, clock=lambda: now[0])
    r(bearer(directory.token(PERSON)))
    for _ in range(5):
        with pytest.raises(Unauthenticated):
            r(bearer(directory.token(PERSON, kid="unknown-key")))
    assert directory.fetches == 1
    retired, retired_kid = directory.key, directory.kid
    directory.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    directory.kid = "rotated-key"
    now[0] += entra.KEYS_MIN_REFRESH + 1
    assert r(bearer(directory.token(PERSON)))[0] == TENANT
    assert directory.fetches == 2
    # The retired key, no longer published, is no longer trusted.
    now[0] += entra.KEYS_MIN_REFRESH + 1
    with pytest.raises(Unauthenticated):
        r(bearer(directory.token(PERSON, key=retired, kid=retired_kid)))


def test_an_outage_keeps_known_keys_and_admits_no_new_one(new_directory) -> None:
    directory = new_directory()
    now = [1000.0]
    r = resolver(directory, clock=lambda: now[0])
    r(bearer(directory.token(PERSON)))

    def down(_: uuid.UUID) -> bytes:
        raise OSError("obviously fake outage")

    r._fetch = down
    now[0] += entra.KEYS_MAX_AGE + 1
    assert r(bearer(directory.token(PERSON)))[0] == TENANT
    now[0] += entra.KEYS_MIN_REFRESH + 1
    with pytest.raises(Unauthenticated):
        r(bearer(directory.token(PERSON, kid="new-key")))


def _jwk(key: rsa.RSAPrivateKey, **fields) -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(fields)
    return jwk


def test_keys_that_cannot_be_trusted_are_ignored() -> None:
    strong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # A deliberately weak key: the test proves it is refused.
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    for name, keys in {
        "too short": [_jwk(weak, kid="k")],
        "for encryption": [_jwk(strong, kid="k", use="enc")],
        "another algorithm": [_jwk(strong, kid="k", alg="PS256")],
        "duplicate id": [_jwk(strong, kid="k"), _jwk(second, kid="k")],
        "not RSA": [{"kty": "oct", "kid": "k", "k": "b2J2aW91c2x5LWZha2U"}],
        "no id": [_jwk(strong)],
    }.items():
        assert entra.usable_keys(json.dumps({"keys": keys}).encode()) == {}, name
    assert set(entra.usable_keys(json.dumps({"keys": [_jwk(strong, kid="k")]}).encode())) == {"k"}
    with pytest.raises(ValueError):
        entra.usable_keys(b"[]")


def test_the_keys_come_only_from_the_directorys_fixed_endpoint(monkeypatch) -> None:
    opened = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def __init__(self, chunks: list[bytes]) -> None:
            self.chunks = chunks

        def read(self, limit: int) -> bytes:
            return self.chunks.pop(0) if self.chunks else b""

    answer: list[bytes] = [b'{"keys": []}']
    monkeypatch.setattr(
        entra._opener,
        "open",
        lambda url, timeout: opened.append((url, timeout)) or Response(answer),
    )
    assert entra.fetch_keys(DIRECTORY) == b'{"keys": []}'
    assert opened == [
        (f"https://login.microsoftonline.com/{DIRECTORY}/discovery/v2.0/keys", entra.KEYS_TIMEOUT)
    ]
    assert any(isinstance(h, entra._NoRedirects) for h in entra._opener.handlers)
    # Too large, or too slow as a whole even when each read is quick, is refused.
    answer[:] = [b"x" * 65536] * 17
    with pytest.raises(Unauthenticated):
        entra.fetch_keys(DIRECTORY)
    clock = iter([0.0, 1.0, entra.KEYS_TIMEOUT + 1.0])
    monkeypatch.setattr(entra.time, "monotonic", lambda: next(clock))
    answer[:] = [b"{", b'"keys": []}']
    with pytest.raises(Unauthenticated):
        entra.fetch_keys(DIRECTORY)


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(lambda: http.client.IncompleteRead(b"{"), id="incomplete read"),
        pytest.param(lambda: RecursionError("deeply nested"), id="nested JSON"),
        pytest.param(lambda: RuntimeError("anything else"), id="anything"),
    ],
)
def test_any_key_fetch_failure_keeps_known_keys_and_admits_none(new_directory, failure) -> None:
    directory = new_directory()
    now = [1000.0]
    r = resolver(directory, clock=lambda: now[0])
    r(bearer(directory.token(PERSON)))

    def broken(_: uuid.UUID) -> bytes:
        raise failure()

    r._fetch = broken
    now[0] += entra.KEYS_MAX_AGE + 1
    assert r(bearer(directory.token(PERSON)))[0] == TENANT
    now[0] += entra.KEYS_MIN_REFRESH + 1
    with pytest.raises(Unauthenticated):
        r(bearer(directory.token(PERSON, kid="new-key")))


# With the database: registrations, REST and MCP.


def test_a_directory_belongs_to_one_tenant(entra_world) -> None:
    world = entra_world.world
    with pytest.raises(psycopg.errors.UniqueViolation):
        entra.register(world.db.owner_url, world.other_tenant, DIRECTORY, AUDIENCE)
    assert world.knowledge.db.entra_tenant(DIRECTORY) == (world.tenant, AUDIENCE)
    # Re-pointing a tenant is explicit, and says what it replaced.
    other = uuid.uuid4()
    with pytest.raises(entra.AlreadyRegistered):
        entra.register(world.db.owner_url, world.tenant, other, AUDIENCE)
    assert world.knowledge.db.entra_tenant(DIRECTORY) == (world.tenant, AUDIENCE)
    assert entra.register(world.db.owner_url, world.tenant, DIRECTORY, AUDIENCE) == (
        DIRECTORY,
        AUDIENCE,
    )
    assert entra.register(world.db.owner_url, world.tenant, other, AUDIENCE, replace=True) == (
        DIRECTORY,
        AUDIENCE,
    )
    assert world.knowledge.db.entra_tenant(DIRECTORY) is None
    assert world.knowledge.db.entra_tenant(uuid.uuid4()) is None


def test_entra_callers_use_the_api_as_themselves(entra_world) -> None:
    d = entra_world.directory
    person = entra_world.client(d.token(PERSON))
    note = {"key": "a-note", "type": "fact", "title": "A note", "body": "Only mine."}
    assert person.post("/v1/knowledge/personal/entries", json=note).status_code == 201
    mine = person.get("/v1/knowledge/personal/entries").json()["items"]
    assert [e["key"] for e in mine] == ["a-note"]
    # Another person of the same directory sees none of it.
    assert (
        entra_world.client(d.token(OTHER)).get("/v1/knowledge/personal/entries").json()["items"]
        == []
    )
    contributor = (
        psycopg.connect(entra_world.world.db.owner_url)
        .execute("SELECT contributor FROM knowledge.entries")
        .fetchone()[0]
    )
    assert contributor == f"entra:{PERSON}"


def test_refusals_carry_a_bearer_challenge(entra_world) -> None:
    for token in (
        None,
        "obviously-fake-not-a-jwt",
        entra_world.directory.token(PERSON, idtyp="app"),
    ):
        res = entra_world.client(token).get("/v1/knowledge/personal/entries")
        assert res.status_code == 401
        assert res.headers["WWW-Authenticate"] == 'Bearer realm="muistamo-knowledge"'
        assert "detail" not in res.json()


def test_mcp_callers_authenticate_with_their_token(entra_world) -> None:
    d = entra_world.directory
    assert "search_knowledge" in entra_world.mcp(d.token(PERSON))
    result = entra_world.mcp(d.token(PERSON), "search_knowledge", {"query": "anything"})
    assert not result.is_error
    challenge = 'Bearer realm="muistamo-knowledge"'
    assert entra_world.mcp_refusal(d.token(PERSON, scp="User.Read")) == (401, challenge)
    assert entra_world.mcp_refusal(None) == (401, challenge)
