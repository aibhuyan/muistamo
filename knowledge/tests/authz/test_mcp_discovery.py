"""Adversarial suite: a tenant's MCP endpoint, its sign-in discovery and the thin sign-in layer in
front of its Entra directory (docs/assistants-plan.md).

An assistant (Claude, Copilot, ...) is configured with a tenant's MCP URL. From a 401 it learns
where the person signs in (RFC 9728), finds the tenant's authorization server (RFC 8414), and
signs the person in with Entra through it. The endpoint serves only that tenant's people. Never
skip or weaken.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.parse
import uuid

import anyio
import httpx2
import pytest
from mcp.client.auth import OAuthClientProvider
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)
from muistamo_knowledge import entra, oauth
from muistamo_knowledge.app import create_app

pytestmark = pytest.mark.authz

PUBLIC = "https://knowledge.example.invalid"
PERSON = uuid.UUID("8b000000-0000-4000-8000-00000000000a")
CLIENT = "8c000000-0000-4000-8000-0000000000c1"  # an assistant's client, registered in Entra
REDIRECT = "https://assistant.example.invalid/callback"
ENTRA = "https://login.microsoftonline.com"


@pytest.fixture
def public(monkeypatch) -> str:
    monkeypatch.setenv("MUISTAMO_KNOWLEDGE_PUBLIC_URL", PUBLIC)
    return PUBLIC


def mcp_path(tenant) -> str:
    return f"/mcp/t/{tenant}/knowledge"


def metadata_path(tenant) -> str:
    return f"/.well-known/oauth-protected-resource/mcp/t/{tenant}/knowledge"


def issuer(tenant) -> str:
    return f"{PUBLIC}/oauth/t/{tenant}"


def raw_post(ew, path: str, token: str | None = None):
    return ew.client(token).post(
        path,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
        follow_redirects=False,
    )


def challenge_params(header: str) -> dict[str, str]:
    """RFC 6750 §3 auth-params, parsed (not substring-matched)."""
    scheme, _, rest = header.partition(" ")
    assert scheme == "Bearer", header
    params, i = {}, 0
    while i < len(rest):
        name_end = rest.index("=", i)
        name = rest[i:name_end].strip(" ,")
        assert rest[name_end + 1] == '"', header
        value_end = rest.index('"', name_end + 2)
        params[name] = rest[name_end + 2 : value_end]
        i = value_end + 1
    return params


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def authorize_params(tenant, **changes) -> dict[str, str]:
    _, challenge = pkce()
    params = {
        "response_type": "code",
        "client_id": CLIENT,
        "redirect_uri": REDIRECT,
        "scope": "Knowledge.Read offline_access",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "opaque-state",
        "resource": f"{PUBLIC}{mcp_path(tenant)}",
    }
    for name, value in changes.items():
        if value is None:
            params.pop(name, None)
        else:
            params[name] = value
    return params


# Discovery ----------------------------------------------------------------------------------


def test_the_resource_metadata_names_the_tenants_own_issuer(entra_world, public) -> None:
    tenant = entra_world.world.tenant
    res = entra_world.client(None).get(metadata_path(tenant))
    assert res.status_code == 200, res.text
    assert res.json() == {
        "resource": f"{PUBLIC}{mcp_path(tenant)}",
        "authorization_servers": [issuer(tenant)],
        "scopes_supported": ["Knowledge.Read", "offline_access"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Muistamo knowledge",
    }
    assert "max-age" in res.headers["Cache-Control"]


@pytest.mark.parametrize(
    "path",
    [
        "/.well-known/oauth-authorization-server/oauth/t/{t}",  # RFC 8414 path-inserted
        "/oauth/t/{t}/.well-known/oauth-authorization-server",  # appended, as clients also try
    ],
)
def test_the_issuer_advertises_pkce_and_no_registration(entra_world, public, path) -> None:
    tenant = entra_world.world.tenant
    res = entra_world.client(None).get(path.format(t=tenant))
    assert res.status_code == 200, res.text
    meta = res.json()
    assert meta["issuer"] == issuer(tenant)
    assert meta["authorization_endpoint"] == f"{issuer(tenant)}/authorize"
    assert meta["token_endpoint"] == f"{issuer(tenant)}/token"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert meta["response_types_supported"] == ["code"]
    assert "registration_endpoint" not in meta  # clients are registered in the customer's Entra


@pytest.mark.parametrize("which", ["unknown", "no-entra", "malformed", "not-canonical"])
def test_no_sign_in_for_a_tenant_without_a_directory(entra_world, public, which) -> None:
    tenant = {
        "unknown": uuid.uuid4(),
        "no-entra": entra_world.world.other_tenant,  # registered, but with no Entra directory
        "malformed": "not-a-tenant",
        # One URL per tenant: the canonical (lower-case) id only.
        "not-canonical": str(entra_world.world.tenant).upper(),
    }[which]
    client = entra_world.client(None)
    for path in (
        metadata_path(tenant),
        f"/.well-known/oauth-authorization-server/oauth/t/{tenant}",
        f"/oauth/t/{tenant}/authorize?" + urllib.parse.urlencode(authorize_params(tenant)),
    ):
        res = client.get(path, follow_redirects=False)
        assert res.status_code == 404, (path, res.status_code)
        assert res.headers.get("Cache-Control") == "no-store"


def test_no_sign_in_without_a_public_url(entra_world, monkeypatch) -> None:
    monkeypatch.delenv("MUISTAMO_KNOWLEDGE_PUBLIC_URL", raising=False)
    tenant = entra_world.world.tenant
    assert entra_world.client(None).get(metadata_path(tenant)).status_code == 404
    res = raw_post(entra_world, mcp_path(tenant) + "/")
    assert res.status_code == 401 and "resource_metadata" not in res.headers["WWW-Authenticate"]


@pytest.mark.parametrize(
    "value",
    [
        "http://knowledge.example.invalid",  # plain http off loopback
        "https://knowledge.example.invalid/prefix",  # a path breaks RFC 9728 well-known URLs
        'https://knowledge.example.invalid"',  # would break the quoted header parameter
        "https://user@knowledge.example.invalid",
        "ftp://knowledge.example.invalid",
    ],
)
def test_a_bad_public_url_stops_the_service_starting(entra_world, monkeypatch, value) -> None:
    monkeypatch.setenv("MUISTAMO_KNOWLEDGE_PUBLIC_URL", value)
    with pytest.raises(ValueError):
        create_app(entra_world.world.knowledge, entra_world.resolver)


def test_a_401_tells_the_assistant_where_the_person_signs_in(entra_world, public) -> None:
    tenant = entra_world.world.tenant
    res = raw_post(entra_world, mcp_path(tenant) + "/")
    assert res.status_code == 401
    params = challenge_params(res.headers["WWW-Authenticate"])
    assert params["resource_metadata"] == f"{PUBLIC}{metadata_path(tenant)}"
    assert params["scope"] == "Knowledge.Read offline_access"
    assert "error" not in params  # no token was presented
    # A presented but unusable token is invalid_token (RFC 6750 §3.1).
    bad = raw_post(entra_world, mcp_path(tenant) + "/", "not-a-token")
    assert challenge_params(bad.headers["WWW-Authenticate"])["error"] == "invalid_token"


def test_the_endpoint_answers_without_the_trailing_slash(entra_world, public) -> None:
    """The URL as the metadata names it is served, never redirected (a redirect behind a TLS
    proxy would name the internal host)."""
    res = raw_post(entra_world, mcp_path(entra_world.world.tenant))
    assert res.status_code == 401 and "location" not in res.headers


def test_a_database_failure_on_the_401_path_still_answers_401(
    entra_world, public, monkeypatch
) -> None:
    def broken(_tenant):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(entra_world.world.knowledge.db, "entra_registration", broken)
    res = raw_post(entra_world, mcp_path(entra_world.world.tenant) + "/")
    assert res.status_code == 401
    assert res.headers["WWW-Authenticate"] == 'Bearer realm="muistamo-knowledge"'


# Authorize ----------------------------------------------------------------------------------


def test_authorize_sends_the_person_to_their_entra_without_resource(entra_world, public) -> None:
    tenant = entra_world.world.tenant
    params = authorize_params(tenant)
    res = entra_world.client(None).get(
        f"/oauth/t/{tenant}/authorize", params=params, follow_redirects=False
    )
    assert res.status_code == 302, res.text
    target = urllib.parse.urlsplit(res.headers["Location"])
    directory = entra_world.directory.directory
    assert f"{target.scheme}://{target.netloc}{target.path}" == (
        f"{ENTRA}/{directory}/oauth2/v2.0/authorize"
    )
    audience = entra_world.directory.claims(PERSON)["aud"]
    assert dict(urllib.parse.parse_qsl(target.query)) == {
        "client_id": CLIENT,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": f"{audience}/Knowledge.Read offline_access",  # any App ID URI
        "code_challenge": params["code_challenge"],
        "code_challenge_method": "S256",
        "state": "opaque-state",
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"code_challenge_method": "plain"},
        {"code_challenge": None},
        {"code_challenge_method": None},
        {"response_type": "token"},
        {"client_id": "not-an-app-id"},
        {"client_id": CLIENT.upper()},
        {"redirect_uri": None},
        {"resource": f"{PUBLIC}/mcp/t/{uuid.uuid4()}/knowledge"},  # another tenant's endpoint
        {"resource": "https://elsewhere.example.invalid/mcp"},
        {"scope": "Knowledge.Read Files.ReadWrite.All"},  # nothing but the knowledge scope
        {"scope": "offline_access"},
    ],
)
def test_authorize_refuses_and_never_redirects(entra_world, public, changes) -> None:
    tenant = entra_world.world.tenant
    res = entra_world.client(None).get(
        f"/oauth/t/{tenant}/authorize",
        params=authorize_params(tenant, **changes),
        follow_redirects=False,
    )
    assert res.status_code == 400, (changes, res.status_code, res.text)
    assert "location" not in res.headers


# Token --------------------------------------------------------------------------------------


class FakeEntraToken:
    """Entra's token endpoint for the tests: records what it is sent, answers as given."""

    def __init__(self, status: int = 200, body: bytes = b'{"access_token": "t"}') -> None:
        self.status, self.body, self.calls = status, body, []

    def __call__(self, url: str, form: bytes):
        self.calls.append((url, dict(urllib.parse.parse_qsl(form.decode()))))
        return self.status, self.body


@pytest.fixture
def entra_token(monkeypatch) -> FakeEntraToken:
    fake = FakeEntraToken()
    monkeypatch.setattr(oauth, "entra_transport", fake)
    return fake


def token_form(tenant, **changes) -> dict[str, str]:
    form = {
        "grant_type": "authorization_code",
        "client_id": CLIENT,
        "code": "entra-code",
        "redirect_uri": REDIRECT,
        "code_verifier": "v" * 50,
        "resource": f"{PUBLIC}{mcp_path(tenant)}",
    }
    for name, value in changes.items():
        if value is None:
            form.pop(name, None)
        else:
            form[name] = value
    return form


def test_the_token_request_reaches_entra_without_resource(entra_world, public, entra_token) -> None:
    tenant = entra_world.world.tenant
    res = entra_world.client(None).post(f"/oauth/t/{tenant}/token", data=token_form(tenant))
    assert res.status_code == 200 and res.json() == {"access_token": "t"}
    assert res.headers["Cache-Control"] == "no-store"
    audience = entra_world.directory.claims(PERSON)["aud"]
    [(url, sent)] = entra_token.calls
    assert url == f"{ENTRA}/{entra_world.directory.directory}/oauth2/v2.0/token"
    assert sent == {
        "grant_type": "authorization_code",
        "client_id": CLIENT,
        "scope": f"{audience}/Knowledge.Read offline_access",
        "code": "entra-code",
        "redirect_uri": REDIRECT,
        "code_verifier": "v" * 50,
    }


def test_a_refresh_and_a_basic_client_secret_reach_entra(entra_world, public, entra_token) -> None:
    tenant = entra_world.world.tenant
    basic = base64.b64encode(f"{CLIENT}:fake-secret".encode()).decode()
    form = {"grant_type": "refresh_token", "refresh_token": "entra-refresh"}
    res = entra_world.client(None).post(
        f"/oauth/t/{tenant}/token", data=form, headers={"Authorization": "Basic " + basic}
    )
    assert res.status_code == 200
    sent = entra_token.calls[0][1]
    assert sent["client_id"] == CLIENT and sent["client_secret"] == "fake-secret"  # noqa: S105
    assert sent["refresh_token"] == "entra-refresh" and "code" not in sent  # noqa: S105


def test_entras_own_refusal_is_returned_unchanged(entra_world, public, entra_token) -> None:
    entra_token.status, entra_token.body = 400, b'{"error": "invalid_grant"}'
    tenant = entra_world.world.tenant
    res = entra_world.client(None).post(f"/oauth/t/{tenant}/token", data=token_form(tenant))
    assert res.status_code == 400 and res.json() == {"error": "invalid_grant"}


@pytest.mark.parametrize(
    "changes",
    [
        {"grant_type": "client_credentials"},  # never an app token for a person
        {"grant_type": "password"},
        {"code_verifier": None},
        {"code": None},
        {"resource": f"{PUBLIC}/mcp/t/{uuid.uuid4()}/knowledge"},
        {"client_id": "not-an-app-id"},
        {"scope": "Knowledge.Read Mail.Read"},
    ],
)
def test_token_requests_are_refused_before_entra(entra_world, public, entra_token, changes) -> None:
    tenant = entra_world.world.tenant
    res = entra_world.client(None).post(
        f"/oauth/t/{tenant}/token", data=token_form(tenant, **changes)
    )
    assert res.status_code in (400, 401), (changes, res.status_code)
    assert entra_token.calls == []


def test_an_unreachable_entra_is_a_temporary_failure(entra_world, public, monkeypatch) -> None:
    def down(url, form):
        raise OSError("connection refused")

    monkeypatch.setattr(oauth, "entra_transport", down)
    tenant = entra_world.world.tenant
    res = entra_world.client(None).post(f"/oauth/t/{tenant}/token", data=token_form(tenant))
    assert res.status_code == 503 and res.json()["error"] == "temporarily_unavailable"


def test_only_entras_host_is_ever_called() -> None:
    with pytest.raises(ValueError):
        oauth.entra_transport("https://elsewhere.example.invalid/token", b"")


# The tenant binding -------------------------------------------------------------------------


def test_a_token_for_one_tenant_is_refused_at_anothers_endpoint(
    entra_world, new_directory, public
) -> None:
    world = entra_world.world
    second = new_directory(directory=uuid.uuid4(), kid="second-key")
    entra.register(world.db.owner_url, world.other_tenant, second.directory, uuid.uuid4())
    token = entra_world.directory.token(PERSON)
    res = raw_post(entra_world, mcp_path(world.other_tenant) + "/", token)
    assert res.status_code == 401, res.text
    # The challenge sends the person to tenant two's sign-in, not one's.
    params = challenge_params(res.headers["WWW-Authenticate"])
    assert params["resource_metadata"] == f"{PUBLIC}{metadata_path(world.other_tenant)}"
    # Even the tenant's own token is refused at a non-canonical spelling of its endpoint.
    upper = mcp_path(str(world.tenant).upper()) + "/"
    assert raw_post(entra_world, upper, token).status_code == 401
    for path in (mcp_path(uuid.uuid4()), mcp_path("not-a-tenant")):
        assert raw_post(entra_world, path + "/", token).status_code == 401


def test_the_shared_endpoint_is_unchanged(entra_world, public) -> None:
    res = raw_post(entra_world, "/mcp/knowledge/")
    assert res.status_code == 401 and "resource_metadata" not in res.headers["WWW-Authenticate"]


# The whole sign-in, as an MCP client does it ---------------------------------------------------


class Storage:
    """A client registered in advance (as Claude's Advanced settings or Copilot's manual OAuth
    give it), and its tokens."""

    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens) -> None:
        self.tokens = tokens

    async def get_client_info(self):
        return OAuthClientInformationFull(
            client_id=CLIENT,
            redirect_uris=[REDIRECT],
            token_endpoint_auth_method="none",  # noqa: S106 - a public client
        )

    async def set_client_info(self, info) -> None:
        raise AssertionError("no client registration is offered")


def test_an_mcp_client_signs_the_person_in_through_entra(entra_world, public, monkeypatch) -> None:
    """The MCP SDK's own OAuth client, end to end: 401 → resource metadata → issuer metadata →
    authorize (redirected to the fake Entra, which signs the person in) → token (passed to the
    fake Entra, which checks PKCE) → the MCP call with Entra's token."""
    ew, tenant = entra_world, entra_world.world.tenant
    issued: dict[str, str] = {}

    def fake_entra(url: str, form: bytes):
        sent = dict(urllib.parse.parse_qsl(form.decode()))
        verifier = sent["code_verifier"].encode()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).rstrip(b"=")
        assert "resource" not in sent and sent["code"] == issued["code"]
        assert challenge.decode() == issued["code_challenge"], "PKCE did not reach Entra intact"
        token = ew.directory.token(PERSON)
        body = f'{{"access_token": "{token}", "token_type": "Bearer", "expires_in": 3600}}'
        return 200, body.encode()

    monkeypatch.setattr(oauth, "entra_transport", fake_entra)
    app = create_app(ew.world.knowledge, ew.resolver)
    base = PUBLIC
    redirected: list[str] = []

    async def run():
        async with app.router.lifespan_context(app):
            transport = httpx2.ASGITransport(app=app)

            async def redirect_handler(url: str) -> None:
                # The assistant opens our authorize URL; we send the person to Entra.
                async with httpx2.AsyncClient(transport=transport, base_url=base) as browser:
                    res = await browser.get(url, follow_redirects=False)
                assert res.status_code == 302, res.text
                redirected.append(res.headers["location"])

            async def callback_handler() -> AuthorizationCodeResult:
                # The fake Entra signs the person in and redirects back with a code.
                query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(redirected[-1]).query))
                issued.update(
                    code="entra-code-" + secrets.token_hex(4),
                    code_challenge=query["code_challenge"],
                )
                return AuthorizationCodeResult(code=issued["code"], state=query["state"])

            auth = OAuthClientProvider(
                server_url=f"{base}{mcp_path(tenant)}",
                client_metadata=OAuthClientMetadata(
                    redirect_uris=[REDIRECT], client_name="assistant"
                ),
                storage=Storage(),
                redirect_handler=redirect_handler,
                callback_handler=callback_handler,
            )
            async with httpx2.AsyncClient(transport=transport, base_url=base, auth=auth) as http:
                async with streamable_http_client(
                    f"{base}{mcp_path(tenant)}", http_client=http
                ) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await session.initialize()
                        return sorted(t.name for t in (await session.list_tools()).tools)

    tools = anyio.run(run)
    assert tools == ["propose_knowledge", "remember", "search_knowledge"]
    entra_authorize = f"{ENTRA}/{ew.directory.directory}/oauth2/v2.0/authorize?"
    assert redirected and redirected[0].startswith(entra_authorize)


def test_dns_rebinding_protection_admits_only_the_public_host(entra_world, public) -> None:
    """With a valid token, a request whose Host is neither the public host nor loopback is
    refused by the MCP transport (DNS rebinding)."""
    token = entra_world.directory.token(PERSON)
    path = mcp_path(entra_world.world.tenant) + "/"
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    accept = {"Accept": "application/json, text/event-stream"}
    # As a context manager, so the app's lifespan (the MCP session manager) runs.
    with entra_world.client(token) as client:
        ok = client.post(path, json=body, headers={**accept, "Host": "knowledge.example.invalid"})
        assert ok.status_code == 200, ok.text
        bad = client.post(path, json=body, headers={**accept, "Host": "attacker.example.invalid"})
        assert bad.status_code == 421, bad.status_code


@pytest.mark.parametrize(
    "grant", ["client_credentials", "password", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
)
def test_no_other_grant_ever_reaches_entra(entra_world, public, entra_token, grant) -> None:
    """Never an app token, a password or an exchanged token through this layer, even with every
    field another grant would need."""
    tenant = entra_world.world.tenant
    form = token_form(tenant, grant_type=grant, refresh_token="x", client_secret="fake")  # noqa: S106
    res = entra_world.client(None).post(f"/oauth/t/{tenant}/token", data=form)
    assert res.status_code == 400 and res.json()["error"] == "unsupported_grant_type"
    assert entra_token.calls == []


def test_one_client_authentication_method_and_one_client(entra_world, public, entra_token) -> None:
    tenant = entra_world.world.tenant
    basic = "Basic " + base64.b64encode(f"{CLIENT}:fake-secret".encode()).decode()
    url = f"/oauth/t/{tenant}/token"
    client = entra_world.client(None)
    both = client.post(
        url,
        data=token_form(tenant, client_secret="other"),  # noqa: S106 - a fake secret
        headers={"Authorization": basic},
    )
    assert both.status_code == 400 and both.json()["error"] == "invalid_request"
    other = str(uuid.uuid4())
    mismatch = client.post(
        url, data=token_form(tenant, client_id=other), headers={"Authorization": basic}
    )
    assert mismatch.status_code == 400 and mismatch.json()["error"] == "invalid_request"
    assert entra_token.calls == []


def test_an_entra_answer_that_is_not_json_is_a_temporary_failure(
    entra_world, public, entra_token
) -> None:
    entra_token.status, entra_token.body = 502, b"<html>Bad gateway</html>"
    tenant = entra_world.world.tenant
    res = entra_world.client(None).post(f"/oauth/t/{tenant}/token", data=token_form(tenant))
    assert res.status_code == 503 and res.json()["error"] == "temporarily_unavailable"


def test_the_registration_cache_is_bounded() -> None:
    lookups = []
    signin = oauth.SignIn(PUBLIC, lambda t: lookups.append(t))
    for _ in range(oauth.CACHE_ENTRIES + 50):
        assert signin.registered(uuid.uuid4()) is None
    assert len(signin._cache) == oauth.CACHE_ENTRIES
    assert len(lookups) == oauth.CACHE_ENTRIES + 50


def test_entras_answer_is_bounded_in_time_and_size(monkeypatch) -> None:
    class Slow:
        def __init__(self, chunks):
            self.chunks = list(chunks)

        def read(self, _n):
            return self.chunks.pop(0) if self.chunks else b""

    with pytest.raises(OSError):  # too slow as a whole, whatever each read takes
        oauth._bounded(Slow([b"{", b"}"]), deadline=0)
    with pytest.raises(ValueError):
        oauth._bounded(Slow([b"x" * (oauth.MAX_BODY + 1)]), deadline=float("inf"))
