"""A tenant's sign-in for assistants: a thin OAuth layer in front of its Entra directory
(docs/assistants-plan.md).

HUMAN REVIEW REQUIRED (CLAUDE.md): token handling.

MCP clients (Claude, Copilot, ...) follow the MCP authorization spec: they send RFC 8707
`resource` and require an authorization server that advertises PKCE S256. Entra v2 rejects a
`resource` that does not match the scope, and its metadata advertises no PKCE. So each tenant has
an issuer here, `<public>/oauth/t/<tenant>`, whose metadata says what MCP clients need. Its
authorize and token endpoints pass the request through to the tenant's Entra:
- the `resource` is checked against this tenant's MCP URL, then dropped;
- the scope is mapped to the Entra one;
- the client, its redirect URI, the person's sign-in and the token stay Entra's.

The access token is Entra's own, so EntraBearer checks it exactly as before. Authorization codes
and tokens pass through here and are never logged or stored. Dynamic client registration is not
offered: a client is registered in advance in the customer's Entra.
"""

from __future__ import annotations

import base64
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

log = logging.getLogger("muistamo.knowledge")

ENTRA = "https://login.microsoftonline.com"
KNOWLEDGE_SCOPE = "Knowledge.Read"
OFFLINE = "offline_access"
SCOPES = (KNOWLEDGE_SCOPE, OFFLINE)  # what a client may ask for
TIMEOUT = 10  # seconds, for Entra's token endpoint
MAX_BODY = 64 * 1024
CACHE_SECONDS = 60  # registrations, found or not: the unauthenticated endpoints read them

# A tenant's (directory, audience), or None (migration 0011's knowledge.entra_registration).
RegistrationLookup = Callable[[UUID], "tuple[UUID, UUID] | None"]
# POST form to url → (status, body). Tests replace it; in production Entra, nothing else.
Transport = Callable[[str, bytes], "tuple[int, bytes]"]


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_opener = urllib.request.build_opener(_NoRedirects(), urllib.request.ProxyHandler({}))


def entra_transport(url: str, form: bytes) -> tuple[int, bytes]:
    """POST form to Entra's token endpoint: verified TLS, no redirects, no proxies, bounded."""
    if not url.startswith(ENTRA + "/"):
        raise ValueError("only Entra's token endpoint is called")
    request = urllib.request.Request(  # noqa: S310 - Entra's https host only, checked above
        url,
        data=form,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        with _opener.open(request, timeout=TIMEOUT) as response:
            return response.status, response.read(MAX_BODY + 1)[:MAX_BODY]
    except urllib.error.HTTPError as exc:  # Entra's own error answers (400, 401) pass through
        return exc.code, exc.read(MAX_BODY + 1)[:MAX_BODY]


def public_url(value: str | None) -> str:
    """MUISTAMO_KNOWLEDGE_PUBLIC_URL, checked: https (http only for loopback), a host and nothing
    else, since it goes into metadata and a quoted header parameter. Empty when unset."""
    if not value:
        return ""
    parts = urllib.parse.urlsplit(value.rstrip("/"))
    loopback = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if (
        parts.scheme not in ("https", "http")
        or (parts.scheme == "http" and not loopback)
        or not parts.hostname
        or parts.path
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
        or any(c in value for c in '"\\ ')
    ):
        raise ValueError(
            "MUISTAMO_KNOWLEDGE_PUBLIC_URL must be https://<host>[:port], with no path"
        )
    return f"{parts.scheme}://{parts.netloc}"


class OAuthError(Exception):
    """An OAuth error answer (RFC 6749 §5.2): status, error code and a description."""

    def __init__(self, status: int, error: str, description: str) -> None:
        super().__init__(description)
        self.status, self.error, self.description = status, error, description


@dataclass(frozen=True)
class Redirect:
    location: str


class SignIn:
    def __init__(
        self,
        public: str,
        registration: RegistrationLookup,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.public = public
        self._registration = registration
        self._transport = transport
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: dict[UUID, tuple[float, tuple[UUID, UUID] | None]] = {}

    # Names ------------------------------------------------------------------------------------

    def resource(self, tenant: UUID) -> str:
        return f"{self.public}/mcp/t/{tenant}/knowledge"

    def issuer(self, tenant: UUID) -> str:
        return f"{self.public}/oauth/t/{tenant}"

    def resource_metadata_url(self, tenant: UUID) -> str:
        return f"{self.public}/.well-known/oauth-protected-resource/mcp/t/{tenant}/knowledge"

    def registered(self, tenant: UUID) -> tuple[UUID, UUID] | None:
        """The tenant's (directory, audience) when sign-in is offered, else None. Cached briefly,
        found or not, since the unauthenticated endpoints read it."""
        if not self.public:
            return None
        now = self._clock()
        with self._lock:
            hit = self._cache.get(tenant)
            if hit is not None and now - hit[0] < CACHE_SECONDS:
                return hit[1]
        found = self._registration(tenant)
        with self._lock:
            self._cache[tenant] = (now, found)
        return found

    # Metadata ---------------------------------------------------------------------------------

    def protected_resource(self, tenant: UUID) -> dict[str, Any] | None:
        """RFC 9728 metadata for the tenant's MCP endpoint."""
        if self.registered(tenant) is None:
            return None
        return {
            "resource": self.resource(tenant),
            "authorization_servers": [self.issuer(tenant)],
            "scopes_supported": list(SCOPES),
            "bearer_methods_supported": ["header"],
            "resource_name": "Muistamo knowledge",
        }

    def authorization_server(self, tenant: UUID) -> dict[str, Any] | None:
        """RFC 8414 metadata for the tenant's issuer."""
        if self.registered(tenant) is None:
            return None
        issuer = self.issuer(tenant)
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            "scopes_supported": list(SCOPES),
        }

    def challenge(self, tenant: UUID, token_presented: bool) -> str | None:
        """WWW-Authenticate for a 401 at the tenant's MCP endpoint (RFC 9728 §5.1, RFC 6750)."""
        if self.registered(tenant) is None:
            return None
        error = ' error="invalid_token",' if token_presented else ""
        return (
            f'Bearer realm="muistamo-knowledge",{error}'
            f' resource_metadata="{self.resource_metadata_url(tenant)}",'
            f' scope="{" ".join(SCOPES)}"'
        )

    # Endpoints --------------------------------------------------------------------------------

    def authorize(self, tenant: UUID, params: Mapping[str, str]) -> Redirect:
        """Check the client's authorization request and send the person to sign in with the
        tenant's Entra. Entra checks the client and its redirect URI against its registration,
        so this never redirects anywhere else."""
        directory, audience = self._require(tenant)
        if params.get("response_type") != "code":
            raise OAuthError(400, "unsupported_response_type", "only the code flow is offered")
        client = _client_id(params.get("client_id"))
        redirect = params.get("redirect_uri", "")
        if not redirect:
            raise OAuthError(400, "invalid_request", "redirect_uri is required")
        challenge = params.get("code_challenge", "")
        if params.get("code_challenge_method") != "S256" or not 43 <= len(challenge) <= 128:
            raise OAuthError(400, "invalid_request", "PKCE with S256 is required")
        self._check_resource(tenant, params.get("resource"))
        scope = self._entra_scope(audience, params.get("scope"))
        forward = {
            "client_id": str(client),
            "response_type": "code",
            "redirect_uri": redirect,
            "scope": scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        for passthrough in ("state", "prompt", "login_hint"):
            if params.get(passthrough):
                forward[passthrough] = params[passthrough]
        query = urllib.parse.urlencode(forward)
        return Redirect(f"{ENTRA}/{directory}/oauth2/v2.0/authorize?{query}")

    def token(
        self, tenant: UUID, form: Mapping[str, str], authorization: str | None
    ) -> tuple[int, bytes]:
        """Forward an authorization-code or refresh-token grant to the tenant's Entra and return
        its answer unchanged. Nothing of the request or the answer is logged."""
        directory, audience = self._require(tenant)
        grant = form.get("grant_type")
        if grant not in ("authorization_code", "refresh_token"):
            raise OAuthError(400, "unsupported_grant_type", "authorization_code or refresh_token")
        self._check_resource(tenant, form.get("resource"))
        client_id, secret = form.get("client_id"), form.get("client_secret")
        if authorization:  # client_secret_basic, sent to Entra as client_secret_post
            client_id, secret = _basic(authorization, client_id)
        forward = {
            "grant_type": grant,
            "client_id": str(_client_id(client_id)),
            "scope": self._entra_scope(audience, form.get("scope")),
        }
        if secret:
            forward["client_secret"] = secret
        names = (
            ("code", "redirect_uri", "code_verifier")
            if grant == "authorization_code"
            else ("refresh_token",)
        )
        for name in names:
            if not form.get(name):
                raise OAuthError(400, "invalid_request", f"{name} is required")
            forward[name] = form[name]
        url = f"{ENTRA}/{directory}/oauth2/v2.0/token"
        try:
            send = self._transport or entra_transport  # looked up per call: tests substitute it
            return send(url, urllib.parse.urlencode(forward).encode())
        except (OSError, ValueError) as exc:
            log.warning("Entra token endpoint unreachable", extra={"tenant": str(tenant)})
            raise OAuthError(
                503, "temporarily_unavailable", "the sign-in service is unavailable"
            ) from exc

    # Helpers ----------------------------------------------------------------------------------

    def _require(self, tenant: UUID) -> tuple[UUID, UUID]:
        found = self.registered(tenant)
        if found is None:
            raise OAuthError(404, "invalid_request", "no sign-in for this tenant")
        return found

    def _check_resource(self, tenant: UUID, resource: str | None) -> None:
        # RFC 8707: a client names the resource the token is for; only this tenant's endpoint.
        if resource is not None and resource.rstrip("/") != self.resource(tenant):
            raise OAuthError(400, "invalid_target", "the resource is not this tenant's endpoint")

    @staticmethod
    def _entra_scope(audience: UUID, requested: str | None) -> str:
        asked = set((requested or KNOWLEDGE_SCOPE).split())
        unknown = asked - set(SCOPES)
        if unknown or KNOWLEDGE_SCOPE not in asked:
            raise OAuthError(400, "invalid_scope", f"ask for {KNOWLEDGE_SCOPE} (and {OFFLINE})")
        # The Entra scope names the API by its application id, whatever its App ID URI.
        return f"{audience}/{KNOWLEDGE_SCOPE} {OFFLINE}"


def _client_id(value: str | None) -> UUID:
    """A client registered in Entra: its application id, in canonical form only."""
    try:
        parsed = UUID(str(value))
    except ValueError:
        parsed = None
    if parsed is None or str(parsed) != value:
        raise OAuthError(
            400, "invalid_client", "client_id must be the client's Entra application id"
        )
    return parsed


def _basic(header: str, form_client: str | None) -> tuple[str, str]:
    scheme, _, value = header.partition(" ")
    try:
        if scheme.lower() != "basic":
            raise ValueError
        user, sep, password = base64.b64decode(value, validate=True).decode().partition(":")
        if not sep:
            raise ValueError
    except (ValueError, UnicodeDecodeError) as exc:
        raise OAuthError(401, "invalid_client", "malformed client authentication") from exc
    client, secret = urllib.parse.unquote(user), urllib.parse.unquote(password)
    if form_client is not None and form_client != client:
        raise OAuthError(400, "invalid_request", "two different client ids")
    return client, secret
