"""Entra authentication of knowledge callers (docs/obo-retrieval-plan.md, PR C).

HUMAN REVIEW REQUIRED (CLAUDE.md): token validation. A caller is accepted only with an Entra
access token for the tenant's Muistamo blueprint, issued by the directory registered for that
tenant, to a person (never an app), carrying the Knowledge.Read scope, and current. The caller is then
entra:<the user's object id>. The rules match the control plane's (internal/entra/usertoken.go),
which validates the same token again before acting for the person.

Not yet a lifecycle check: any person of the directory the blueprint admits is a caller. Until
callers are matched to their HR person (person links, then on-behalf-of retrieval), a leaver's
personal layer is not frozen for review, and the enterprise application should require user
assignment. serve says so at startup.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from muistamo_knowledge.auth import Unauthenticated, _header

log = logging.getLogger(__name__)

LEEWAY = 60  # seconds of clock skew allowed on exp and nbf
KEYS_MAX_AGE = 24 * 3600
KEYS_MIN_REFRESH = 30  # unknown key ids never fetch the keys more often than this
KEYS_TIMEOUT = 5  # seconds for the whole key fetch, not per read
KNOWLEDGE_SCOPE = "Knowledge.Read"  # as the control plane requires (usertoken.go)
MAX_TOKEN = 16384
MAX_KEYS_RESPONSE = 1 << 20


@dataclass(frozen=True)
class Registration:
    """What knowledge.entra_tenant() returns for a directory."""

    tenant: uuid.UUID
    audience: uuid.UUID


# Finds the registration for a directory (None when the directory is not registered).
Lookup = Callable[[uuid.UUID], Registration | None]
# Fetches a directory's published key set as JSON.
FetchKeys = Callable[[uuid.UUID], bytes]


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_opener = urllib.request.build_opener(_NoRedirects())


def fetch_keys(directory: uuid.UUID) -> bytes:
    """The directory's signing keys from Entra's fixed, public discovery endpoint."""
    url = f"https://login.microsoftonline.com/{directory}/discovery/v2.0/keys"
    deadline = time.monotonic() + KEYS_TIMEOUT
    body = b""
    with _opener.open(url, timeout=KEYS_TIMEOUT) as response:
        if response.status != 200:
            raise Unauthenticated("signing keys unavailable")
        # A slow answer is bounded as a whole, not only between reads.
        while chunk := response.read(65536):
            body += chunk
            if len(body) > MAX_KEYS_RESPONSE:
                raise Unauthenticated("signing keys response too large")
            if time.monotonic() > deadline:
                raise Unauthenticated("signing keys too slow")
    return body


def usable_keys(raw: bytes) -> dict[str, RSAPublicKey]:
    """RSA keys of at least 2048 bits meant for RS256 signatures; a key id published twice is
    trusted for neither key."""
    keys: dict[str, RSAPublicKey | None] = {}
    document = json.loads(raw)
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("not a key set")
    for jwk in document["keys"]:
        if not isinstance(jwk, dict):
            continue
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid or jwk.get("kty") != "RSA":
            continue
        if jwk.get("use", "sig") != "sig" or jwk.get("alg", "RS256") != "RS256":
            continue
        try:
            key = jwt.PyJWK(jwk, algorithm="RS256").key
        except (jwt.PyJWKError, jwt.InvalidKeyError, ValueError, TypeError):
            continue
        if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
            continue
        keys[kid] = None if kid in keys else key
    return {kid: key for kid, key in keys.items() if key is not None}


@dataclass
class _KeySet:
    keys: dict[str, RSAPublicKey] = field(default_factory=dict)
    fetched: float = float("-inf")
    tried: float = float("-inf")
    lock: threading.Lock = field(default_factory=threading.Lock)


def _canonical_uuid(value: object) -> uuid.UUID | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return parsed if str(parsed) == value and parsed.int != 0 else None


class EntraBearer:
    """A resolver: Authorization: Bearer <Entra access token> → (tenant, "entra:<oid>")."""

    challenge = 'Bearer realm="muistamo-knowledge"'

    def __init__(
        self,
        lookup: Lookup,
        fetch: FetchKeys = fetch_keys,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._lookup = lookup
        self._fetch = fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._sets: dict[uuid.UUID, _KeySet] = {}

    def __call__(self, headers: Mapping[str, str]) -> tuple[uuid.UUID, str]:
        scheme, _, token = _header(headers, "Authorization").partition(" ")
        if scheme.lower() != "bearer" or not token or " " in token or len(token) > MAX_TOKEN:
            raise Unauthenticated("missing or malformed bearer token")
        try:
            header = jwt.get_unverified_header(token)
            # Only to find the directory's registration: everything is verified below.
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise Unauthenticated("malformed bearer token") from exc
        directory = _canonical_uuid(unverified.get("tid"))
        kid = header.get("kid")
        if directory is None or header.get("alg") != "RS256" or not isinstance(kid, str) or not kid:
            raise Unauthenticated("bearer token is not an Entra user token")
        registration = self._lookup(directory)
        if registration is None:
            raise Unauthenticated("directory is not registered")
        key = self._key(directory, kid)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=str(registration.audience),
                issuer=f"https://login.microsoftonline.com/{directory}/v2.0",
                leeway=LEEWAY,
                options={"require": ["exp", "nbf", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise Unauthenticated("bearer token is not valid") from exc
        # One audience, exactly the blueprint (PyJWT also accepts a list containing it).
        if claims.get("aud") != str(registration.audience):
            raise Unauthenticated("bearer token is for another audience")
        if claims.get("tid") != str(directory) or claims.get("ver") != "2.0":
            raise Unauthenticated("bearer token is not a v2.0 token of the directory")
        if claims.get("idtyp") == "app":
            raise Unauthenticated("an app token never acts for a person")
        scopes = claims.get("scp")
        if not isinstance(scopes, str) or KNOWLEDGE_SCOPE not in scopes.split():
            raise Unauthenticated("bearer token lacks the required scope")
        user = _canonical_uuid(claims.get("oid"))
        if user is None:
            raise Unauthenticated("bearer token names no user")
        return registration.tenant, f"entra:{user}"

    def _key(self, directory: uuid.UUID, kid: str) -> RSAPublicKey:
        """The directory's signing key kid, fetching the keys when the cache is old or lacks it,
        at most once per KEYS_MIN_REFRESH. An outage keeps known keys and never admits new ones.

        The fetch runs outside any lock: one request per directory fetches, and the others meanwhile
        use the keys already known (or are refused for an unknown key) rather than wait."""
        with self._lock:
            keys = self._sets.setdefault(directory, _KeySet())
        with keys.lock:
            now = self._clock()
            known = keys.keys.get(kid)
            if known is not None and now - keys.fetched < KEYS_MAX_AGE:
                return known
            if now - keys.tried < KEYS_MIN_REFRESH:
                if known is not None:
                    return known
                raise Unauthenticated("unknown signing key")
            keys.tried = now
        try:
            fresh = usable_keys(self._fetch(directory))
        except Exception as exc:  # any failure to fetch or parse keeps what is known
            log.warning(
                "Entra signing keys unavailable",
                extra={"directory": str(directory), "error": type(exc).__name__},
            )
            if known is not None:
                return known
            raise Unauthenticated("signing keys unavailable") from exc
        with keys.lock:
            keys.keys, keys.fetched = fresh, now
        if kid not in fresh:
            raise Unauthenticated("unknown signing key")
        return fresh[kid]


def registrations(db: Any) -> Lookup:
    """Lookup through the knowledge database (db.Database.entra_tenant)."""

    def lookup(directory: uuid.UUID) -> Registration | None:
        row = db.entra_tenant(directory)
        return Registration(*row) if row else None

    return lookup


class AlreadyRegistered(Exception):
    """The tenant already accepts another directory or audience; replacing it must be explicit."""


def register(
    owner_url: str,
    tenant: uuid.UUID,
    directory: uuid.UUID,
    audience: uuid.UUID,
    replace: bool = False,
) -> tuple[uuid.UUID, uuid.UUID] | None:
    """Map an Entra directory to a tenant, as the schema owner, and return the (directory,
    audience) it replaced, if any. A tenant already mapped elsewhere is changed only with
    replace=True: every caller of the old directory loses access, and their entra: identities no
    longer resolve. A directory already mapped to another tenant is refused by the database."""
    import psycopg

    with psycopg.connect(owner_url) as conn, conn.transaction():
        row = conn.execute(
            "SELECT entra_tenant_id, audience FROM knowledge.entra_tenants WHERE tenant_id = %s FOR UPDATE",
            (tenant,),
        ).fetchone()
        previous = (row[0], row[1]) if row else None
        if previous == (directory, audience):
            return previous
        if previous is not None and not replace:
            raise AlreadyRegistered(
                f"tenant {tenant} accepts directory {previous[0]} for audience {previous[1]}"
            )
        conn.execute(
            "INSERT INTO knowledge.entra_tenants (tenant_id, entra_tenant_id, audience) VALUES (%s, %s, %s)"
            " ON CONFLICT (tenant_id) DO UPDATE SET entra_tenant_id = EXCLUDED.entra_tenant_id,"
            " audience = EXCLUDED.audience, created_at = now()",
            (tenant, directory, audience),
        )
        return previous
