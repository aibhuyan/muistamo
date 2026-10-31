"""Who is calling. Fails closed: any doubt refuses the request.

Until real authentication exists (Keycloak, PRD section 9), the only resolver besides deny_all
trusts development headers, and only when MUISTAMO_INSECURE_DEV_TENANT_HEADER=true.

HUMAN REVIEW REQUIRED (CLAUDE.md): service-call signatures below are a credential check. The
control plane signs /v1/knowledge/internal/ calls with the tenant's service secret; those routes
accept nothing else, and no other route accepts a service signature.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable, Mapping
from uuid import UUID


class Unauthenticated(Exception):
    pass


class UnmappedIdentity(Exception):
    """No identity mapping is configured, so an email cannot be turned into an identity."""


# Resolvers read request headers, so REST and MCP requests resolve callers identically.
Resolver = Callable[[Mapping[str, str]], tuple[UUID, str]]
# An identity map turns an email (as HR sends it) into the identity the resolver records.
IdentityMap = Callable[[str], str]

SIGNATURE_TOLERANCE = 300  # seconds, as for HR webhooks


def deny_all(_: Mapping[str, str]) -> tuple[UUID, str]:
    raise Unauthenticated("no authentication configured")


def _header(headers: Mapping[str, str], name: str) -> str:
    # HTTP header names are case-insensitive; not every mapping handed to us is.
    lowered = name.lower()
    return next((v for k, v in headers.items() if k.lower() == lowered), "")


def insecure_dev_headers(headers: Mapping[str, str]) -> tuple[UUID, str]:
    """Development only: anyone who can reach the service can claim any tenant and person."""
    try:
        tenant = UUID(_header(headers, "X-Muistamo-Tenant"))
    except ValueError as exc:
        raise Unauthenticated("missing or malformed X-Muistamo-Tenant") from exc
    actor = _header(headers, "X-Muistamo-Actor")
    if not actor:
        raise Unauthenticated("missing X-Muistamo-Actor")
    return tenant, "dev:" + actor


def entra_bearer(name: str, headers: Mapping[str, str]) -> str | None:
    """The bearer token of a caller the Entra resolver accepted (entra: identities), else None."""
    if not name.startswith("entra:"):
        return None
    scheme, _, token = _header(headers, "Authorization").partition(" ")
    return token if scheme.lower() == "bearer" and token else None


def no_identity_map(_: str) -> str:
    raise UnmappedIdentity("no identity mapping is configured")


def dev_identity(email: str) -> str:
    """The identity insecure_dev_headers records for a person who signs in as email."""
    return "dev:" + email


def identity_map_for(resolver: Resolver) -> IdentityMap:
    """The mapping that matches a resolver. Entra's arrives with real identities (FR-201)."""
    return dev_identity if resolver is insecure_dev_headers else no_identity_map


def sign(secret: bytes, body: bytes, at: float | None = None) -> str:
    """X-Muistamo-Signature for body: t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.body">."""
    ts = str(int(time.time() if at is None else at))
    mac = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def service_tenant(headers: Mapping[str, str]) -> UUID:
    """The tenant a service call names. The signature is checked against its secret next."""
    try:
        return UUID(_header(headers, "X-Muistamo-Tenant"))
    except ValueError as exc:
        raise Unauthenticated("missing or malformed X-Muistamo-Tenant") from exc


def verify_service(
    headers: Mapping[str, str], body: bytes, secret: bytes | None, now: float | None = None
) -> None:
    """Refuse unless headers carry a fresh signature of body under secret."""
    if not secret:
        raise Unauthenticated("the tenant has no service secret")
    parts = dict(
        p.split("=", 1) for p in _header(headers, "X-Muistamo-Signature").split(",") if "=" in p
    )
    ts, given = parts.get("t", ""), parts.get("v1", "")
    if not ts.isdigit() or not given:
        raise Unauthenticated("missing or malformed X-Muistamo-Signature")
    if abs((time.time() if now is None else now) - int(ts)) > SIGNATURE_TOLERANCE:
        raise Unauthenticated("service signature is stale")
    want = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, given):
        raise Unauthenticated("service signature does not match")
