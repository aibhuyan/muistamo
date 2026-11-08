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
import logging
import time
from collections.abc import Callable, Mapping
from typing import NamedTuple
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
log = logging.getLogger("muistamo.knowledge")


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


class Caller(NamedTuple):
    """Who called: the tenant and the caller, and, for an Entra caller, the allowed client app
    its token was obtained by (its name, kind and application id)."""

    tenant: UUID
    name: str
    assistant: str | None = None
    kind: str | None = None
    client_app: UUID | None = None


def resolve_caller(resolver: Resolver, headers: Mapping[str, str]) -> Caller:
    """The caller, from one verification. Resolvers other than Entra's name no client."""
    resolve = getattr(resolver, "resolve_caller", None)
    if resolve is not None:
        return resolve(headers)
    tenant, name = resolver(headers)
    return Caller(tenant, name)


def no_identity_map(_: str) -> str:
    raise UnmappedIdentity("no identity mapping is configured")


def dev_identity(email: str) -> str:
    """The identity insecure_dev_headers records for a person who signs in as email."""
    return "dev:" + email


def identity_map_for(resolver: Resolver) -> IdentityMap:
    """The mapping that matches a resolver. Entra's arrives with real identities (FR-201)."""
    return dev_identity if resolver is insecure_dev_headers else no_identity_map


# v2 binds the method and path (docs/signature-plan.md); the control plane's signature.MACv2.
V2_DOMAIN = "muistamo/v2 control-plane→knowledge"


def _mac_v2(secret: bytes, ts: str, method: str, path: str, body: bytes) -> str:
    head = "\n".join((V2_DOMAIN, ts, method, path, "")).encode()
    return hmac.new(secret, head + body, hashlib.sha256).hexdigest()


def sign(
    secret: bytes,
    body: bytes,
    at: float | None = None,
    method: str | None = None,
    path: str | None = None,
) -> str:
    """X-Muistamo-Signature for body: t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.body">, and,
    given the method and path, v2 (as the control plane signs its calls)."""
    ts = str(int(time.time() if at is None else at))
    mac = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    value = f"t={ts},v1={mac}"
    if method is not None and path is not None:
        value += f",v2={_mac_v2(secret, ts, method, path, body)}"
    return value


def service_tenant(headers: Mapping[str, str]) -> UUID:
    """The tenant a service call names. The signature is checked against its secret next."""
    try:
        return UUID(_header(headers, "X-Muistamo-Tenant"))
    except ValueError as exc:
        raise Unauthenticated("missing or malformed X-Muistamo-Tenant") from exc


def _signable_path(path: str) -> bool:
    """A path that v2 can bind unambiguously: no control characters (the fields are newline-
    joined, and the path is the last before the body)."""
    return bool(path) and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in path)


def verify_service(
    headers: Mapping[str, str],
    body: bytes,
    secret: bytes | None,
    method: str,
    path: str,
    now: float | None = None,
    tenant: UUID | None = None,
) -> None:
    """Refuse unless headers carry a fresh v2 signature of this method, path and body under
    secret. A v1 (body and time only) is never enough: the overlap is over
    (docs/signature-retirement-plan.md). A v1 next to a valid v2 is ignored.

    path must be the request's own decoded path as the router matched it (ASGI scope["path"]),
    the same bytes the control plane signs (its req.URL.Path)."""
    if not secret:
        raise Unauthenticated("the tenant has no service secret")
    parts = dict(
        p.split("=", 1) for p in _header(headers, "X-Muistamo-Signature").split(",") if "=" in p
    )
    ts = parts.get("t", "")
    macs = [parts[k] for k in ("v1", "v2") if k in parts]
    well_formed = ts.isascii() and ts.isdigit() and len(ts) <= 12
    if not well_formed or not any(macs) or not all(m.isascii() for m in macs):
        raise Unauthenticated("missing or malformed X-Muistamo-Signature")
    if not _signable_path(path):
        raise Unauthenticated("the request path cannot be signed")
    if abs((time.time() if now is None else now) - int(ts)) > SIGNATURE_TOLERANCE:
        raise Unauthenticated("service signature is stale")
    if "v2" not in parts:
        raise Unauthenticated("service signature has no v2 (method and path); refused")
    # A v1 beside it (control planes from #47 until v1 sending ended) is ignored.
    if not hmac.compare_digest(_mac_v2(secret, ts, method, path, body), parts["v2"]):
        raise Unauthenticated("service signature does not match")
