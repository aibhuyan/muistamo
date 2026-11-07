"""HTTP API of the knowledge service (contracts/openapi/knowledge.v1.yaml).

No `from __future__ import annotations` here: FastAPI must resolve the dependency annotations
defined inside create_app at definition time.
"""

import logging
import os
import urllib.parse
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from mcp.server.transport_security import TransportSecuritySettings
from muistamo_contracts.v1.accessrequest import AccessRequest
from muistamo_contracts.v1.common.healthstatus import HealthStatus, Status
from muistamo_contracts.v1.erasurerequest import ErasureRequest
from muistamo_contracts.v1.knowledgeentryinput import KnowledgeEntryInput
from muistamo_contracts.v1.knowledgepack import KnowledgePack
from muistamo_contracts.v1.knowledgesource import KnowledgeSource
from muistamo_contracts.v1.leaverreviewdecision import LeaverReviewDecision
from muistamo_contracts.v1.leaverreviewfence import LeaverReviewFence
from muistamo_contracts.v1.leaverreviewopen import LeaverReviewOpen
from muistamo_contracts.v1.personalentryvisibility import PersonalEntryVisibility
from muistamo_contracts.v1.proposaldecision import ProposalDecision
from muistamo_contracts.v1.proposalinput import ProposalInput
from muistamo_contracts.v1.rollbackinput import RollbackInput
from muistamo_contracts.v1.verificationinput import VerificationInput
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.routing import Route

from muistamo_knowledge import auth, evidence, oauth
from muistamo_knowledge.auth import Resolver, Unauthenticated, deny_all
from muistamo_knowledge.connectors import ConnectorUnavailable
from muistamo_knowledge.db import UnknownTenant
from muistamo_knowledge.leavers import Leavers
from muistamo_knowledge.mcp_server import build as build_mcp
from muistamo_knowledge.mcp_server import require_identity
from muistamo_knowledge.privacy import Privacy
from muistamo_knowledge.retrieval import Sources
from muistamo_knowledge.service import (
    Actor,
    Conflict,
    Forbidden,
    Invalid,
    Knowledge,
    NotFound,
    Superseded,
    to_jsonable,
)

SERVICE = "knowledge"
log = logging.getLogger("muistamo.knowledge")

_STATUS: list[tuple[type[Exception], int, str]] = [
    (Unauthenticated, 401, "Unauthorized"),
    (UnknownTenant, 401, "Unauthorized"),
    (Forbidden, 403, "Forbidden"),
    (NotFound, 404, "Not found"),
    (Superseded, 409, "Superseded by a later HR event"),
    (Conflict, 409, "Conflict"),
    (Invalid, 422, "Invalid request"),
    (evidence.EvidenceNotRecorded, 503, "Evidence could not be recorded; nothing was changed"),
    (ConnectorUnavailable, 503, "The source could not be reached; nothing was changed"),
]


def problem(
    status: int,
    title: str,
    detail: str | None = None,
    headers: dict[str, str] | None = None,
    type: str | None = None,  # noqa: A002 - the RFC 9457 member
) -> JSONResponse:
    body: dict[str, Any] = {"title": title, "status": status}
    if type:
        body["type"] = type
    if detail:
        body["detail"] = detail
    return JSONResponse(
        body, status_code=status, media_type="application/problem+json", headers=headers
    )


def create_app(knowledge: Knowledge | None, resolver: Resolver = deny_all) -> FastAPI:
    """Without a Knowledge service (no database or key), every /v1 and MCP call is refused."""
    mcp = build_mcp(knowledge, resolver) if knowledge is not None else None
    # A bearer-token resolver says how to authenticate on every 401 (RFC 6750 section 3).
    challenge = getattr(resolver, "challenge", None)
    unauthorized_headers = {"WWW-Authenticate": challenge} if challenge else None
    # The service's public URL, checked (a bad one stops startup): assistants reach the MCP
    # endpoints and sign-in there (docs/assistants-plan.md).
    public = oauth.public_url(os.environ.get("MUISTAMO_KNOWLEDGE_PUBLIC_URL"))
    # DNS-rebinding protection stays on: loopback, as the SDK allows by default, and the public
    # host the service is configured with, nothing else.
    hosts, origins = (
        ["127.0.0.1:*", "localhost:*", "[::1]:*"],
        ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
    )
    if public:
        hosts.append(urllib.parse.urlsplit(public).netloc)
        origins.append(public)
    mcp_app = (
        mcp.streamable_http_app(
            streamable_http_path="/",
            stateless_http=True,
            json_response=True,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins
            ),
        )
        if mcp is not None
        else None
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if mcp is None:
            yield
            return
        async with mcp.session_manager.run():
            yield

    app = FastAPI(title="muistamo-knowledge", lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        return problem(422, "Document does not match its contract", str(exc.errors()))

    @app.exception_handler(Exception)
    def _errors(request: Request, exc: Exception) -> JSONResponse:
        for kind, status, title in _STATUS:
            if isinstance(exc, kind):
                if status >= 500:
                    log.error("request failed", extra={"path": request.url.path, "error": str(exc)})
                # 401 never says why; others explain to the caller.
                return problem(
                    status,
                    title,
                    None if status in (401, 503) else str(exc),
                    unauthorized_headers if status == 401 else None,
                    getattr(exc, "type", None),
                )
        log.exception("unhandled error", extra={"path": request.url.path})
        return problem(500, "Internal error")

    def actor(request: Request) -> Actor:
        if knowledge is None:
            raise Unauthenticated("knowledge service not configured")
        tenant, name, assistant, kind = auth.resolve_caller(resolver, request.headers)
        return Actor(
            tenant=tenant,
            name=name,
            request_id=str(uuid.uuid4()),
            bearer=auth.entra_bearer(name, request.headers),
            assistant=assistant,
            client_kind=kind,
        )

    Who = Annotated[Actor, Depends(actor)]

    def reviewer(who: Who) -> Actor:
        """A person acting as themselves: reviewer and admin actions are never made through an
        assistant (maintainer decision, 2026-11-07). Reviewers use Muistamo's console, a client
        app of kind 'console' (migration 0013)."""
        if who.through_assistant:
            raise Forbidden(
                "reviewer and admin actions are not available through an assistant;"
                " use the Muistamo console"
            )
        return who

    Reviewer = Annotated[Actor, Depends(reviewer)]

    def svc() -> Knowledge:
        if knowledge is None:
            raise Unauthenticated("knowledge service not configured")
        return knowledge

    def ok(value: Any, status: int = 200) -> JSONResponse:
        return JSONResponse(to_jsonable(value), status_code=status)

    @app.get("/healthz")
    def healthz() -> HealthStatus:
        return HealthStatus(status=Status.ok, service=SERVICE)

    # D60: an assistant acting for a person (an Entra caller) reads only its agent's scope, the
    # template's packs and the mandatory packs, asked of the control plane at each read. Outside
    # it a single pack is refused (403, whether or not it exists); lists and resolve leave it out
    # and say so. Development callers are unchanged.
    def require_in_scope(who: Actor, name: str) -> None:
        scope = sources().agent_scope(who)
        if scope is not None and name not in scope.allowed:
            raise Forbidden(f"pack {name!r} is outside this assistant's agent scope")

    @app.get("/v1/knowledge/packs")
    def list_packs(who: Who) -> JSONResponse:
        scope = sources().agent_scope(who)
        items = svc().list_packs(who)
        if scope is None:
            return ok({"items": items})
        mine = [p for p in items if p["document"]["metadata"]["name"] in scope.allowed]
        return ok({"items": mine, "agentScope": scope.report()})

    @app.get("/v1/knowledge/packs/{name}")
    def get_pack(name: str, who: Who) -> JSONResponse:
        require_in_scope(who, name)
        return ok(svc().get_pack(who, name))

    @app.put("/v1/knowledge/packs/{name}")
    def apply_pack(name: str, body: KnowledgePack, who: Reviewer) -> JSONResponse:
        record, created = svc().apply_pack(
            who, name, body.model_dump(mode="json", exclude_none=True)
        )
        return ok(record, 201 if created else 200)

    @app.get("/v1/knowledge/packs/{name}/versions")
    def list_versions(name: str, who: Who) -> JSONResponse:
        require_in_scope(who, name)
        return ok({"items": svc().list_versions(who, name)})

    @app.get("/v1/knowledge/packs/{name}/versions/{version}")
    def get_version(name: str, version: str, who: Who) -> JSONResponse:
        require_in_scope(who, name)
        return ok(svc().get_version(who, name, version))

    @app.get("/v1/knowledge/packs/{name}/versions/{version}/skills.zip")
    def export_skills(name: str, version: str, who: Who) -> Response:
        require_in_scope(who, name)
        resolved, data = svc().export_skills(who, name, version)
        return Response(
            data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{name}-{resolved}-skills.zip"',
                "X-Muistamo-Pack-Version": resolved,
            },
        )

    @app.post("/v1/knowledge/packs/{name}/rollback")
    def rollback(name: str, body: RollbackInput, who: Reviewer) -> JSONResponse:
        return ok(svc().rollback(who, name, body.toVersion, body.reason), 201)

    @app.post("/v1/knowledge/packs/{name}/entries/{key}/verification")
    def verify_entry(name: str, key: str, body: VerificationInput, who: Reviewer) -> JSONResponse:
        return ok(svc().verify_entry(who, name, key, body.entryId, body.reason))

    @app.get("/v1/knowledge/verifications")
    def list_verifications(who: Reviewer) -> JSONResponse:
        return ok({"items": svc().verification_queue(who)})

    @app.get("/v1/knowledge/personal/entries")
    def list_personal(who: Who) -> JSONResponse:
        return ok({"items": svc().list_personal(who)})

    @app.post("/v1/knowledge/personal/entries")
    def capture(body: KnowledgeEntryInput, who: Who) -> JSONResponse:
        return ok(svc().capture(who, body.model_dump(mode="json", exclude_none=True)), 201)

    @app.patch("/v1/knowledge/personal/entries/{entry_id}")
    def set_entry_visibility(
        entry_id: uuid.UUID, body: PersonalEntryVisibility, who: Who
    ) -> JSONResponse:
        return ok(svc().set_visibility(who, entry_id, body.private))

    @app.delete("/v1/knowledge/personal/entries/{entry_id}", status_code=204)
    def delete_entry(entry_id: uuid.UUID, who: Who) -> Response:
        svc().delete_personal(who, entry_id)
        return Response(status_code=204)

    @app.get("/v1/knowledge/proposals")
    def list_proposals(
        who: Who, role: str = Query("contributor", pattern="^(contributor|reviewer)$")
    ) -> JSONResponse:
        if role == "reviewer" and who.through_assistant:
            raise Forbidden("the review inbox is not available through an assistant")
        return ok({"items": svc().list_proposals(who, role)})

    @app.post("/v1/knowledge/proposals")
    def propose(body: ProposalInput, who: Who) -> JSONResponse:
        scope = sources().agent_scope(who)
        if scope is not None and body.pack not in scope.template:
            # Only the agent's template packs: mandatory packs are the privacy officers' own.
            raise Forbidden(f"pack {body.pack!r} is outside this assistant's agent scope")
        ids = [uuid.UUID(str(i)) for i in body.entryIds]
        return ok(svc().propose(who, body.pack, ids, body.summary), 201)

    @app.get("/v1/knowledge/proposals/{proposal_id}")
    def get_proposal(proposal_id: uuid.UUID, who: Who) -> JSONResponse:
        proposal = svc().get_proposal(who, proposal_id)
        # Through an assistant, only the person's own proposals: reviewing is the console's.
        if who.through_assistant and proposal["contributor"] != who.name:
            raise NotFound(f"proposal {proposal_id}")
        return ok(proposal)

    @app.post("/v1/knowledge/proposals/{proposal_id}/decision")
    def decide(proposal_id: uuid.UUID, body: ProposalDecision, who: Reviewer) -> JSONResponse:
        edits = [e.model_dump(mode="json") for e in body.edits or []]
        return ok(svc().decide(who, proposal_id, body.decision.value, body.reason, edits))

    @app.get("/v1/knowledge/resolve")
    def resolve(who: Who, packs: str = "") -> JSONResponse:
        names = [p for p in (s.strip() for s in packs.split(",")) if p]
        scope = sources().agent_scope(who)
        if scope is None:
            return ok({"items": svc().resolve(who, names)})
        outside = sorted({n for n in names if n not in scope.allowed})
        within = [n for n in names if n in scope.allowed]
        return ok({"items": svc().resolve(who, within), "agentScope": scope.report(outside)})

    def sources() -> Sources:
        return Sources(svc())

    @app.get("/v1/knowledge/sources")
    def list_sources(who: Who) -> JSONResponse:
        scope = sources().agent_scope(who)
        items = sources().list(who)
        if scope is not None:  # D60: only the sources of packs in the agent's scope
            items = [s for s in items if s["document"]["spec"]["pack"] in scope.allowed]
        return ok({"items": items})

    @app.get("/v1/knowledge/sources/{name}")
    def get_source(name: str, who: Who) -> JSONResponse:
        scope = sources().agent_scope(who)
        try:
            record = sources().get(who, name)
        except NotFound:
            if scope is not None:  # an assistant learns nothing of what is outside its scope
                raise Forbidden(
                    f"source {name!r} is outside this assistant's agent scope"
                ) from None
            raise
        if scope is not None and record["document"]["spec"]["pack"] not in scope.allowed:
            raise Forbidden(f"source {name!r} is outside this assistant's agent scope")
        return ok(record)

    @app.put("/v1/knowledge/sources/{name}")
    def apply_source(name: str, body: KnowledgeSource, who: Reviewer) -> JSONResponse:
        record, created = sources().apply(
            who, name, body.model_dump(mode="json", exclude_none=True)
        )
        return ok(record, 201 if created else 200)

    @app.post("/v1/knowledge/sources/{name}/sync")
    def sync_source(name: str, who: Reviewer) -> JSONResponse:
        return ok(sources().sync(who, name))

    @app.get("/v1/knowledge/retrieve")
    def retrieve(
        who: Who,
        q: str = Query(..., min_length=1),
        packs: str = "",
        limit: int = Query(10, ge=1, le=50),
    ) -> JSONResponse:
        names = [p for p in (s.strip() for s in packs.split(",")) if p]
        return ok(sources().retrieve(who, q, names, limit))

    @app.get("/v1/knowledge/events")
    def events(
        who: Who, afterSeq: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)
    ) -> JSONResponse:  # noqa: N803
        # The evidence chain names every pack and reviewer: an auditor's export, never an
        # assistant's (D60).
        if who.through_assistant:
            raise Forbidden("the evidence export is not available to an assistant")
        items = svc().events(who, afterSeq, limit + 1)
        page: dict[str, Any] = {"items": [e.to_json() for e in items[:limit]]}
        if len(items) > limit:
            page["nextAfterSeq"] = items[limit - 1].seq
        return ok(page)

    @app.get("/v1/knowledge/reads")
    def reads(who: Who, limit: int = Query(100, ge=1, le=500)) -> JSONResponse:
        return ok({"items": sources().reads(who, limit)})

    def privacy() -> Privacy:
        return Privacy(svc())

    @app.post("/v1/knowledge/privacy/erasures")
    def erase(body: ErasureRequest, who: Reviewer) -> JSONResponse:
        proof, created = privacy().erase(who, body.model_dump(mode="json", exclude_none=True))
        return ok(proof, 201 if created else 200)

    @app.get("/v1/knowledge/privacy/erasures/{erasure_id}")
    def get_erasure(erasure_id: uuid.UUID, who: Reviewer) -> JSONResponse:
        return ok(privacy().get_erasure(who, erasure_id))

    @app.post("/v1/knowledge/privacy/access")
    def export_personal_data(body: AccessRequest, who: Reviewer) -> JSONResponse:
        return ok(privacy().export(who, body.subject.model_dump(mode="json", exclude_none=True)))

    def leavers() -> Leavers:
        return Leavers(svc(), auth.identity_map_for(resolver))

    @app.get("/v1/knowledge/leaver-reviews")
    def list_leaver_reviews(who: Reviewer) -> JSONResponse:
        return ok({"items": leavers().list(who)})

    @app.post("/v1/knowledge/leaver-reviews/{review_id}/decision")
    def decide_leaver_review(
        review_id: str, body: LeaverReviewDecision, who: Reviewer
    ) -> JSONResponse:
        return ok(leavers().decide(who, review_id, body.model_dump(mode="json", exclude_none=True)))

    @app.get("/v1/knowledge/leaver-reviews/{review_id}")
    def get_leaver_review(review_id: str, who: Reviewer) -> JSONResponse:
        return ok(leavers().get(who, review_id))

    # Service calls from the control plane. Signed with the tenant's service secret; never a
    # user identity. The signature is checked over the raw body before anything is parsed.
    # The method and path are signed too (v2). Only during a rollout where the control plane
    # predates v2 may an operator accept v1-only signatures (docs/signature-plan.md).
    accept_v1 = os.environ.get("MUISTAMO_KNOWLEDGE_ACCEPT_V1_SIGNATURES") == "true"

    async def signed(request: Request) -> tuple[uuid.UUID, bytes]:
        body = await request.body()
        tenant = auth.service_tenant(request.headers)
        secret = await run_in_threadpool(leavers().service_secret, tenant)
        # scope["path"]: the decoded path the router matched, not request.url.path (rebuilt, so
        # it re-quotes some characters and drops others).
        auth.verify_service(
            request.headers,
            body,
            secret,
            request.method,
            request.scope["path"],
            accept_v1=accept_v1,
            tenant=tenant,
        )
        return tenant, body

    # Service calls: a refusal never echoes the request's values (entra: identities), since the
    # control plane may record the answer.
    @app.post("/v1/knowledge/internal/leaver-reviews")
    async def open_leaver_review(request: Request) -> JSONResponse:
        tenant, body = await signed(request)
        try:
            doc = LeaverReviewOpen.model_validate_json(body)
        except ValidationError as exc:
            return problem(
                422, "Document does not match its contract", str(exc.errors(include_input=False))
            )
        review, created = await run_in_threadpool(
            leavers().open, tenant, doc.model_dump(mode="json", exclude_none=True)
        )
        return ok(review, 201 if created else 200)

    @app.post("/v1/knowledge/internal/leaver-reviews/{review_id}/expire")
    async def expire_leaver_review(review_id: str, request: Request) -> JSONResponse:
        tenant, _ = await signed(request)
        return ok(await run_in_threadpool(leavers().expire, tenant, review_id))

    @app.post("/v1/knowledge/internal/leaver-reviews/{review_id}/cancel")
    async def cancel_leaver_review(review_id: str, request: Request) -> JSONResponse:
        tenant, _ = await signed(request)
        return ok(await run_in_threadpool(leavers().cancel, tenant, review_id))

    @app.post("/v1/knowledge/internal/leaver-reviews/fence")
    async def fence_leaver_reviews(request: Request) -> JSONResponse:
        tenant, body = await signed(request)
        try:
            doc = LeaverReviewFence.model_validate_json(body)
        except ValidationError as exc:
            return problem(
                422, "Document does not match its contract", str(exc.errors(include_input=False))
            )
        return ok(await run_in_threadpool(leavers().fence, tenant, doc.user, doc.generation))

    # Sign-in for assistants (docs/assistants-plan.md): per tenant, RFC 9728 metadata for the
    # MCP endpoint and a thin authorization server in front of the tenant's Entra (oauth.py).
    # Offered only when the service knows its public URL (checked here: a bad one stops startup)
    # and the tenant has an Entra directory; otherwise every one of these answers 404.
    signin = oauth.SignIn(
        public,
        knowledge.db.entra_registration if knowledge is not None else (lambda _: None),
        knowledge.db.entra_client if knowledge is not None else (lambda _t, _c: None),
    )

    def canonical_tenant(value: str) -> uuid.UUID | None:
        try:
            parsed = uuid.UUID(value)
        except ValueError:
            return None
        return parsed if str(parsed) == value else None

    def tenant_challenge(tenant: uuid.UUID, token_presented: bool) -> str | None:
        try:
            return signin.challenge(tenant, token_presented)
        except Exception:  # noqa: BLE001 - the 401 is still sent, with the generic challenge
            log.exception(
                "sign-in discovery unavailable for a challenge", extra={"tenant": str(tenant)}
            )
            return None

    async def metadata(tenant: str, build) -> JSONResponse:
        parsed = canonical_tenant(tenant)
        found = await run_in_threadpool(build, parsed) if parsed is not None else None
        if found is None:
            return problem(404, "Not found", headers={"Cache-Control": "no-store"})
        return JSONResponse(found, headers={"Cache-Control": "public, max-age=300"})

    @app.get("/.well-known/oauth-protected-resource/mcp/t/{tenant}/knowledge")
    async def protected_resource_metadata(tenant: str) -> JSONResponse:
        return await metadata(tenant, signin.protected_resource)

    # RFC 8414 path-inserted, and appended to the issuer, as MCP clients try both.
    @app.get("/.well-known/oauth-authorization-server/oauth/t/{tenant}")
    @app.get("/oauth/t/{tenant}/.well-known/oauth-authorization-server")
    async def authorization_server_metadata(tenant: str) -> JSONResponse:
        return await metadata(tenant, signin.authorization_server)

    def oauth_error(exc: oauth.OAuthError) -> JSONResponse:
        return JSONResponse(
            {"error": exc.error, "error_description": exc.description},
            status_code=exc.status,
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/oauth/t/{tenant}/authorize")
    async def oauth_authorize(tenant: str, request: Request) -> Response:
        parsed = canonical_tenant(tenant)
        if parsed is None:
            return oauth_error(oauth.OAuthError(404, "invalid_request", "no sign-in here"))
        params = dict(request.query_params)
        try:
            redirect = await run_in_threadpool(signin.authorize, parsed, params)
        except oauth.OAuthError as exc:
            return oauth_error(exc)
        return Response(
            status_code=302, headers={"Location": redirect.location, "Cache-Control": "no-store"}
        )

    @app.post("/oauth/t/{tenant}/token")
    async def oauth_token(tenant: str, request: Request) -> Response:
        parsed = canonical_tenant(tenant)
        if parsed is None:
            return oauth_error(oauth.OAuthError(404, "invalid_request", "no sign-in here"))
        raw = await request.body()
        if len(raw) > oauth.MAX_BODY:
            return oauth_error(oauth.OAuthError(400, "invalid_request", "request too large"))
        form = {
            k: v for k, v in urllib.parse.parse_qsl(raw.decode("latin-1"), keep_blank_values=True)
        }
        try:
            status, body = await run_in_threadpool(
                signin.token, parsed, form, request.headers.get("Authorization")
            )
        except oauth.OAuthError as exc:
            return oauth_error(exc)
        return Response(
            content=body,
            status_code=status,
            media_type="application/json",
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    if mcp_app is not None:
        app.mount("/mcp/knowledge", require_identity(mcp_app, resolver, knowledge))
        tenant_mcp = require_identity(
            mcp_app, resolver, knowledge, tenant_challenge=tenant_challenge
        )
        app.mount("/mcp/t/{tenant}/knowledge", tenant_mcp)

        class Slashless:
            """The endpoint as its metadata names it, without the trailing slash: served directly,
            never redirected (a redirect behind a TLS proxy would name the internal host). A class,
            so Starlette routes to it as an ASGI app rather than a request handler."""

            async def __call__(self, scope, receive, send) -> None:
                path = scope["path"]
                inner = dict(scope, root_path=scope.get("root_path", "") + path, path=path + "/")
                await tenant_mcp(inner, receive, send)

        app.router.routes.append(
            Route(
                "/mcp/t/{tenant}/knowledge",
                endpoint=Slashless(),
                methods=["GET", "POST", "DELETE"],
            )
        )
    else:

        @app.api_route("/mcp/knowledge/{rest:path}", methods=["GET", "POST", "DELETE"])
        def mcp_refused(rest: str) -> JSONResponse:
            return problem(401, "Unauthorized", headers=unauthorized_headers)

    return app


# Health only: the CLI's `serve` builds the configured app.
app = create_app(None)
