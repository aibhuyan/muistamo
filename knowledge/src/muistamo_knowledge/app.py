"""HTTP API of the knowledge service (contracts/openapi/knowledge.v1.yaml).

No `from __future__ import annotations` here: FastAPI must resolve the dependency annotations
defined inside create_app at definition time.
"""

import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from muistamo_contracts.v1.accessrequest import AccessRequest
from muistamo_contracts.v1.common.healthstatus import HealthStatus, Status
from muistamo_contracts.v1.erasurerequest import ErasureRequest
from muistamo_contracts.v1.knowledgeentryinput import KnowledgeEntryInput
from muistamo_contracts.v1.knowledgepack import KnowledgePack
from muistamo_contracts.v1.knowledgesource import KnowledgeSource
from muistamo_contracts.v1.leaverreviewdecision import LeaverReviewDecision
from muistamo_contracts.v1.leaverreviewopen import LeaverReviewOpen
from muistamo_contracts.v1.proposaldecision import ProposalDecision
from muistamo_contracts.v1.proposalinput import ProposalInput
from muistamo_contracts.v1.rollbackinput import RollbackInput
from muistamo_contracts.v1.verificationinput import VerificationInput
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from muistamo_knowledge import auth, evidence
from muistamo_knowledge.auth import Resolver, Unauthenticated, deny_all
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
    to_jsonable,
)

SERVICE = "knowledge"
log = logging.getLogger("muistamo.knowledge")

_STATUS: list[tuple[type[Exception], int, str]] = [
    (Unauthenticated, 401, "Unauthorized"),
    (UnknownTenant, 401, "Unauthorized"),
    (Forbidden, 403, "Forbidden"),
    (NotFound, 404, "Not found"),
    (Conflict, 409, "Conflict"),
    (Invalid, 422, "Invalid request"),
    (evidence.EvidenceNotRecorded, 503, "Evidence could not be recorded; nothing was changed"),
]


def problem(
    status: int, title: str, detail: str | None = None, headers: dict[str, str] | None = None
) -> JSONResponse:
    body: dict[str, Any] = {"title": title, "status": status}
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
    mcp_app = (
        mcp.streamable_http_app(streamable_http_path="/", stateless_http=True, json_response=True)
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
                )
        log.exception("unhandled error", extra={"path": request.url.path})
        return problem(500, "Internal error")

    def actor(request: Request) -> Actor:
        if knowledge is None:
            raise Unauthenticated("knowledge service not configured")
        tenant, name = resolver(request.headers)
        return Actor(
            tenant=tenant,
            name=name,
            request_id=str(uuid.uuid4()),
            bearer=auth.entra_bearer(name, request.headers),
        )

    Who = Annotated[Actor, Depends(actor)]

    def svc() -> Knowledge:
        if knowledge is None:
            raise Unauthenticated("knowledge service not configured")
        return knowledge

    def ok(value: Any, status: int = 200) -> JSONResponse:
        return JSONResponse(to_jsonable(value), status_code=status)

    @app.get("/healthz")
    def healthz() -> HealthStatus:
        return HealthStatus(status=Status.ok, service=SERVICE)

    @app.get("/v1/knowledge/packs")
    def list_packs(who: Who) -> JSONResponse:
        return ok({"items": svc().list_packs(who)})

    @app.get("/v1/knowledge/packs/{name}")
    def get_pack(name: str, who: Who) -> JSONResponse:
        return ok(svc().get_pack(who, name))

    @app.put("/v1/knowledge/packs/{name}")
    def apply_pack(name: str, body: KnowledgePack, who: Who) -> JSONResponse:
        record, created = svc().apply_pack(
            who, name, body.model_dump(mode="json", exclude_none=True)
        )
        return ok(record, 201 if created else 200)

    @app.get("/v1/knowledge/packs/{name}/versions")
    def list_versions(name: str, who: Who) -> JSONResponse:
        return ok({"items": svc().list_versions(who, name)})

    @app.get("/v1/knowledge/packs/{name}/versions/{version}")
    def get_version(name: str, version: str, who: Who) -> JSONResponse:
        return ok(svc().get_version(who, name, version))

    @app.get("/v1/knowledge/packs/{name}/versions/{version}/skills.zip")
    def export_skills(name: str, version: str, who: Who) -> Response:
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
    def rollback(name: str, body: RollbackInput, who: Who) -> JSONResponse:
        return ok(svc().rollback(who, name, body.toVersion, body.reason), 201)

    @app.post("/v1/knowledge/packs/{name}/entries/{key}/verification")
    def verify_entry(name: str, key: str, body: VerificationInput, who: Who) -> JSONResponse:
        return ok(svc().verify_entry(who, name, key, body.entryId, body.reason))

    @app.get("/v1/knowledge/verifications")
    def list_verifications(who: Who) -> JSONResponse:
        return ok({"items": svc().verification_queue(who)})

    @app.get("/v1/knowledge/personal/entries")
    def list_personal(who: Who) -> JSONResponse:
        return ok({"items": svc().list_personal(who)})

    @app.post("/v1/knowledge/personal/entries")
    def capture(body: KnowledgeEntryInput, who: Who) -> JSONResponse:
        return ok(svc().capture(who, body.model_dump(mode="json", exclude_none=True)), 201)

    @app.delete("/v1/knowledge/personal/entries/{entry_id}", status_code=204)
    def delete_entry(entry_id: uuid.UUID, who: Who) -> Response:
        svc().delete_personal(who, entry_id)
        return Response(status_code=204)

    @app.get("/v1/knowledge/proposals")
    def list_proposals(
        who: Who, role: str = Query("contributor", pattern="^(contributor|reviewer)$")
    ) -> JSONResponse:
        return ok({"items": svc().list_proposals(who, role)})

    @app.post("/v1/knowledge/proposals")
    def propose(body: ProposalInput, who: Who) -> JSONResponse:
        ids = [uuid.UUID(str(i)) for i in body.entryIds]
        return ok(svc().propose(who, body.pack, ids, body.summary), 201)

    @app.get("/v1/knowledge/proposals/{proposal_id}")
    def get_proposal(proposal_id: uuid.UUID, who: Who) -> JSONResponse:
        return ok(svc().get_proposal(who, proposal_id))

    @app.post("/v1/knowledge/proposals/{proposal_id}/decision")
    def decide(proposal_id: uuid.UUID, body: ProposalDecision, who: Who) -> JSONResponse:
        edits = [e.model_dump(mode="json") for e in body.edits or []]
        return ok(svc().decide(who, proposal_id, body.decision.value, body.reason, edits))

    @app.get("/v1/knowledge/resolve")
    def resolve(who: Who, packs: str = "") -> JSONResponse:
        names = [p for p in (s.strip() for s in packs.split(",")) if p]
        return ok({"items": svc().resolve(who, names)})

    def sources() -> Sources:
        return Sources(svc())

    @app.get("/v1/knowledge/sources")
    def list_sources(who: Who) -> JSONResponse:
        return ok({"items": sources().list(who)})

    @app.get("/v1/knowledge/sources/{name}")
    def get_source(name: str, who: Who) -> JSONResponse:
        return ok(sources().get(who, name))

    @app.put("/v1/knowledge/sources/{name}")
    def apply_source(name: str, body: KnowledgeSource, who: Who) -> JSONResponse:
        record, created = sources().apply(
            who, name, body.model_dump(mode="json", exclude_none=True)
        )
        return ok(record, 201 if created else 200)

    @app.post("/v1/knowledge/sources/{name}/sync")
    def sync_source(name: str, who: Who) -> JSONResponse:
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
    def erase(body: ErasureRequest, who: Who) -> JSONResponse:
        proof, created = privacy().erase(who, body.model_dump(mode="json", exclude_none=True))
        return ok(proof, 201 if created else 200)

    @app.get("/v1/knowledge/privacy/erasures/{erasure_id}")
    def get_erasure(erasure_id: uuid.UUID, who: Who) -> JSONResponse:
        return ok(privacy().get_erasure(who, erasure_id))

    @app.post("/v1/knowledge/privacy/access")
    def export_personal_data(body: AccessRequest, who: Who) -> JSONResponse:
        return ok(privacy().export(who, body.subject.model_dump(mode="json", exclude_none=True)))

    def leavers() -> Leavers:
        return Leavers(svc(), auth.identity_map_for(resolver))

    @app.get("/v1/knowledge/leaver-reviews")
    def list_leaver_reviews(who: Who) -> JSONResponse:
        return ok({"items": leavers().list(who)})

    @app.post("/v1/knowledge/leaver-reviews/{review_id}/decision")
    def decide_leaver_review(review_id: str, body: LeaverReviewDecision, who: Who) -> JSONResponse:
        return ok(leavers().decide(who, review_id, body.model_dump(mode="json", exclude_none=True)))

    @app.get("/v1/knowledge/leaver-reviews/{review_id}")
    def get_leaver_review(review_id: str, who: Who) -> JSONResponse:
        return ok(leavers().get(who, review_id))

    # Service calls from the control plane. Signed with the tenant's service secret; never a
    # user identity. The signature is checked over the raw body before anything is parsed.
    async def signed(request: Request) -> tuple[uuid.UUID, bytes]:
        body = await request.body()
        tenant = auth.service_tenant(request.headers)
        secret = await run_in_threadpool(leavers().service_secret, tenant)
        auth.verify_service(request.headers, body, secret)
        return tenant, body

    @app.post("/v1/knowledge/internal/leaver-reviews")
    async def open_leaver_review(request: Request) -> JSONResponse:
        tenant, body = await signed(request)
        try:
            doc = LeaverReviewOpen.model_validate_json(body)
        except ValidationError as exc:
            return problem(422, "Document does not match its contract", str(exc.errors()))
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

    if mcp_app is not None:
        app.mount("/mcp/knowledge", require_identity(mcp_app, resolver, knowledge))
    else:

        @app.api_route("/mcp/knowledge/{rest:path}", methods=["GET", "POST", "DELETE"])
        def mcp_refused(rest: str) -> JSONResponse:
            return problem(401, "Unauthorized", headers=unauthorized_headers)

    return app


# Health only: the CLI's `serve` builds the configured app.
app = create_app(None)
