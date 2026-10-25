"""HTTP API of the knowledge service (contracts/openapi/knowledge.v1.yaml).

No `from __future__ import annotations` here: FastAPI must resolve the dependency annotations
defined inside create_app at definition time.
"""

import logging
import uuid
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from muistamo_contracts.v1.common.healthstatus import HealthStatus, Status
from muistamo_contracts.v1.knowledgeentryinput import KnowledgeEntryInput
from muistamo_contracts.v1.knowledgepack import KnowledgePack
from muistamo_contracts.v1.knowledgesource import KnowledgeSource
from muistamo_contracts.v1.proposaldecision import ProposalDecision
from muistamo_contracts.v1.proposalinput import ProposalInput
from muistamo_contracts.v1.rollbackinput import RollbackInput

from muistamo_knowledge import evidence
from muistamo_knowledge.auth import Resolver, Unauthenticated, deny_all
from muistamo_knowledge.db import UnknownTenant
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


def problem(status: int, title: str, detail: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"title": title, "status": status}
    if detail:
        body["detail"] = detail
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


def create_app(knowledge: Knowledge | None, resolver: Resolver = deny_all) -> FastAPI:
    """Without a Knowledge service (no database or key), every /v1 call is refused."""
    app = FastAPI(title="muistamo-knowledge")

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
                return problem(status, title, None if status in (401, 503) else str(exc))
        log.exception("unhandled error", extra={"path": request.url.path})
        return problem(500, "Internal error")

    def actor(request: Request) -> Actor:
        if knowledge is None:
            raise Unauthenticated("knowledge service not configured")
        tenant, name = resolver(request)
        return Actor(tenant=tenant, name=name, request_id=str(uuid.uuid4()))

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

    @app.post("/v1/knowledge/packs/{name}/rollback")
    def rollback(name: str, body: RollbackInput, who: Who) -> JSONResponse:
        return ok(svc().rollback(who, name, body.toVersion, body.reason), 201)

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

    return app


# Health only: the CLI's `serve` builds the configured app.
app = create_app(None)
