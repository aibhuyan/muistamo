"""Document connectors.

HUMAN REVIEW REQUIRED (CLAUDE.md): this interface is invariant 1's contract.

A connector does two separate things:

- list_documents() feeds the index, using the connector's own indexing credential. The index is
  only a list of candidates; nothing in it reaches a person directly.
- authorise(principal, external_ids) is the use-time check: which of these documents the acting
  person can open right now, decided by the source under that person's own rights. A real
  connector must call the source as (or on behalf of) that person, never with a broadly
  privileged service account: for an Entra caller, principal carries the Graph token the
  control plane delegated to the person's own agent for this request.

Retrieval returns a document only if authorise() named it in the same request. If authorise()
raises, every document from that source is withheld.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class SourceDocument:
    external_id: str
    title: str
    body: str
    url: str | None = None
    modified_at: datetime | None = None


@dataclass(frozen=True)
class Principal:
    """Who a source is asked about: the acting person, and for an Entra caller the Graph token
    delegated to their agent for this one request (never logged, never stored)."""

    person: str
    graph_token: str | None = field(default=None, repr=False)


class ConnectorUnavailable(Exception):
    """The source could not answer. Its documents must be withheld."""


class Connector(Protocol):
    name: str
    is_test: bool

    def list_documents(self) -> list[SourceDocument]: ...

    def authorise(self, principal: Principal, external_ids: list[str]) -> set[str]: ...


# Builds a connector for one source of a tenant from that source's current configuration.
ConnectorFactory = Callable[[str, dict[str, Any], uuid.UUID], Connector]


class NotBuilt(Exception):
    """The connector is part of the contract but has no implementation yet."""


@dataclass
class InMemoryConnector:
    """In-memory connector for development and the adversarial suite. Not a real system.

    Documents and their readers come from the source's `spec.test` configuration, so changing
    the configuration changes what authorise() answers immediately, without re-indexing.
    """

    documents: list[dict[str, Any]]
    name: str = "test"
    is_test: bool = True
    unavailable: bool = False
    calls: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def list_documents(self) -> list[SourceDocument]:
        return [
            SourceDocument(external_id=d["id"], title=d["title"], body=d["body"], url=d.get("url"))
            for d in self.documents
        ]

    def authorise(self, principal: Principal, external_ids: list[str]) -> set[str]:
        with self._lock:
            self.calls.append((principal.person, tuple(external_ids)))
        if self.unavailable:
            raise ConnectorUnavailable("test connector is simulating an outage")
        readers = {d["id"]: set(d.get("readers", [])) for d in self.documents}
        return {i for i in external_ids if principal.person in readers.get(i, set())}


def in_memory_factory(source: str, spec: dict[str, Any], tenant: uuid.UUID) -> Connector:
    return InMemoryConnector(documents=list((spec.get("test") or {}).get("documents", [])))


def default_factories(
    enable_test: bool, sharepoint: ConnectorFactory | None = None
) -> dict[str, ConnectorFactory]:
    """The connectors a service offers. The test connector only when explicitly enabled."""
    from muistamo_knowledge import sharepoint as sp

    factories: dict[str, ConnectorFactory] = {
        "sharepoint": sharepoint or sp.factory_for(lambda tenant: None)
    }
    if enable_test:
        factories["test"] = in_memory_factory
    return factories
