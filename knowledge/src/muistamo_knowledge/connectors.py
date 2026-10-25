"""Document connectors.

HUMAN REVIEW REQUIRED (CLAUDE.md): this interface is invariant 1's contract.

A connector does two separate things:

- list_documents() feeds the index, using the connector's own indexing credential. The index is
  only a list of candidates; nothing in it reaches a person directly.
- authorise(person, external_ids) is the use-time check: which of these documents the acting
  person can open right now, decided by the source under that person's own rights. A real
  connector must call the source as (or on behalf of) that person, never with a broadly
  privileged service account.

Retrieval returns a document only if authorise() named it in the same request. If authorise()
raises, every document from that source is withheld.
"""

from __future__ import annotations

import threading
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


class ConnectorUnavailable(Exception):
    """The source could not answer. Its documents must be withheld."""


class Connector(Protocol):
    name: str
    is_test: bool

    def list_documents(self) -> list[SourceDocument]: ...

    def authorise(self, person: str, external_ids: list[str]) -> set[str]: ...


# Builds a connector for one source from that source's current configuration.
ConnectorFactory = Callable[[str, dict[str, Any]], Connector]


class NotBuilt(Exception):
    """The connector is part of the contract but has no implementation yet."""


def sharepoint_factory(source: str, spec: dict[str, Any]) -> Connector:
    raise NotBuilt(
        "the SharePoint connector is not built yet; it needs an Entra test tenant and an app registration "
        "so that authorisation runs on behalf of each person (FR-201-203)"
    )


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

    def authorise(self, person: str, external_ids: list[str]) -> set[str]:
        with self._lock:
            self.calls.append((person, tuple(external_ids)))
        if self.unavailable:
            raise ConnectorUnavailable("test connector is simulating an outage")
        readers = {d["id"]: set(d.get("readers", [])) for d in self.documents}
        return {i for i in external_ids if person in readers.get(i, set())}


def in_memory_factory(source: str, spec: dict[str, Any]) -> Connector:
    return InMemoryConnector(documents=list((spec.get("test") or {}).get("documents", [])))


def default_factories(enable_test: bool) -> dict[str, ConnectorFactory]:
    """The connectors a service offers. The test connector only when explicitly enabled."""
    factories: dict[str, ConnectorFactory] = {"sharepoint": sharepoint_factory}
    if enable_test:
        factories["test"] = in_memory_factory
    return factories
