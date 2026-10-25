"""PostgreSQL access. Every query against tenant data runs inside in_tenant().

in_tenant sets muistamo.tenant_id for the transaction only, as the control plane's InTenant
does. Row-level security does the filtering; nothing here adds tenant predicates, so a
forgotten predicate cannot widen access.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from psycopg import Cursor
from psycopg_pool import ConnectionPool


class UnknownTenant(Exception):
    """The tenant is not registered with the knowledge service."""


class Database:
    def __init__(self, url: str) -> None:
        self.pool = ConnectionPool(url, min_size=1, max_size=10, open=True)
        self.pool.wait(timeout=10)

    def close(self) -> None:
        self.pool.close()

    @contextmanager
    def in_tenant(self, tenant: UUID) -> Iterator[Cursor]:
        """A cursor in a transaction scoped to tenant. Commits only if the block succeeds."""
        with self.pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute("SELECT set_config('muistamo.tenant_id', %s, true)", (str(tenant),))
            cur.execute("SELECT EXISTS (SELECT 1 FROM knowledge.tenants WHERE id = %s)", (tenant,))
            row = cur.fetchone()
            if row is None or not row[0]:
                raise UnknownTenant(str(tenant))
            yield cur

    def key_registered(self, key_id: str) -> bool:
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM knowledge.evidence_signing_keys WHERE key_id = %s)",
                (key_id,),
            )
            row = cur.fetchone()
            return bool(row and row[0])
