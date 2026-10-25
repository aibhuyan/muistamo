"""Forward-only SQL migrations for the knowledge schema, applied in file-name order."""

from __future__ import annotations

from pathlib import Path

import psycopg

MIGRATIONS = Path(__file__).resolve().parents[2] / "migrations"


def migrate(owner_url: str) -> list[str]:
    """Apply pending migrations as the schema owner. Returns the names applied."""
    applied: list[str] = []
    with psycopg.connect(owner_url, autocommit=True) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS public.knowledge_schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        done = {r[0] for r in conn.execute("SELECT name FROM public.knowledge_schema_migrations")}
        for path in sorted(MIGRATIONS.glob("*.sql")):
            if path.name in done:
                continue
            with conn.transaction():
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute(
                    "INSERT INTO public.knowledge_schema_migrations (name) VALUES (%s)",
                    (path.name,),
                )
            applied.append(path.name)
    return applied
