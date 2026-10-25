"""Knowledge service commands: serve, migrate, tenant register, evidence keygen."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import uuid
from pathlib import Path

import psycopg

from muistamo_knowledge import auth, evidence
from muistamo_knowledge.migrate import migrate


def require(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        sys.exit(f"knowledge: {name} is required")
    return value


def serve(_: argparse.Namespace) -> None:
    import uvicorn

    from muistamo_knowledge.app import create_app
    from muistamo_knowledge.connectors import default_factories
    from muistamo_knowledge.db import Database
    from muistamo_knowledge.service import Knowledge

    logging.basicConfig(level=logging.INFO)
    db = Database(require("MUISTAMO_KNOWLEDGE_DATABASE_URL"))
    # Fail closed: without a registered signing key no write could carry evidence.
    key = evidence.LocalKey.load(Path(require("MUISTAMO_KNOWLEDGE_EVIDENCE_KEY_FILE")))
    if not db.key_registered(key.key_id):
        sys.exit(
            f"knowledge: evidence signing key {key.key_id} is not registered; run evidence keygen"
        )
    resolver: auth.Resolver = auth.deny_all
    if os.environ.get("MUISTAMO_INSECURE_DEV_TENANT_HEADER") == "true":
        logging.warning(
            "INSECURE: trusting X-Muistamo-Tenant and X-Muistamo-Actor headers; development only"
        )
        resolver = auth.insecure_dev_headers
    enable_test = os.environ.get("MUISTAMO_ENABLE_TEST_CONNECTOR") == "true"
    if enable_test:
        logging.warning(
            "TEST CONNECTOR enabled: sources may use the in-memory test connector; development only"
        )
    host, _, port = os.environ.get("KNOWLEDGE_ADDR", "127.0.0.1:8001").rpartition(":")
    knowledge = Knowledge(db, key, default_factories(enable_test))
    uvicorn.run(create_app(knowledge, resolver), host=host, port=int(port))


def run_migrate(_: argparse.Namespace) -> None:
    for name in migrate(require("MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL")):
        print(f"applied {name}")


def register_tenant(args: argparse.Namespace) -> None:
    tenant = uuid.UUID(args.tenant)
    with psycopg.connect(require("MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL")) as conn:
        conn.execute("INSERT INTO knowledge.tenants (id) VALUES (%s)", (tenant,))
    print(f"registered tenant {tenant}")


def keygen(args: argparse.Namespace) -> None:
    out = Path(args.out)
    key, pem = evidence.LocalKey.generate()
    # Never overwrite a key: that would orphan every event it signed.
    with out.open("xb") as f:
        f.write(pem)
    out.chmod(0o600)
    Path(f"{out}.pub").write_bytes(key.public_pem())
    with psycopg.connect(require("MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL")) as conn:
        conn.execute(
            "INSERT INTO knowledge.evidence_signing_keys (key_id, algorithm, public_key) VALUES (%s, 'ed25519', %s)",
            (key.key_id, key.public_raw()),
        )
    print(f"key {key.key_id} written to {out} (public half {out}.pub) and registered")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m muistamo_knowledge")
    sub = parser.add_subparsers(required=True)
    sub.add_parser("serve", help="serve the API").set_defaults(fn=serve)
    sub.add_parser("migrate", help="apply schema migrations (owner URL)").set_defaults(
        fn=run_migrate
    )
    tenant = sub.add_parser("tenant", help="manage tenants").add_subparsers(required=True)
    reg = tenant.add_parser("register", help="accept requests for a tenant (owner URL)")
    reg.add_argument("tenant")
    reg.set_defaults(fn=register_tenant)
    ev = sub.add_parser("evidence", help="evidence signing keys").add_subparsers(required=True)
    kg = ev.add_parser("keygen", help="create and register a signing key (owner URL)")
    kg.add_argument("--out", required=True)
    kg.set_defaults(fn=keygen)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
