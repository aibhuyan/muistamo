"""Knowledge service commands: serve, migrate, tenant register, privacy officers, evidence keygen."""

from __future__ import annotations

import argparse
import json
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


def sweep_decay(args: argparse.Namespace) -> None:
    """Remove expired pack entries (FR-307). Run it on a schedule; expired entries are withheld
    from agents whether or not it has run, so a late sweep never serves them."""
    from muistamo_knowledge.db import Database
    from muistamo_knowledge.service import Knowledge

    logging.basicConfig(level=logging.INFO)
    db = Database(require("MUISTAMO_KNOWLEDGE_DATABASE_URL"))
    key = evidence.LocalKey.load(Path(require("MUISTAMO_KNOWLEDGE_EVIDENCE_KEY_FILE")))
    if not db.key_registered(key.key_id):
        sys.exit(
            f"knowledge: evidence signing key {key.key_id} is not registered; run evidence keygen"
        )
    knowledge = Knowledge(db, key)
    # Tenants are named, never discovered: row-level security deliberately stops the server role
    # from listing other tenants, so the scheduler passes the tenants it sweeps.
    failed = 0
    for tenant in args.tenant:
        try:
            removed = knowledge.sweep_decay(tenant)
        except Exception:
            failed += 1
            logging.exception("decay sweep failed", extra={"tenant": str(tenant)})
            continue
        print(json.dumps({"tenant": str(tenant), "removed": removed}, sort_keys=True))
    if failed:
        sys.exit(f"knowledge: decay sweep failed for {failed} tenant(s)")


def run_migrate(_: argparse.Namespace) -> None:
    for name in migrate(require("MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL")):
        print(f"applied {name}")


def register_tenant(args: argparse.Namespace) -> None:
    tenant = uuid.UUID(args.tenant)
    with psycopg.connect(require("MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL")) as conn:
        conn.execute("INSERT INTO knowledge.tenants (id) VALUES (%s)", (tenant,))
    print(f"registered tenant {tenant}")


def set_service_secret(args: argparse.Namespace) -> None:
    from muistamo_knowledge.leavers import set_service_secret as store

    tenant = uuid.UUID(args.tenant)
    store(require("MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL"), tenant, args.secret.encode())
    print(f"tenant {tenant} service secret stored")


def set_privacy_officers(args: argparse.Namespace) -> None:
    from muistamo_knowledge.privacy import replace_officers

    tenant = uuid.UUID(args.tenant)
    replace_officers(require("MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL"), tenant, args.officers)
    print(f"tenant {tenant} now has {len(args.officers)} privacy officers")


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
    ss = tenant.add_parser(
        "service-secret", help="store the secret the control plane signs calls with (owner URL)"
    )
    ss.add_argument("tenant")
    ss.add_argument("secret", help="as printed by control-plane tenant knowledge-secret")
    ss.set_defaults(fn=set_service_secret)
    priv = sub.add_parser("privacy", help="privacy officers").add_subparsers(required=True)
    po = priv.add_parser("officers", help="replace the tenant's privacy officers (owner URL)")
    po.add_argument("tenant")
    po.add_argument("officers", nargs="+")
    po.set_defaults(fn=set_privacy_officers)
    dc = sub.add_parser("decay", help="knowledge decay (FR-307)").add_subparsers(required=True)
    sw = dc.add_parser("sweep", help="remove expired pack entries (server URL and signing key)")
    sw.add_argument(
        "--tenant", type=uuid.UUID, action="append", required=True, help="a tenant to sweep; repeat"
    )
    sw.set_defaults(fn=sweep_decay)
    ev = sub.add_parser("evidence", help="evidence signing keys").add_subparsers(required=True)
    kg = ev.add_parser("keygen", help="create and register a signing key (owner URL)")
    kg.add_argument("--out", required=True)
    kg.set_defaults(fn=keygen)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
