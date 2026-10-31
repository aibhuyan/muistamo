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


def caller_modes() -> tuple[bool, bool]:
    """Whether callers use development headers or Entra tokens. Never both: a header could
    otherwise claim what a token has to prove."""
    dev_headers = os.environ.get("MUISTAMO_INSECURE_DEV_TENANT_HEADER") == "true"
    entra_callers = os.environ.get("MUISTAMO_KNOWLEDGE_ENTRA") == "true"
    if dev_headers and entra_callers:
        sys.exit("knowledge: choose Entra callers or development headers, not both")
    return dev_headers, entra_callers


def serve(_: argparse.Namespace) -> None:
    import uvicorn

    from muistamo_knowledge.app import create_app
    from muistamo_knowledge.connectors import default_factories
    from muistamo_knowledge.db import Database
    from muistamo_knowledge.service import Knowledge

    logging.basicConfig(level=logging.INFO)
    dev_headers, entra_callers = caller_modes()
    db = Database(require("MUISTAMO_KNOWLEDGE_DATABASE_URL"))
    # Fail closed: without a registered signing key no write could carry evidence.
    key = evidence.LocalKey.load(Path(require("MUISTAMO_KNOWLEDGE_EVIDENCE_KEY_FILE")))
    if not db.key_registered(key.key_id):
        sys.exit(
            f"knowledge: evidence signing key {key.key_id} is not registered; run evidence keygen"
        )
    resolver: auth.Resolver = auth.deny_all
    if dev_headers:
        logging.warning(
            "INSECURE: trusting X-Muistamo-Tenant and X-Muistamo-Actor headers; development only"
        )
        resolver = auth.insecure_dev_headers
    if entra_callers:
        from muistamo_knowledge import entra

        logging.info("callers authenticate with Entra access tokens (tenant entra registrations)")
        logging.warning(
            "ENTRA CALLERS ARE NOT YET LIFECYCLE-CHECKED: any person the blueprint admits is a"
            " caller, and a leaver's personal layer is not frozen for review until callers are"
            " matched to HR people. Require user assignment on the enterprise application."
        )
        resolver = entra.EntraBearer(entra.registrations(db))
    enable_test = os.environ.get("MUISTAMO_ENABLE_TEST_CONNECTOR") == "true"
    if enable_test:
        logging.warning(
            "TEST CONNECTOR enabled: sources may use the in-memory test connector; development only"
        )
    host, _, port = os.environ.get("KNOWLEDGE_ADDR", "127.0.0.1:8001").rpartition(":")
    sharepoint = None
    if indexers := os.environ.get("MUISTAMO_SHAREPOINT_INDEXERS", ""):
        from muistamo_knowledge import sharepoint as sp

        # The operator's file names each tenant's read-only indexer app; secrets in their own files.
        sharepoint = sp.factory_for(sp.load_indexers(indexers))
    else:
        logging.warning(
            "MUISTAMO_SHAREPOINT_INDEXERS is not set: SharePoint sources cannot be indexed"
        )
    knowledge = Knowledge(db, key, default_factories(enable_test, sharepoint))
    if entra_callers:
        from muistamo_knowledge.delegation import DelegationClient
        from muistamo_knowledge.leavers import Leavers

        url = os.environ.get("MUISTAMO_CONTROL_PLANE_URL", "")
        plaintext = os.environ.get("MUISTAMO_KNOWLEDGE_CONTROL_PLANE_PLAINTEXT") == "true"
        if url and not url.startswith("https://") and not plaintext:
            # Delegations carry bearer tokens: TLS, unless explicitly a development loopback.
            sys.exit("knowledge: MUISTAMO_CONTROL_PLANE_URL must be https")
        if url:
            if plaintext:
                logging.warning("INSECURE: delegations travel without TLS; development only")
            leavers = Leavers(knowledge, auth.no_identity_map)
            knowledge.delegations = DelegationClient(url, leavers.service_secret)
        else:
            logging.warning(
                "MUISTAMO_CONTROL_PLANE_URL is not set: Entra callers get no delegation, so only"
                " their personal layer and mandatory packs are searched and no source is asked"
            )
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
    # From stdin unless given, so it need not appear in the process list.
    secret = args.secret if args.secret is not None else sys.stdin.readline().strip()
    store(require("MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL"), tenant, secret.encode())
    print(f"tenant {tenant} service secret stored")


def set_entra_tenant(args: argparse.Namespace) -> None:
    from muistamo_knowledge import entra

    tenant = uuid.UUID(args.tenant)
    directory, audience = uuid.UUID(args.entra_tenant), uuid.UUID(args.audience)
    url = require("MUISTAMO_KNOWLEDGE_MIGRATE_DATABASE_URL")
    try:
        previous = entra.register(url, tenant, directory, audience, replace=args.replace)
    except entra.AlreadyRegistered as exc:
        sys.exit(f"knowledge: {exc}; pass --replace to re-point it (its callers lose access)")
    if previous is not None and previous != (directory, audience):
        print(f"tenant {tenant} replaced directory {previous[0]} audience {previous[1]}")
    print(f"tenant {tenant} accepts Entra tokens of directory {directory} for audience {audience}")


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
    ss.add_argument(
        "secret",
        nargs="?",
        help="as printed by control-plane tenant knowledge-secret; stdin if omitted",
    )
    ss.set_defaults(fn=set_service_secret)
    en = tenant.add_parser(
        "entra", help="accept Entra access tokens of a directory for a tenant (owner URL)"
    )
    en.add_argument("tenant")
    en.add_argument("entra_tenant", help="the Entra directory (tenant) id")
    en.add_argument("audience", help="the tenant's Muistamo blueprint app id")
    en.add_argument(
        "--replace", action="store_true", help="re-point a tenant already mapped to a directory"
    )
    en.set_defaults(fn=set_entra_tenant)
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
