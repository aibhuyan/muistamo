"""Signed, hash-chained evidence for the knowledge service.

HUMAN REVIEW REQUIRED (CLAUDE.md): signing keys and the evidence chain.

This is a port of control-plane/evidencechain and control-plane/internal/evidence. The format is
byte-identical: SHA-256 over the RFC 8785 canonical JSON of the event body, signed with Ed25519,
one chain per tenant. contracts/testdata/evidence-golden.json pins it for both languages, and
`mst evidence verify` checks chains from either service.

append() runs inside the caller's transaction, so a write and its evidence commit together or not
at all (invariant 4). It locks the tenant's chain head, keeping the sequence gap-free.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from psycopg import Cursor
from psycopg.types.json import Jsonb

GENESIS_HASH = "0" * 64
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class EvidenceNotRecorded(Exception):
    """Evidence could not be recorded. The caller's action must be aborted."""


@dataclass(frozen=True)
class Event:
    tenant: str
    seq: int
    occurred_at: datetime
    actor: str
    action: str
    subject_kind: str
    subject_name: str
    before: Any
    after: Any
    request_id: str
    prev_hash: str
    hash: str = ""
    key_id: str = ""
    signature: str = ""

    def to_json(self) -> dict[str, Any]:
        """The exported shape, identical to the control plane's /v1/events items."""
        return {
            "tenant": self.tenant,
            "seq": self.seq,
            "occurredAt": self.occurred_at.astimezone(UTC).strftime(TIME_FORMAT),
            "actor": self.actor,
            "action": self.action,
            "subject": {"kind": self.subject_kind, "name": self.subject_name},
            "before": self.before,
            "after": self.after,
            "requestId": self.request_id,
            "prevHash": self.prev_hash,
            "hash": self.hash,
            "keyId": self.key_id,
            "signature": self.signature,
        }


def canonical(event: Event) -> bytes:
    """RFC 8785 canonical JSON of the hashed body. hash, keyId and signature are not part of it."""
    body = {
        "tenant": event.tenant,
        "seq": event.seq,
        "occurredAt": event.occurred_at.astimezone(UTC).strftime(TIME_FORMAT),
        "actor": event.actor,
        "action": event.action,
        "subject": {"kind": event.subject_kind, "name": event.subject_name},
        "before": event.before,
        "after": event.after,
        "requestId": event.request_id,
        "prevHash": event.prev_hash,
    }
    return rfc8785.dumps(body)


def event_hash(event: Event) -> str:
    return hashlib.sha256(canonical(event)).hexdigest()


def key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:32]


class LocalKey:
    """An Ed25519 key in a local PKCS#8 PEM file. Release 1 only; KMS signers replace it."""

    def __init__(self, private: Ed25519PrivateKey) -> None:
        self._private = private

    @classmethod
    def generate(cls) -> tuple[LocalKey, bytes]:
        private = Ed25519PrivateKey.generate()
        pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return cls(private), pem

    @classmethod
    def load(cls, path: Path) -> LocalKey:
        private = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError(f"{path}: not an Ed25519 private key")
        return cls(private)

    @property
    def public(self) -> Ed25519PublicKey:
        return self._private.public_key()

    @property
    def key_id(self) -> str:
        return key_id(self.public)

    def public_pem(self) -> bytes:
        return self.public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def public_raw(self) -> bytes:
        return self.public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, digest: bytes) -> bytes:
        return self._private.sign(digest)


def append(
    cur: Cursor,
    signer: LocalKey,
    *,
    tenant: UUID,
    actor: str,
    action: str,
    subject_kind: str,
    subject_name: str,
    request_id: str,
    before: Any = None,
    after: Any = None,
) -> Event:
    """Record the next event in the tenant's chain inside the caller's transaction."""
    try:
        cur.execute(
            "INSERT INTO knowledge.evidence_heads (tenant_id, seq, hash) VALUES (%s, 0, %s)"
            " ON CONFLICT (tenant_id) DO NOTHING",
            (tenant, GENESIS_HASH),
        )
        cur.execute(
            "SELECT seq, hash FROM knowledge.evidence_heads WHERE tenant_id = %s FOR UPDATE",
            (tenant,),
        )
        row = cur.fetchone()
        if row is None:
            raise EvidenceNotRecorded("chain head missing")
        seq, prev = row
        # Round-trip through JSON so the hashed values equal what the database will return.
        before = _json_value(before)
        after = _json_value(after)
        now = datetime.now(UTC)  # microsecond precision, as stored by PostgreSQL
        unsigned = Event(
            tenant=str(tenant),
            seq=seq + 1,
            occurred_at=now,
            actor=actor,
            action=action,
            subject_kind=subject_kind,
            subject_name=subject_name,
            before=before,
            after=after,
            request_id=request_id,
            prev_hash=prev,
            key_id=signer.key_id,
        )
        digest_hex = event_hash(unsigned)
        signature = base64.b64encode(signer.sign(bytes.fromhex(digest_hex))).decode()
        event = Event(**{**unsigned.__dict__, "hash": digest_hex, "signature": signature})
        cur.execute(
            "INSERT INTO knowledge.evidence_events (tenant_id, seq, occurred_at, actor, action,"
            " subject_kind, subject_name, before, after, request_id, prev_hash, hash, key_id,"
            " signature) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                tenant,
                event.seq,
                event.occurred_at,
                actor,
                action,
                subject_kind,
                subject_name,
                _db_json(before),
                _db_json(after),
                request_id,
                prev,
                event.hash,
                event.key_id,
                event.signature,
            ),
        )
        cur.execute(
            "UPDATE knowledge.evidence_heads SET seq = %s, hash = %s WHERE tenant_id = %s",
            (event.seq, event.hash, tenant),
        )
    except EvidenceNotRecorded:
        raise
    except Exception as exc:  # noqa: BLE001 - any failure means the evidence is missing
        raise EvidenceNotRecorded(f"{action} for {subject_kind} {subject_name!r}: {exc}") from exc
    return event


def list_events(cur: Cursor, after_seq: int, limit: int) -> list[Event]:
    """The tenant's events after after_seq, in order. Row-level security scopes cur."""
    cur.execute(
        "SELECT tenant_id, seq, occurred_at, actor, action, subject_kind, subject_name, before,"
        " after, request_id, prev_hash, hash, key_id, signature FROM knowledge.evidence_events"
        " WHERE seq > %s ORDER BY seq LIMIT %s",
        (after_seq, limit),
    )
    return [
        Event(
            tenant=str(r[0]),
            seq=r[1],
            occurred_at=r[2].astimezone(UTC),
            actor=r[3],
            action=r[4],
            subject_kind=r[5],
            subject_name=r[6],
            before=r[7],
            after=r[8],
            request_id=r[9],
            prev_hash=r[10],
            hash=r[11],
            key_id=r[12],
            signature=r[13],
        )
        for r in cur.fetchall()
    ]


class VerifyError(Exception):
    def __init__(self, seq: int, reason: str) -> None:
        super().__init__(f"evidence seq {seq}: {reason}")
        self.seq = seq
        self.reason = reason


def verify(events: list[Event], keys: dict[str, Ed25519PublicKey]) -> None:
    """Same checks as evidencechain.Verify: contiguous from 1, links, hashes, signatures."""
    if not events:
        raise VerifyError(0, "no events to verify")
    prev = GENESIS_HASH
    for i, e in enumerate(events):
        want = i + 1
        if e.seq != want:
            raise VerifyError(want, f"missing or out of order: found seq {e.seq}")
        if e.tenant != events[0].tenant:
            raise VerifyError(e.seq, "belongs to a different tenant's chain")
        if e.prev_hash != prev:
            raise VerifyError(e.seq, "prevHash does not match the previous event's hash")
        if event_hash(e) != e.hash:
            raise VerifyError(e.seq, "content does not match its hash")
        key = keys.get(e.key_id)
        if key is None:
            raise VerifyError(e.seq, f"signed by unknown key {e.key_id}")
        try:
            key.verify(base64.b64decode(e.signature), bytes.fromhex(e.hash))
        except (InvalidSignature, ValueError) as exc:
            raise VerifyError(e.seq, "signature is not valid") from exc
        prev = e.hash


def _json_value(value: Any) -> Any:
    return None if value is None else json.loads(json.dumps(value, default=str))


def _db_json(value: Any) -> Any:
    return None if value is None else Jsonb(value)
