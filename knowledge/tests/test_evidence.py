import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from muistamo_knowledge import evidence
from muistamo_knowledge.evidence import Event

TESTDATA = Path(__file__).resolve().parents[2] / "contracts" / "testdata"
GOLDEN = json.loads((TESTDATA / "evidence-golden.json").read_text(encoding="utf-8"))
SEED = bytes.fromhex(GOLDEN["testSeedHex"])


def golden_event() -> Event:
    b = GOLDEN["body"]
    return Event(
        tenant=b["tenant"],
        seq=b["seq"],
        occurred_at=datetime(2026, 10, 25, 10, 0, 0, tzinfo=UTC),
        actor=b["actor"],
        action=b["action"],
        subject_kind=b["subject"]["kind"],
        subject_name=b["subject"]["name"],
        before=b["before"],
        after=b["after"],
        request_id=b["requestId"],
        prev_hash=b["prevHash"],
    )


def test_golden_vector_matches_go() -> None:
    assert evidence.canonical(golden_event()).decode() == GOLDEN["canonical"]
    assert evidence.event_hash(golden_event()) == GOLDEN["hash"]
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    assert evidence.key_id(key.public_key()) == GOLDEN["keyId"]
    signature = key.sign(bytes.fromhex(GOLDEN["hash"]))
    assert base64.b64encode(signature).decode() == GOLDEN["signature"]


def build_chain(n: int) -> list[Event]:
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    kid = evidence.key_id(key.public_key())
    chain, prev = [], evidence.GENESIS_HASH
    for seq in range(1, n + 1):
        e = Event(
            tenant="00000000-0000-0000-0000-000000000001",
            seq=seq,
            occurred_at=datetime(2026, 10, 25, 10, 0, seq, 123456, tzinfo=UTC),
            actor="dev:person-a@example.invalid",
            action="knowledge.entry.captured",
            subject_kind="KnowledgeEntry",
            subject_name=f"entry-{seq}",
            before=None,
            after={"key": f"k{seq}", "nested": {"b": 2, "a": [1, "x"]}},
            request_id=f"req-{seq}",
            prev_hash=prev,
            key_id=kid,
        )
        h = evidence.event_hash(e)
        sig = base64.b64encode(key.sign(bytes.fromhex(h))).decode()
        e = Event(**{**e.__dict__, "hash": h, "signature": sig})
        chain.append(e)
        prev = h
    return chain


def from_json(item: dict) -> Event:
    occurred = datetime.fromisoformat(item["occurredAt"].replace("Z", "+00:00"))
    return Event(
        tenant=item["tenant"],
        seq=item["seq"],
        occurred_at=occurred,
        actor=item["actor"],
        action=item["action"],
        subject_kind=item["subject"]["kind"],
        subject_name=item["subject"]["name"],
        before=item["before"],
        after=item["after"],
        request_id=item["requestId"],
        prev_hash=item["prevHash"],
        hash=item["hash"],
        key_id=item["keyId"],
        signature=item["signature"],
    )


def keys() -> dict:
    public = Ed25519PrivateKey.from_private_bytes(SEED).public_key()
    return {evidence.key_id(public): public}


def test_python_chain_fixture_is_current() -> None:
    """The fixture Go verifies (evidencechain TestVerifiesPythonChain) is this exact chain."""
    lines = [json.dumps(e.to_json(), separators=(",", ":")) for e in build_chain(3)]
    fixture = TESTDATA / "evidence-chain-python.jsonl"
    if os.environ.get("MUISTAMO_UPDATE_FIXTURES") == "1":
        fixture.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    assert fixture.read_text(encoding="utf-8").splitlines() == lines


def test_verifies_go_chain() -> None:
    """A chain produced by Go (evidencechain TestGoChainFixtureIsCurrent) verifies in Python."""
    lines = (TESTDATA / "evidence-chain-go.jsonl").read_text(encoding="utf-8").splitlines()
    evidence.verify([from_json(json.loads(line)) for line in lines], keys())


@pytest.mark.parametrize(
    ("tamper", "want_seq"),
    [
        (lambda c: c.__setitem__(1, Event(**{**c[1].__dict__, "after": {"key": "x"}})), 2),
        (lambda c: c.pop(1), 2),
        (lambda c: c.reverse(), 1),
        (lambda c: c.__setitem__(2, Event(**{**c[2].__dict__, "signature": c[1].signature})), 3),
        (lambda c: c.__setitem__(0, Event(**{**c[0].__dict__, "key_id": "0" * 32})), 1),
    ],
    ids=["edited", "deleted", "reordered", "wrong-signature", "unknown-key"],
)
def test_verify_detects_tampering(tamper, want_seq: int) -> None:
    chain = build_chain(3)
    evidence.verify(chain, keys())
    tamper(chain)
    with pytest.raises(evidence.VerifyError) as err:
        evidence.verify(chain, keys())
    assert err.value.seq == want_seq
