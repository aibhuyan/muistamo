"""Automated checks on every proposal (definition section 5).

These are deliberately simple, deterministic rules: a starting subset, not the full design
(Presidio, the gitleaks rule set and OWASP Agent Memory Guard come later). Findings name the
rule and entry but never echo a matched secret or personal-data value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

BLOCKING = "blocking"
WARNING = "warning"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    entry_key: str
    message: str


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    pattern: re.Pattern[str]
    message: str


RULES = [
    # Secrets (a subset of gitleaks-style patterns).
    Rule(
        "secret.private-key",
        BLOCKING,
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "contains a private key",
    ),
    Rule(
        "secret.aws-access-key",
        BLOCKING,
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "contains an AWS access key id",
    ),
    Rule(
        "secret.github-token",
        BLOCKING,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "contains a GitHub token",
    ),
    Rule(
        "secret.api-key",
        BLOCKING,
        re.compile(r"\b(sk|rk|pk)-[A-Za-z0-9_-]{20,}\b"),
        "contains an API key",
    ),
    Rule(
        "secret.assignment",
        BLOCKING,
        re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{8,}"),
        "contains what looks like a credential assignment",
    ),
    # Personal data.
    Rule(
        "pii.email",
        BLOCKING,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "contains an email address",
    ),
    Rule(
        "pii.iban",
        BLOCKING,
        re.compile(r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b"),
        "contains an IBAN",
    ),
    Rule(
        "pii.finnish-personal-id",
        BLOCKING,
        re.compile(
            r"\b(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])[0-9]{2}[-+A-FU-Y][0-9]{3}[0-9A-Y]\b"
        ),
        "contains a Finnish personal identity code",
    ),
    # Prompt injection (ASI06): instructions aimed at the agent rather than knowledge.
    Rule(
        "injection.override",
        BLOCKING,
        re.compile(
            r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b.{0,20}\b(instructions?|rules?|prompts?)\b"
        ),
        "contains an instruction-override phrase",
    ),
    Rule(
        "injection.role",
        BLOCKING,
        re.compile(r"(?i)\b(you are now|act as|new system prompt|system:\s)"),
        "tries to change the agent's role or system prompt",
    ),
]


def check_entry(key: str, title: str, body: str, source: str | None) -> list[Finding]:
    text = "\n".join(part for part in (title, body, source or "") if part)
    return [Finding(r.rule_id, r.severity, key, r.message) for r in RULES if r.pattern.search(text)]


def duplicate(key: str, body: str, existing: dict[str, str]) -> list[Finding]:
    """Warn when the pack already holds the same key with identical content."""
    if existing.get(key) is not None and existing[key].strip() == body.strip():
        return [Finding("duplicate.exact", WARNING, key, "the pack already holds this exact entry")]
    return []


def blocked(findings: list[Finding]) -> bool:
    return any(f.severity == BLOCKING for f in findings)
