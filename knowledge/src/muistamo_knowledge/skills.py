"""Agent Skills export of a published pack version (FR-312; https://agentskills.io/specification).

Layout of an export:

    <pack>/SKILL.md                 the pack: facts inline, an index of its procedures
    <pack>/references/examples.md   the pack's examples, when it has any
    <pack>-<key>/SKILL.md           one skill per `skill` entry; its body is the procedure

Only a published version's entries are rendered: never personal layers or open proposals.
Output is deterministic (sorted files, fixed timestamps and modes), so the same version always
yields a byte-identical archive. Frontmatter values are JSON-quoted strings, which are valid YAML
and cannot be broken out of by entry text.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from typing import Any

MAX_NAME = 64
MAX_DESCRIPTION = 1024
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def skill_name(*parts: str) -> str:
    """A spec-valid skill name: [a-z0-9] and single hyphens, 1-64 characters."""
    raw = "-".join(parts).lower()
    name = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    name = re.sub(r"-{2,}", "-", name) or "skill"
    if len(name) <= MAX_NAME:
        return name
    tag = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return name[: MAX_NAME - len(tag) - 1].rstrip("-") + "-" + tag


def _description(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_DESCRIPTION else text[: MAX_DESCRIPTION - 1].rstrip() + "…"


def _skill_md(name: str, description: str, metadata: dict[str, str], body: str) -> bytes:
    lines = [
        "---",
        f"name: {name}",
        f"description: {json.dumps(_description(description), ensure_ascii=False)}",
    ]
    lines.append("metadata:")
    for key in sorted(metadata):
        lines.append(f"  {key}: {json.dumps(metadata[key], ensure_ascii=False)}")
    lines += ["---", "", body.rstrip(), ""]
    return "\n".join(lines).encode("utf-8")


def render(pack: str, version: str, layer: str, entries: list[dict[str, Any]]) -> dict[str, bytes]:
    """Files of the export, keyed by path. entries are a pack version's `entries`."""
    base = {"muistamo-pack": pack, "muistamo-version": version, "muistamo-layer": layer}
    by_type: dict[str, list[dict[str, Any]]] = {"fact": [], "skill": [], "example": []}
    for item in sorted(entries, key=lambda e: e["entry"]["key"]):
        by_type[item["entry"]["type"]].append(item["entry"])

    pack_name = skill_name(pack)
    files: dict[str, bytes] = {}
    skill_names: dict[str, str] = {}
    for entry in by_type["skill"]:
        name = skill_name(pack, entry["key"])
        if name == pack_name or name in skill_names.values():
            name = skill_name(
                pack, entry["key"], hashlib.sha256(entry["key"].encode()).hexdigest()[:6]
            )
        skill_names[entry["key"]] = name
        body = [f"# {entry['title']}", "", entry["body"]]
        if entry.get("source"):
            body += ["", f"Source: {entry['source']}"]
        body += [
            "",
            f"From the `{pack}` knowledge pack, version {version}, reviewed and merged in Muistamo.",
        ]
        files[f"{name}/SKILL.md"] = _skill_md(
            name,
            f"{entry['title']}. A reviewed procedure from the {pack} knowledge pack ({layer} layer).",
            {**base, "muistamo-entry-key": entry["key"]},
            "\n".join(body),
        )

    body = [
        f"# {pack}",
        "",
        f"Reviewed knowledge from the `{pack}` pack ({layer} layer), version {version}.",
    ]
    if by_type["fact"]:
        body += ["", "## Facts", ""]
        for entry in by_type["fact"]:
            line = f"- **{entry['title']}** (`{entry['key']}`): {' '.join(entry['body'].split())}"
            if entry.get("source"):
                line += f" Source: {entry['source']}"
            body.append(line)
    if by_type["skill"]:
        body += ["", "## Procedures", ""]
        body += [f"- `{skill_names[e['key']]}`: {e['title']}" for e in by_type["skill"]]
    if by_type["example"]:
        body += ["", "Examples are in [references/examples.md](references/examples.md)."]
        examples = [f"# Examples from {pack} {version}"]
        for entry in by_type["example"]:
            examples += ["", f"## {entry['title']} (`{entry['key']}`)", "", entry["body"].rstrip()]
        files[f"{pack_name}/references/examples.md"] = ("\n".join(examples) + "\n").encode("utf-8")
    counts = ", ".join(
        f"{len(by_type[t])} {t if len(by_type[t]) == 1 else t + 's'}"
        for t in ("fact", "skill", "example")
        if by_type[t]
    )
    files[f"{pack_name}/SKILL.md"] = _skill_md(
        pack_name,
        f"Reviewed company knowledge from the {pack} pack ({layer} layer, version {version}): {counts}. "
        f"Use when a task concerns {pack.replace('-', ' ')}.",
        base,
        "\n".join(body),
    )
    return files


def archive(files: dict[str, bytes]) -> bytes:
    """A deterministic zip of files: sorted, fixed timestamps and permissions."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=FIXED_TIME)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, files[path])
    return out.getvalue()
