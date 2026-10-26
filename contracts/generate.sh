#!/usr/bin/env bash
# Regenerates every language's types from contracts/. Run via `make generate`.
set -euo pipefail

cd "$(dirname "$0")/.."

schemas=contracts/schemas
bundle=contracts/gen/openapi/muistamo.v1.bundled.yaml
py_out=contracts/gen/python/src/muistamo_contracts/v1
go_out=contracts/gen/go/muistamov1

rm -rf "$py_out" "$go_out" "$(dirname "$bundle")"
mkdir -p "$py_out" "$go_out"

uv run --no-sync datamodel-codegen \
  --input "$schemas" \
  --input-file-type jsonschema \
  --output "$py_out" \
  --output-model-type pydantic_v2.BaseModel \
  --target-python-version 3.12 \
  --use-annotated \
  --field-constraints \
  --use-title-as-name \
  --disable-timestamp \
  --formatters ruff-format
# datamodel-codegen writes the platform's line endings; generated code is LF everywhere, so
# check-generated compares like with like on Windows too.
uv run --no-sync python -c '
import pathlib, sys
for path in pathlib.Path(sys.argv[1]).rglob("*.py"):
    data = path.read_bytes()
    if b"\r\n" in data:
        path.write_bytes(data.replace(b"\r\n", b"\n"))
' "$py_out"

# oapi-codegen inlines external $refs as anonymous types, so it reads a bundled document.
uv run --no-sync python contracts/bundle.py contracts/openapi/muistamo.v1.yaml "$bundle"
# The knowledge service's API; bundling also proves every $ref in it resolves.
uv run --no-sync python contracts/bundle.py contracts/openapi/knowledge.v1.yaml "$(dirname "$bundle")/knowledge.v1.bundled.yaml"
go tool oapi-codegen -config contracts/oapi-codegen.yaml "$bundle"

gofmt -w "$go_out"

# The console's TypeScript types, from the same bundled documents.
ts_out=contracts/gen/ts
rm -rf "$ts_out"
mkdir -p "$ts_out"
console/node_modules/.bin/openapi-typescript "$bundle" -o "$ts_out/muistamo.ts" >/dev/null
console/node_modules/.bin/openapi-typescript "$(dirname "$bundle")/knowledge.v1.bundled.yaml" -o "$ts_out/knowledge.ts" >/dev/null
