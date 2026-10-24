#!/usr/bin/env bash
# Regenerates every language's types from contracts/schemas. Run via `make generate`.
set -euo pipefail

cd "$(dirname "$0")/.."

schemas=contracts/schemas
py_out=contracts/gen/python/src/muistamo_contracts/v1
go_out=contracts/gen/go/muistamov1

rm -rf "$py_out" "$go_out"
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

go tool go-jsonschema \
  --package muistamov1 \
  --struct-name-from-title \
  --output "$go_out/types.gen.go" \
  "$schemas"/common/*.json "$schemas"/*.json

gofmt -w "$go_out"
