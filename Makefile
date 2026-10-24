SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := test

GOLANGCI_LINT_VERSION := v2.15.0
BIN := $(CURDIR)/bin
GOLANGCI_LINT := $(BIN)/golangci-lint
COMPOSE := docker compose -f deploy/dev/compose.yaml

.PHONY: setup generate check-generated lint test test-authz dev dev-down

setup:
	@for tool in go uv npm; do command -v $$tool >/dev/null || { echo "missing required tool: $$tool" >&2; exit 1; }; done
	go mod download
	uv sync --all-packages --locked
	npm ci --prefix console
	GOBIN=$(BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

generate:
	bash contracts/generate.sh

# Regenerates into a scratch copy and fails if the committed output differs.
check-generated:
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	cp -r contracts/gen "$$tmp/before"; \
	bash contracts/generate.sh; \
	diff -r "$$tmp/before" contracts/gen >/dev/null || { \
		diff -r "$$tmp/before" contracts/gen || true; \
		echo "contracts/gen is stale: run make generate and commit the result" >&2; exit 1; }

lint: check-generated
	$(GOLANGCI_LINT) run ./...
	uv run --no-sync ruff check .
	uv run --no-sync ruff format --check .
	uv run --no-sync datamodel-codegen --input contracts/openapi/muistamo.v1.yaml \
		--input-file-type openapi --output-model-type pydantic_v2.BaseModel >/dev/null
	npm run --prefix console lint

test:
	go test ./...
	uv run --no-sync pytest -m "not authz"
	npm test --prefix console

# Adversarial permission suite. Never skip or weaken (CLAUDE.md).
test-authz:
	uv run --no-sync pytest knowledge/tests/authz -m authz -p no:cacheprovider

dev:
	@command -v docker >/dev/null || { echo "missing required tool: docker" >&2; exit 1; }
	$(COMPOSE) up -d --wait

dev-down:
	$(COMPOSE) down
