SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := test

GOLANGCI_LINT_VERSION := v2.15.0
BIN := $(CURDIR)/bin
GOLANGCI_LINT := $(BIN)/golangci-lint
COMPOSE := docker compose -f deploy/dev/compose.yaml

# Host port of the dev PostgreSQL; override if 5432 is taken (make test POSTGRES_PORT=55432).
POSTGRES_PORT ?= 5432
export POSTGRES_PORT
export MUISTAMO_TEST_DATABASE_URL ?= postgres://muistamo:dev-only-not-a-secret@127.0.0.1:$(POSTGRES_PORT)/muistamo
export MUISTAMO_TEST_TEMPORAL_ADDRESS ?= 127.0.0.1:7233

# The Terraform provider's acceptance tests run against OpenTofu (MPL-2.0), never a BUSL binary.
TOFU ?= $(shell command -v tofu 2>/dev/null)

.PHONY: setup generate check-generated lint test test-db test-authz dev dev-down dev-gateway

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
	diff -r -x __pycache__ "$$tmp/before" contracts/gen >/dev/null || { \
		diff -r -x __pycache__ "$$tmp/before" contracts/gen || true; \
		echo "contracts/gen is stale: run make generate and commit the result" >&2; exit 1; }

lint: check-generated
	$(GOLANGCI_LINT) run ./...
	$(GOLANGCI_LINT) run --build-tags authz ./...
	uv run --no-sync ruff check .
	uv run --no-sync ruff format --check .
	npm run --prefix console lint

# Integration tests need PostgreSQL and Temporal; they fail, never skip, without them.
# TEST_DB_EXTERNAL=1 uses MUISTAMO_TEST_DATABASE_URL and MUISTAMO_TEST_TEMPORAL_ADDRESS as given.
test-db:
	@if [ -n "$${TEST_DB_EXTERNAL:-}" ]; then echo "using external PostgreSQL at MUISTAMO_TEST_DATABASE_URL"; exit 0; fi; \
	command -v docker >/dev/null || { echo "missing required tool: docker" >&2; exit 1; }; \
	$(COMPOSE) up -d --wait postgres temporal

test: test-db
	@[ -n "$(TOFU)" ] || { echo "OpenTofu (tofu) is required for the provider acceptance tests: install it, or set TOFU=/path/to/tofu" >&2; exit 1; }
	TF_ACC=1 TF_ACC_TERRAFORM_PATH="$(TOFU)" TF_ACC_PROVIDER_NAMESPACE=hashicorp TF_ACC_PROVIDER_HOST=registry.opentofu.org go test ./...
	uv run --no-sync pytest -m "not authz"
	npm test --prefix console

# Adversarial permission suite. Never skip or weaken (CLAUDE.md). Both halves always run;
# a skipped Go test counts as a failure, as the pytest conftest does for Python.
test-authz: test-db
	@status=0; \
	go test -count=1 -tags authz -run Authz -v ./control-plane/... | tee /tmp/muistamo-authz-go.log | grep -E '^(--- |ok|FAIL|PASS)' || status=1; \
	if grep -q -- '--- SKIP' /tmp/muistamo-authz-go.log; then echo "authz: Go tests must never be skipped" >&2; status=1; fi; \
	if ! grep -q -- '--- PASS\|--- FAIL' /tmp/muistamo-authz-go.log; then echo "authz: no Go tests ran" >&2; status=1; fi; \
	uv run --no-sync pytest knowledge/tests/authz -m authz -p no:cacheprovider || status=1; \
	exit $$status

dev:
	@command -v docker >/dev/null || { echo "missing required tool: docker" >&2; exit 1; }
	$(COMPOSE) up -d --wait

dev-down:
	$(COMPOSE) --profile gateway down

# The dev gateway for one tenant: renders the checker's and the gateway's configuration from
# deploy/dev/gateway/authz.template.json, then starts or refreshes the gateway profile. Rerun
# after an alias or model change. EVIDENCE_KEY is a key from `control-plane evidence keygen`;
# MUISTAMO_DEV_GATEWAY_DB names another database than the dev one.
DEV_GATEWAY_ENV = MUISTAMO_DEV_EVIDENCE_KEY="$(abspath $(EVIDENCE_KEY))" MUISTAMO_DEV_INGEST_TOKEN="$$(cat deploy/dev/gateway/ingest-token)"
dev-gateway:
	@test -n "$(TENANT)" && test -f "$(EVIDENCE_KEY)" || { echo "usage: make dev-gateway TENANT=<tenant uuid> EVIDENCE_KEY=<evidence key file>" >&2; exit 1; }
	sed 's/@TENANT@/$(TENANT)/' deploy/dev/gateway/authz.template.json > deploy/dev/gateway/authz.json
	@test -s deploy/dev/gateway/ingest-token || printf 'fake-dev-ingest-token-%s' "$$(openssl rand -hex 16)" > deploy/dev/gateway/ingest-token
	go run ./control-plane/cmd/control-plane gateway render-config --config deploy/dev/gateway/authz.json \
		--authz-host gateway-authz:18081 --ingest-host gateway-ingest:4317 --out deploy/dev/gateway/agentgateway.yaml
	$(COMPOSE) --profile gateway build gateway-authz gateway-ingest
	$(DEV_GATEWAY_ENV) $(COMPOSE) --profile gateway up -d --wait --no-start agentgateway
	$(COMPOSE) --profile gateway cp deploy/dev/gateway/agentgateway.yaml agentgateway:/etc/agentgateway/config.yaml
	$(DEV_GATEWAY_ENV) $(COMPOSE) --profile gateway up -d --force-recreate --no-deps gateway-authz gateway-ingest
	$(DEV_GATEWAY_ENV) $(COMPOSE) --profile gateway up -d --wait
