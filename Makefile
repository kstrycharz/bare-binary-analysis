# BARE task runner.
#
# Windows users without `make`: run `./make.ps1 <target>`, which forwards to the
# same commands. Keep the two in sync — every target added here needs an entry
# there, and `make.ps1 --list` is checked against this file in CI.

SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE := docker compose
COMPOSE_DEV := $(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml
PY := uv run
RUN_ROOT ?= /var/lib/bare/runs

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- environment ------------------------------------------------------------

.PHONY: install
install: ## Resolve and install Python dependencies into .venv
	uv sync --extra dev

.PHONY: run-root
run-root: ## Create the per-run staging directory the worker and daemon share
	mkdir -p $(RUN_ROOT)
	chmod 0771 $(RUN_ROOT)

# --- development ------------------------------------------------------------

.PHONY: dev
dev: run-root ## Boot the full stack with source reload
	$(COMPOSE_DEV) up --build

.PHONY: dev-detached
dev-detached: run-root ## Boot the stack in the background
	$(COMPOSE_DEV) up --build -d

.PHONY: down
down: ## Stop the stack, keeping volumes
	$(COMPOSE_DEV) down --remove-orphans

.PHONY: clean
clean: ## Stop the stack and delete its volumes (destroys uploaded artifacts)
	$(COMPOSE_DEV) down --remove-orphans --volumes

.PHONY: logs
logs: ## Follow logs for all services
	$(COMPOSE_DEV) logs -f

.PHONY: shell
shell: ## Open a shell in the API container
	$(COMPOSE_DEV) exec api /bin/bash

# --- analyzer images --------------------------------------------------------
#
# The tag these are built with, and the tag the orchestrator runs, come from the
# same variable, so `make images` and a scan cannot disagree about which image
# they mean. `?=` keeps the environment authoritative: BARE_ANALYZER_TAG
# set in the shell (or in .env, exported) wins, and an unset variable builds
# `:dev` exactly as before.
BARE_ANALYZER_TAG ?= dev

# `docker compose up` already builds all three; these targets are for building
# one in isolation. They delegate so the build context and dockerfile for each
# analyzer live in docker-compose.yml and nowhere else.
#
# Normalised to match core.sandbox.images.analyzer_tag(), which strips and falls
# back to `dev`. Without this an exported-but-empty variable built
# `bare/hello:` — a reference the daemon rejects with an error naming
# nothing useful — while a scan went looking for `:dev`. Whitespace-only is the
# same class of broken deployment script and resolves the same way.
override BARE_ANALYZER_TAG := $(or $(strip $(BARE_ANALYZER_TAG)),dev)

# Passed on the command line rather than exported: make does not export `?=`
# variables to recipes, and Compose reads this one from the environment.
BUILD_ANALYZER := BARE_ANALYZER_TAG=$(BARE_ANALYZER_TAG) $(COMPOSE) build

.PHONY: images
images: image-hello image-static image-unpack ## Build every analyzer image

.PHONY: image-hello
image-hello: ## Build the reference analyzer / isolation probe image
	$(BUILD_ANALYZER) analyzer-hello

.PHONY: image-static
image-static: ## Build the static scan analyzer (strings, rules, entropy)
	$(BUILD_ANALYZER) analyzer-static

.PHONY: image-unpack
image-unpack: ## Build the recursive unpack analyzer
	$(BUILD_ANALYZER) analyzer-unpack

.PHONY: refresh-digests
refresh-digests: ## Print current digests for the pinned base images
	@for image in python:3.12-slim-bookworm; do \
	  docker pull -q $$image >/dev/null; \
	  printf '%-32s %s\n' "$$image" "$$(docker inspect --format '{{index .RepoDigests 0}}' $$image)"; \
	done

# --- verification -----------------------------------------------------------

.PHONY: test
test: ## Run the unit suite (no Docker required)
	$(PY) pytest tests/unit -v

.PHONY: test-integration
test-integration: images ## Run sandbox isolation tests (requires Docker)
	$(PY) pytest tests/integration -v -m "integration"

.PHONY: test-all
test-all: images ## Run every test
	$(PY) pytest -v

.PHONY: lint
lint: ## Lint and check formatting
	$(PY) ruff check .
	$(PY) ruff format --check .

.PHONY: format
format: ## Apply formatting and autofixes
	$(PY) ruff format .
	$(PY) ruff check --fix .

.PHONY: typecheck
typecheck: ## Type-check core/ under mypy strict
	$(PY) mypy

.PHONY: secrets
secrets: ## Scan this repo for secrets (the irony would be fatal)
	@command -v gitleaks >/dev/null 2>&1 \
	  && gitleaks detect --source . --redact --verbose \
	  || docker run --rm -v "$$PWD:/repo" zricethezav/gitleaks:latest detect --source /repo --redact

.PHONY: check
check: lint typecheck test ## Everything CI runs on a pull request

.PHONY: sandbox-check
sandbox-check: image-hello run-root ## M0 acceptance: run the probe through the real sandbox
	BARE_RUN_ROOT=$(RUN_ROOT) $(PY) bare sandbox health
	BARE_RUN_ROOT=$(RUN_ROOT) $(PY) bare sandbox hello

# --- placeholders (raise until implemented; see CLAUDE.md) -------------------

.PHONY: corpus
corpus: ## Build the synthetic vulnerable-binary corpus
	$(PY) python tests/corpus/build_corpus.py

.PHONY: demo
demo: images corpus run-root ## End-to-end: boot the stack, scan a planted artifact
	$(COMPOSE_DEV) up -d --build
	$(PY) python scripts/demo.py

.PHONY: screenshots
screenshots: corpus ## Regenerate docs/images from a FRESH running stack (synthetic data only)
	$(PY) playwright install chromium
	$(PY) python scripts/screenshots.py

.PHONY: airgap-bundle
airgap-bundle: ## Produce the offline install tarball (M6)
	@echo "make airgap-bundle is not implemented yet; scheduled for M6 (see CLAUDE.md)" >&2
	@exit 1
