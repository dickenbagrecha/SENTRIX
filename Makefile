# ==============================================================================
# SENTRIX - Root Monorepository Makefile
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help
help: ## Display this help message
	@echo "SENTRIX Unified Cybersecurity Platform - Build Orchestrator"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: validate
validate: ## Run configuration, schema, and repository integrity checks
	@node scripts/validate-configs.js

.PHONY: submodules
submodules: ## Inspect and fetch ModSecurity git submodules
	@bash scripts/init-submodules.sh

.PHONY: build-core
build-core: ## Compile SENTRIX Core binaries (sentrixd and sentrix-waf)
	@bash scripts/build-core.sh

.PHONY: build-containers
build-containers: ## Build Docker images for the SENTRIX multi-engine stack
	@bash scripts/build-all.sh

.PHONY: dev-up
dev-up: ## Start the lightweight development cluster (Core, WAF, CrowdSec, Promptfoo)
	@bash scripts/run-dev.sh

.PHONY: dev-down
dev-down: ## Stop the development cluster
	@docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.dev.yml down

.PHONY: logs
logs: ## Tail development cluster logs
	@docker compose -f deploy/docker-compose.yml logs -f

.PHONY: clean
clean: ## Remove compiled binaries and temporary artifacts
	@rm -rf bin/
	@echo "Cleaned build artifacts."
