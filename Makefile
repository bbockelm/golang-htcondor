# Makefile for golang-htcondor

.PHONY: help
help: ## Display this help message
	@echo "golang-htcondor - Makefile targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/bbockelm/golang-htcondor/version.Version=$(VERSION) \
           -X github.com/bbockelm/golang-htcondor/version.Commit=$(COMMIT)

# This is a multi-module repo (no committed go.work — the workspace is dev-local):
#   .            -> github.com/bbockelm/golang-htcondor         (core library + daemon framework)
#   ./webapi     -> github.com/bbockelm/golang-htcondor/webapi  (web server, OAuth2 issuer, MCP, UI)
#   ./localcredmon -> .../golang-htcondor/localcredmon          (local credential monitor daemon)
# Each nested module carries a `replace ... => ../`, so it builds standalone. The
# build/test targets fan out over the modules, running go in each directory with
# GOWORK=off so a developer's local go.work never changes the result.
APP_MODULE_DIRS := . webapi localcredmon

.PHONY: build
build: build-jupyter-helper ## Build all modules with embedded version info + embedded JupyterLab helper
	@echo "Building all modules (version=$(VERSION) commit=$(COMMIT)) with -tags embed_jupyter_helper..."
	@for dir in $(APP_MODULE_DIRS); do \
		echo "==> build $$dir"; \
		(cd $$dir && GOWORK=off go build -v -tags embed_jupyter_helper -ldflags "$(LDFLAGS)" ./...) || exit 1; \
	done

# --- HTCondor docs (MCP reference content) -------------------------------
#
# A subset of the upstream HTCondor RST docs is embedded into the api
# binary so the MCP server can answer "what attribute is this?" /
# "what does this submit command do?" / "which config macro controls
# X?" without an external lookup. The source tree is expected at
# reference/htcondor (cloned via stage-condor-docs below).
#
# The stage is fast and idempotent; the build-prod / Dockerfile.release
# targets call it before invoking go build with -tags embed_condor_docs.
CONDOR_DOCS_SRC ?= reference/htcondor/docs
CONDOR_DOCS_DST := webapi/condordocs/dist
HTCONDOR_GIT_URL ?= https://github.com/htcondor/htcondor.git
HTCONDOR_GIT_REF ?= main

.PHONY: fetch-condor-docs
fetch-condor-docs: ## Clone or update reference/htcondor (only if missing)
	@if [ ! -d reference/htcondor/.git ]; then \
		echo "Cloning HTCondor source from $(HTCONDOR_GIT_URL) ($(HTCONDOR_GIT_REF))..."; \
		mkdir -p reference; \
		git clone --depth 1 --branch $(HTCONDOR_GIT_REF) $(HTCONDOR_GIT_URL) reference/htcondor; \
	else \
		echo "Reusing existing reference/htcondor checkout"; \
	fi

.PHONY: stage-condor-docs
stage-condor-docs: ## Stage curated HTCondor RST docs into $(CONDOR_DOCS_DST) for embedding
	@if [ ! -d "$(CONDOR_DOCS_SRC)" ]; then \
		echo "ERROR: $(CONDOR_DOCS_SRC) not found. Run 'make fetch-condor-docs' or set CONDOR_DOCS_SRC."; \
		exit 1; \
	fi
	@echo "Staging HTCondor docs from $(CONDOR_DOCS_SRC) -> $(CONDOR_DOCS_DST)..."
	@rm -rf $(CONDOR_DOCS_DST)
	@mkdir -p $(CONDOR_DOCS_DST)/config
	@cp $(CONDOR_DOCS_SRC)/classad-attributes/job-classad-attributes.rst $(CONDOR_DOCS_DST)/job-attributes.rst
	@cp $(CONDOR_DOCS_SRC)/classad-attributes/machine-classad-attributes.rst $(CONDOR_DOCS_DST)/machine-attributes.rst
	@cp $(CONDOR_DOCS_SRC)/man-pages/condor_submit.rst $(CONDOR_DOCS_DST)/condor-submit.rst
	@# Skip configuration-macros.rst itself — the upstream "all" page is
	@# a Sphinx-time aggregation of generated content and is empty in
	@# the source tree. The per-subsystem files under
	@# admin-manual/configuration/ are the actual definitions.
	@for f in $(CONDOR_DOCS_SRC)/admin-manual/configuration/*.rst; do \
		base=$$(basename $$f); \
		if [ "$$base" = "all.rst" ] || [ "$$base" = "index.rst" ]; then continue; fi; \
		cp "$$f" "$(CONDOR_DOCS_DST)/config/$$base"; \
	done
	@echo "Staged docs:"
	@ls -1 $(CONDOR_DOCS_DST) | sed 's|^|  |'

.PHONY: clean-condor-docs
clean-condor-docs: ## Remove staged HTCondor doc artifacts
	rm -rf $(CONDOR_DOCS_DST)
	@mkdir -p $(CONDOR_DOCS_DST)
	@touch $(CONDOR_DOCS_DST)/.keep

# --- Frontend (Web UI) ---
#
# The Next.js app lives under frontend/ and is built into a static export
# (frontend/out). For production we copy that into httpserver/webui/dist
# and rebuild the Go binary with -tags embed_frontend so the SPA is
# embedded into the binary.

FRONTEND_DIR := webapi/frontend
WEBUI_DIST   := webapi/httpserver/webui/dist

.PHONY: frontend-install
frontend-install: ## Install frontend npm dependencies
	cd $(FRONTEND_DIR) && npm install

.PHONY: dev-frontend
dev-frontend: ## Run Next.js dev server (proxies /api to Go on :8080)
	cd $(FRONTEND_DIR) && npm run dev

# --- JupyterLab tunnel helper ----------------------------------------------
#
# The helper runs *inside* the JupyterLab job sandbox on the execute node, so
# it must match that machine's GOOS+GOARCH — not the API server's host arch.
# Go cross-compiles trivially (CGO_ENABLED=0, no libc), so we just build all
# the relevant target tuples every time and let the API server's submit
# handler pick the right one at submit time based on the requirements
# expression / inferred slot platform.
#
# Targets are fixed below; add a row to JUPYTER_HELPER_TARGETS to extend.
# Each target produces dist/htcondor-jupyter-helper-<goos>-<goarch>, which
# the api binary's embed.FS picks up under the embed_jupyter_helper tag.
JUPYTER_HELPER_TARGETS := \
	linux/amd64 \
	linux/arm64 \
	darwin/arm64
JUPYTER_HELPER_EMBED_DIR := webapi/httpserver/jupyterhelperbin/dist

.PHONY: build-jupyter-helper
build-jupyter-helper: ## Cross-compile the JupyterLab tunnel helper for every target in JUPYTER_HELPER_TARGETS
	@mkdir -p bin $(JUPYTER_HELPER_EMBED_DIR)
	@for target in $(JUPYTER_HELPER_TARGETS); do \
		goos=$${target%/*}; \
		goarch=$${target#*/}; \
		out="$(CURDIR)/$(JUPYTER_HELPER_EMBED_DIR)/htcondor-jupyter-helper-$$goos-$$goarch"; \
		echo "Building $$out for $$goos/$$goarch..."; \
		(cd webapi && GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 GOWORK=off go build \
			-ldflags "$(LDFLAGS)" \
			-o "$$out" \
			./cmd/htcondor-jupyter-helper) || exit 1; \
	done
	@echo "Embed-staged helpers in $(JUPYTER_HELPER_EMBED_DIR):"
	@ls -1 $(JUPYTER_HELPER_EMBED_DIR)/htcondor-jupyter-helper-* 2>/dev/null | sed 's|^|  |' || true

.PHONY: build-frontend
build-frontend: ## Build Next.js static export into frontend/out
	cd $(FRONTEND_DIR) && NODE_ENV=production npm run build

.PHONY: build-prod
build-prod: build-frontend build-jupyter-helper stage-condor-docs ## Build htcondor-api with embedded frontend + JupyterLab helper + HTCondor docs
	@echo "Staging frontend export into $(WEBUI_DIST)..."
	rm -rf $(WEBUI_DIST)
	cp -r $(FRONTEND_DIR)/out $(WEBUI_DIST)
	@echo "Building htcondor-api with -tags embed_frontend,embed_jupyter_helper,embed_condor_docs..."
	mkdir -p bin
	cd webapi && CGO_ENABLED=0 GOWORK=off go build -tags "embed_frontend embed_jupyter_helper embed_condor_docs" -ldflags "$(LDFLAGS)" -o $(CURDIR)/bin/htcondor-api ./cmd/htcondor-api
	@echo "Built bin/htcondor-api"

.PHONY: clean-frontend
clean-frontend: ## Remove frontend build artifacts
	rm -rf $(FRONTEND_DIR)/out $(FRONTEND_DIR)/.next $(WEBUI_DIST)/*
	@touch $(WEBUI_DIST)/.keep

.PHONY: clean-jupyter-helper
clean-jupyter-helper: ## Remove staged JupyterLab helper artifacts
	rm -f $(JUPYTER_HELPER_EMBED_DIR)/htcondor-jupyter-helper-*
	@touch $(JUPYTER_HELPER_EMBED_DIR)/.keep

DEMO_LISTEN ?= :8080

.PHONY: demo
demo: build-prod ## Run htcondor-api in demo mode (rebuilds with embedded UI first)
	@echo "Starting demo server on $(DEMO_LISTEN)..."
	bin/htcondor-api -demo -listen $(DEMO_LISTEN)

.PHONY: test
test: ## Run all tests across every module
	@echo "Running tests..."
	@for dir in $(APP_MODULE_DIRS); do \
		echo "==> test $$dir"; \
		(cd $$dir && GOWORK=off go test -v ./...) || exit 1; \
	done

.PHONY: test-integration
test-integration: ## Run integration tests (requires HTCondor)
	@echo "Running integration tests..."
	@echo "Note: This requires HTCondor to be installed"
	@for dir in $(APP_MODULE_DIRS); do \
		echo "==> test-integration $$dir"; \
		(cd $$dir && GOWORK=off go test -v -tags=integration -timeout=5m ./...) || exit 1; \
	done

.PHONY: test-race
test-race: ## Run tests with race detector
	@echo "Running tests with race detector..."
	@for dir in $(APP_MODULE_DIRS); do \
		echo "==> test-race $$dir"; \
		(cd $$dir && GOWORK=off go test -v -race ./...) || exit 1; \
	done

.PHONY: vet
vet: ## Run go vet on every module
	@echo "Running go vet..."
	@for dir in $(APP_MODULE_DIRS); do \
		echo "==> vet $$dir"; \
		(cd $$dir && GOWORK=off go vet ./...) || exit 1; \
	done

.PHONY: test-cover
test-cover: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: lint
lint: ## Run golangci-lint on every module
	@echo "Running linter..."
	@for dir in $(APP_MODULE_DIRS); do \
		echo "==> lint $$dir"; \
		(cd $$dir && GOWORK=off golangci-lint run) || exit 1; \
	done

.PHONY: lint-fix
lint-fix: ## Run golangci-lint and auto-fix issues on every module
	@echo "Running linter with auto-fix..."
	@for dir in $(APP_MODULE_DIRS); do \
		echo "==> lint-fix $$dir"; \
		(cd $$dir && GOWORK=off golangci-lint run --fix) || exit 1; \
	done

.PHONY: fmt
fmt: ## Format code with gofmt
	@echo "Formatting code..."
	gofmt -s -w .

.PHONY: imports
imports: ## Organize imports with goimports
	@echo "Organizing imports..."
	goimports -w .

.PHONY: tidy
tidy: ## Run go mod tidy on the application modules (core, webapi, localcredmon)
	@echo "Tidying application modules..."
	@for dir in $(APP_MODULE_DIRS); do \
		echo "  ==> go mod tidy in $$dir"; \
		(cd $$dir && GOWORK=off go mod tidy) || exit 1; \
	done

.PHONY: tidy-all
tidy-all: ## Run go mod tidy on EVERY module in the repo (app modules, examples, test clients)
	@echo "Tidying every module (excluding reference/, node_modules/, build caches)..."
	@find . -name go.mod \
		-not -path './.gocache/*' -not -path './.gotmp/*' \
		-not -path './reference/*' -not -path '*/node_modules/*' \
		-not -path './build/*' | sort | while read -r mod; do \
		dir=$$(dirname "$$mod"); \
		echo "  ==> go mod tidy in $$dir"; \
		(cd "$$dir" && GOWORK=off go mod tidy) || exit 1; \
	done

.PHONY: tidy-check
tidy-check: ## Fail if any module's go.mod/go.sum is not tidy (run `make tidy-all` to fix)
	@echo "Verifying every module is tidy..."
	@$(MAKE) --no-print-directory tidy-all >/dev/null
	@if ! git diff --quiet -- '*go.mod' '*go.sum'; then \
		echo "ERROR: go.mod/go.sum is out of date. Run 'make tidy-all' and commit the result:"; \
		git --no-pager diff --stat -- '*go.mod' '*go.sum'; \
		exit 1; \
	fi
	@echo "All modules tidy."

.PHONY: verify
verify: ## Verify dependencies
	@echo "Verifying dependencies..."
	go mod verify

.PHONY: clean
clean: clean-frontend clean-condor-docs ## Clean build artifacts and coverage files
	@echo "Cleaning..."
	rm -f coverage.out coverage.html
	rm -rf bin
	find . -name "*.test" -delete
	find examples -type f -executable -delete

.PHONY: examples
examples: ## Build all examples
	@echo "Building examples..."
	@# The example modules are standalone (own go.mod + replace => ../..) and
	@# are not part of the root go.work, so build them with the workspace off.
	cd examples/basic && GOWORK=off go build -v
	cd examples/file_transfer_demo && GOWORK=off go build -v
	cd examples/param_defaults_demo && GOWORK=off go build -v
	cd examples/queue_demo && GOWORK=off go build -v

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks on all files
	@echo "Running pre-commit hooks..."
	pre-commit run --all-files

.PHONY: pre-commit-install
pre-commit-install: ## Install pre-commit hooks
	@echo "Installing pre-commit hooks..."
	pip install pre-commit
	pre-commit install

.PHONY: ci
ci: tidy fmt lint test ## Run all CI checks locally
	@echo "All CI checks passed!"

.PHONY: all
all: tidy fmt lint test build examples ## Run all checks and build everything
	@echo "Build complete!"

# Docker targets
DOCKER_IMAGE ?= golang-htcondor:dev
DOCKER_PLATFORM ?= linux/arm64,linux/amd64

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

.PHONY: docker-build-multiarch
docker-build-multiarch: ## Build multi-architecture Docker image
	@echo "Building multi-architecture Docker image..."
	docker buildx build --platform $(DOCKER_PLATFORM) -t $(DOCKER_IMAGE) .

.PHONY: docker-test
docker-test: ## Run tests inside Docker container
	@echo "Running tests inside Docker container..."
	docker build -t $(DOCKER_IMAGE) .
	docker run --rm -v $(PWD):/workspace -w /workspace $(DOCKER_IMAGE) \
		/bin/sh -c 'for d in . webapi localcredmon; do (cd $$d && GOWORK=off go test -v ./...) || exit 1; done'

.PHONY: docker-test-integration
docker-test-integration: ## Run integration tests inside Docker container with HTCondor
	@echo "Running integration tests inside Docker container..."
	docker build -t $(DOCKER_IMAGE) .
	docker run --rm --privileged -v $(PWD):/workspace -w /workspace $(DOCKER_IMAGE) /bin/bash -c "\
		sudo condor_master && \
		sleep 5 && \
		cd webapi && GOWORK=off go test -v -tags=integration -timeout=5m ./httpserver/"

.PHONY: docker-shell
docker-shell: ## Start interactive shell in Docker container
	@echo "Starting Docker shell..."
	docker build -t $(DOCKER_IMAGE) .
	docker run --rm -it -v $(PWD):/workspace -w /workspace $(DOCKER_IMAGE) /bin/bash

.PHONY: docker-clean
docker-clean: ## Remove Docker image
	@echo "Removing Docker image..."
	docker rmi $(DOCKER_IMAGE) || true
