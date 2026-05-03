# Makefile for golang-htcondor

.PHONY: help
help: ## Display this help message
	@echo "golang-htcondor - Makefile targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/bbockelm/golang-htcondor/version.Version=$(VERSION) \
           -X github.com/bbockelm/golang-htcondor/version.Commit=$(COMMIT)

.PHONY: build
build: build-jupyter-helper ## Build all packages with embedded version info + embedded JupyterLab helper
	@echo "Building packages (version=$(VERSION) commit=$(COMMIT)) with -tags embed_jupyter_helper..."
	go build -v -tags embed_jupyter_helper -ldflags "$(LDFLAGS)" ./...

# --- Frontend (Web UI) ---
#
# The Next.js app lives under frontend/ and is built into a static export
# (frontend/out). For production we copy that into httpserver/webui/dist
# and rebuild the Go binary with -tags embed_frontend so the SPA is
# embedded into the binary.

FRONTEND_DIR := frontend
WEBUI_DIST   := httpserver/webui/dist

.PHONY: frontend-install
frontend-install: ## Install frontend npm dependencies
	cd $(FRONTEND_DIR) && npm install

.PHONY: dev-frontend
dev-frontend: ## Run Next.js dev server (proxies /api to Go on :8080)
	cd $(FRONTEND_DIR) && npm run dev

# --- JupyterLab tunnel helper ----------------------------------------------
#
# The helper runs *inside* the JupyterLab job sandbox. We always cross-build a
# linux/<host arch> binary for Docker-universe jobs (the standard Linux pool
# case). When the host running `make build` is itself macOS, we also build a
# darwin/<host arch> helper, because on macOS the API server falls back to
# vanilla universe + on-the-fly conda — and the execute node is also macOS,
# so it needs a darwin-native helper.
#
# Both binaries land in httpserver/jupyterhelperbin/dist/ where embed.go
# (gated on the embed_jupyter_helper tag) picks them up.
JUPYTER_HELPER_GOARCH        := $(shell go env GOARCH)
JUPYTER_HELPER_GOOS_HOST     := $(shell go env GOOS)
JUPYTER_HELPER_BIN           := bin/htcondor-jupyter-helper
JUPYTER_HELPER_DARWIN_BIN    := bin/htcondor-jupyter-helper-darwin
# Where the api binary's embed.FS will pick up the cross-compiled helper.
# Must stay in sync with httpserver/jupyterhelperbin/embed.go's //go:embed.
JUPYTER_HELPER_EMBED_DIR     := httpserver/jupyterhelperbin/dist

.PHONY: build-jupyter-helper
build-jupyter-helper: ## Cross-compile the JupyterLab tunnel helper for linux/<host arch> (and darwin too if the host is macOS)
	@echo "Building $(JUPYTER_HELPER_BIN) for linux/$(JUPYTER_HELPER_GOARCH)..."
	@mkdir -p bin $(JUPYTER_HELPER_EMBED_DIR)
	GOOS=linux GOARCH=$(JUPYTER_HELPER_GOARCH) CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS)" \
		-o $(JUPYTER_HELPER_BIN) \
		./cmd/htcondor-jupyter-helper
	cp $(JUPYTER_HELPER_BIN) $(JUPYTER_HELPER_EMBED_DIR)/htcondor-jupyter-helper
	@echo "Built $(JUPYTER_HELPER_BIN) (embed-staged)"
	@if [ "$(JUPYTER_HELPER_GOOS_HOST)" = "darwin" ]; then \
		echo "Host is darwin — also building $(JUPYTER_HELPER_DARWIN_BIN) for darwin/$(JUPYTER_HELPER_GOARCH)..."; \
		GOOS=darwin GOARCH=$(JUPYTER_HELPER_GOARCH) CGO_ENABLED=0 go build \
			-ldflags "$(LDFLAGS)" \
			-o $(JUPYTER_HELPER_DARWIN_BIN) \
			./cmd/htcondor-jupyter-helper; \
		cp $(JUPYTER_HELPER_DARWIN_BIN) $(JUPYTER_HELPER_EMBED_DIR)/htcondor-jupyter-helper-darwin; \
		echo "Built $(JUPYTER_HELPER_DARWIN_BIN) (embed-staged)"; \
	fi

.PHONY: build-frontend
build-frontend: ## Build Next.js static export into frontend/out
	cd $(FRONTEND_DIR) && NODE_ENV=production npm run build

.PHONY: build-prod
build-prod: build-frontend build-jupyter-helper ## Build htcondor-api with embedded frontend + embedded JupyterLab helper
	@echo "Staging frontend export into $(WEBUI_DIST)..."
	rm -rf $(WEBUI_DIST)
	cp -r $(FRONTEND_DIR)/out $(WEBUI_DIST)
	@echo "Building htcondor-api with -tags embed_frontend,embed_jupyter_helper..."
	mkdir -p bin
	CGO_ENABLED=0 go build -tags "embed_frontend embed_jupyter_helper" -ldflags "$(LDFLAGS)" -o bin/htcondor-api ./cmd/htcondor-api
	@echo "Built bin/htcondor-api"

.PHONY: clean-frontend
clean-frontend: ## Remove frontend build artifacts
	rm -rf $(FRONTEND_DIR)/out $(FRONTEND_DIR)/.next $(WEBUI_DIST)/*
	@touch $(WEBUI_DIST)/.keep

.PHONY: clean-jupyter-helper
clean-jupyter-helper: ## Remove staged JupyterLab helper artifacts
	rm -f $(JUPYTER_HELPER_BIN) $(JUPYTER_HELPER_EMBED_DIR)/htcondor-jupyter-helper
	@touch $(JUPYTER_HELPER_EMBED_DIR)/.keep

DEMO_LISTEN ?= :8080

.PHONY: demo
demo: build-prod ## Run htcondor-api in demo mode (rebuilds with embedded UI first)
	@echo "Starting demo server on $(DEMO_LISTEN)..."
	bin/htcondor-api -demo -listen $(DEMO_LISTEN)

.PHONY: test
test: ## Run all tests
	@echo "Running tests..."
	go test -v ./...

.PHONY: test-integration
test-integration: ## Run integration tests (requires HTCondor)
	@echo "Running integration tests..."
	@echo "Note: This requires HTCondor to be installed"
	go test -v -tags=integration -timeout=5m ./...

.PHONY: test-race
test-race: ## Run tests with race detector
	@echo "Running tests with race detector..."
	go test -v -race ./...

.PHONY: test-cover
test-cover: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: lint
lint: ## Run golangci-lint
	@echo "Running linter..."
	golangci-lint run

.PHONY: lint-fix
lint-fix: ## Run golangci-lint and auto-fix issues
	@echo "Running linter with auto-fix..."
	golangci-lint run --fix

.PHONY: fmt
fmt: ## Format code with gofmt
	@echo "Formatting code..."
	gofmt -s -w .

.PHONY: imports
imports: ## Organize imports with goimports
	@echo "Organizing imports..."
	goimports -w .

.PHONY: tidy
tidy: ## Run go mod tidy
	@echo "Tidying modules..."
	go mod tidy

.PHONY: verify
verify: ## Verify dependencies
	@echo "Verifying dependencies..."
	go mod verify

.PHONY: clean
clean: clean-frontend ## Clean build artifacts and coverage files
	@echo "Cleaning..."
	rm -f coverage.out coverage.html
	rm -rf bin
	find . -name "*.test" -delete
	find examples -type f -executable -delete

.PHONY: examples
examples: ## Build all examples
	@echo "Building examples..."
	cd examples/basic && go build -v
	cd examples/file_transfer_demo && go build -v
	cd examples/param_defaults_demo && go build -v
	cd examples/queue_demo && go build -v

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
	docker run --rm -v $(PWD):/workspace -w /workspace $(DOCKER_IMAGE) go test -v ./...

.PHONY: docker-test-integration
docker-test-integration: ## Run integration tests inside Docker container with HTCondor
	@echo "Running integration tests inside Docker container..."
	docker build -t $(DOCKER_IMAGE) .
	docker run --rm --privileged -v $(PWD):/workspace -w /workspace $(DOCKER_IMAGE) /bin/bash -c "\
		sudo condor_master && \
		sleep 5 && \
		go test -v -tags=integration -timeout=5m ./httpserver/"

.PHONY: docker-shell
docker-shell: ## Start interactive shell in Docker container
	@echo "Starting Docker shell..."
	docker build -t $(DOCKER_IMAGE) .
	docker run --rm -it -v $(PWD):/workspace -w /workspace $(DOCKER_IMAGE) /bin/bash

.PHONY: docker-clean
docker-clean: ## Remove Docker image
	@echo "Removing Docker image..."
	docker rmi $(DOCKER_IMAGE) || true
