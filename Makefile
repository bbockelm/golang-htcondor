# Makefile for golang-htcondor

.PHONY: help
help: ## Display this help message
	@echo "golang-htcondor - Makefile targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build all packages
	@echo "Building packages..."
	go build -v ./...

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
clean: ## Clean build artifacts and coverage files
	@echo "Cleaning..."
	rm -f coverage.out coverage.html
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
