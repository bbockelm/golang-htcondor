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
	go test -v -tags=integration -timeout=5m ./metricsd/

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
