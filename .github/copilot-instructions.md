# golang-htcondor Project Instructions

This project provides a Go client library for HTCondor software that mimics the Python bindings API.

## Project Overview

golang-htcondor is a Go implementation of HTCondor client functionality, designed to provide an API similar to the [HTCondor Python bindings](https://htcondor.readthedocs.io/en/latest/apis/python-bindings/). The library enables Go applications to interact with HTCondor services for distributed computing workload management.

### Key Capabilities
- Query HTCondor collector for daemon advertisements
- Advertise to the collector
- Locate HTCondor daemons
- Query schedd for job information
- Submit and manage jobs using submit file syntax
- Transfer files using HTCondor's file transfer protocol
- HTTP/REST API server for job management
- Prometheus metrics collection (inspired by `condor_gangliad`)

## Architecture and Components

### Core Components
- **collector.go**: Collector client for querying and advertising daemon ads
- **schedd.go**: Schedd client for job queries and management
- **schedd_submit.go**: Job submission with full submit file parser
- **schedd_transfer.go**: File transfer protocol implementation
- **submit.go**: Submit file parser with macro expansion and queue statements
- **file_transfer.go**: HTCondor file transfer protocol (requires cedar v0.0.2+)
- **security.go**: HTCondor security configuration and authentication

### Additional Components
- **httpserver/**: HTTP/REST API server for job management
- **metricsd/**: Metrics collection for Prometheus export
- **param/**: HTCondor configuration file parser
- **cmd/**: Command-line utilities
- **examples/**: Working examples and demos

### Protocol Implementation
- Uses Cedar protocol for HTCondor communication (github.com/bbockelm/cedar)
- QMGMT (Queue Management) protocol for job submission
- File transfer protocol for remote job submission with spooling

## Technology Stack

### Core Dependencies
- **Go 1.21+** (tested on 1.21, 1.22, 1.23)
- **github.com/bbockelm/cedar** (v0.0.10+): Cedar protocol bindings for HTCondor communication
- **github.com/PelicanPlatform/classad** (v0.0.4+): ClassAd language implementation for job attributes

### Development Dependencies
- **golangci-lint**: Comprehensive linting (see `.golangci.yml`)
- **pre-commit**: Git hooks for code quality
- **gofmt/goimports**: Code formatting
- **go test**: Testing framework with race detector

### HTCondor Integration
- HTCondor is **not required** for basic development and unit testing
- Integration tests require HTCondor installation (marked with `// +build integration` or skipped automatically)
- Mini HTCondor can be used for testing (see HTTP API demo mode)

## Code Style and Conventions

### Go Standards
- Follow standard Go conventions and idiomatic Go patterns
- Use `gofmt` for formatting (automatically enforced by pre-commit hooks)
- Organize imports properly with `goimports`
- Keep `go.mod` tidy with `go mod tidy`

### Naming Conventions
- Use clear, descriptive names that match HTCondor terminology where appropriate
- Public API should mirror HTCondor Python bindings naming when possible
- Use CamelCase for exported types and functions
- Use camelCase for unexported identifiers

### Error Handling
- Always check and handle errors explicitly
- Use wrapped errors with context: `fmt.Errorf("operation failed: %w", err)`
- Return errors rather than panicking (except for truly exceptional cases)
- Log errors with structured logging when appropriate

### Documentation
- Document all exported types, functions, and constants with godoc comments
- Include usage examples in godoc where helpful
- Keep documentation in sync with implementation
- Update README.md for significant API changes

## Testing Guidelines

### Test Organization
- Unit tests: `*_test.go` files alongside implementation
- Integration tests: Use build tags `// +build integration` or runtime checks for HTCondor
- Test files should mirror the structure of implementation files

### Running Tests
```bash
# Unit tests (no HTCondor required)
go test ./...
make test

# With race detector
go test -race ./...
make test-race

# With coverage
go test -cover ./...
make test-cover

# Integration tests (requires HTCondor)
go test -tags=integration -v ./httpserver/
make test-integration
```

### Test Coverage
- Aim for high test coverage of business logic
- Focus on testing public APIs and critical paths
- Mock external dependencies (collectors, schedds) for unit tests
- Use table-driven tests for multiple scenarios

### Test Best Practices
- Test names should clearly describe what they test: `TestScheddSubmitWithQueue`
- Use subtests (`t.Run()`) for related test cases
- Clean up resources in tests (use `t.Cleanup()` or defer)
- Skip integration tests gracefully when HTCondor is unavailable

## Build and Development Workflow

### Quick Start
```bash
# Build all packages
make build

# Run all CI checks
make ci

# Run linter
make lint

# Format code
make fmt

# Install pre-commit hooks (recommended)
make pre-commit-install
```

### Development Cycle
1. Make changes to code
2. Run tests: `make test`
3. Run linter: `make lint` (or `make lint-fix` for auto-fixes)
4. Commit (pre-commit hooks run automatically)
5. CI runs automatically on push/PR

### Makefile Targets
See `Makefile` for all available targets. Key targets:
- `make help`: Display all available targets
- `make build`: Build all packages
- `make test`: Run all tests
- `make lint`: Run golangci-lint
- `make ci`: Run all CI checks locally
- `make examples`: Build all example programs
- `make clean`: Clean build artifacts

### Pre-commit Hooks
Automatically run before each commit:
- Format code with `gofmt`
- Organize imports with `goimports`
- Keep `go.mod` tidy
- Run `golangci-lint`
- Check for trailing whitespace and other issues

Install with: `make pre-commit-install` or `pip install pre-commit && pre-commit install`

## Important Constraints and Gotchas

### HTCondor Dependencies
- **Unit tests should NOT require HTCondor installation**
- Use build tags or runtime checks to skip integration tests
- Mock HTCondor responses for unit testing where possible

### ClassAd Handling
- ClassAds use a special expression language (similar to Python expressions)
- Be careful with type conversions between Go types and ClassAd types
- ClassAd attributes are case-insensitive but conventionally use CamelCase

### Security Configuration
- HTCondor security configuration is complex (Kerberos, SSL, tokens, etc.)
- Security settings are typically loaded from HTCondor config files
- Be cautious with credential handling and never log secrets

### Protocol Considerations
- Cedar protocol uses specific command codes (integers) for operations
- File transfer protocol requires specific sequence of commands
- QMGMT protocol has strict ordering requirements

### Submit File Parsing
- Submit files support complex macro expansion and substitution
- Queue statements can generate multiple jobs with variable expansion
- Must preserve HTCondor's macro evaluation semantics

## Common Development Tasks

### Adding a New HTTP API Endpoint
1. Implement the handler function in `httpserver/handlers.go`
2. Add route in `httpserver/routes.go` if needed
3. **IMPORTANT: Update the OpenAPI schema in `httpserver/openapi.go`** to document the new endpoint
4. Add unit tests in `httpserver/*_test.go`
5. Test the endpoint manually or with integration tests
6. Update any relevant API documentation

**Note**: Always keep the OpenAPI schema synchronized with the actual HTTP API endpoints. This ensures API documentation is accurate and up-to-date for consumers.

### Adding a New Schedd Method
1. Define the method signature in `schedd.go` (matching Python bindings if applicable)
2. Implement the protocol interaction in appropriate `schedd_*.go` file
3. Add unit tests in corresponding `*_test.go` file
4. Update documentation and examples if it's a public API
5. Consider adding integration test if it requires live HTCondor

### Adding a New Submit File Feature
1. Update parser in `submit.go`
2. Add job ad generation logic
3. Add test cases in `submit_test.go` with various submit file formats
4. Verify macro expansion and queue statement handling

### Debugging Protocol Issues
1. Enable cedar protocol logging if available
2. Use `go test -v` to see detailed test output
3. Compare with HTCondor Python bindings behavior
4. Check HTCondor logs on server side (ScheddLog, CollectorLog)
5. Verify ClassAd format matches expected schema

## Security Considerations

### Authentication and Authorization
- Support for HTCondor security methods: FS, GSI, SSL, IDTOKENS, KERBEROS
- Always validate user credentials before operations
- Use appropriate security methods for environment

### Secure Communication
- Use encryption when available (SSL/TLS)
- Validate certificates in production
- Handle security tokens securely

### Input Validation
- Validate all user input, especially in submit files
- Sanitize file paths to prevent directory traversal
- Validate ClassAd expressions to prevent injection

### Secret Handling
- Never log passwords, tokens, or other credentials
- Use secure temporary files with proper permissions
- Clean up sensitive data from memory when done

## API Compatibility

### HTCondor Python Bindings
- Aim to provide similar API to Python bindings where practical
- See: https://htcondor.readthedocs.io/en/latest/apis/python-bindings/
- Key classes to mirror: `Collector`, `Schedd`, `Submit`
- May diverge for Go idioms (e.g., error handling, context.Context)

### Versioning
- Follow semantic versioning (SemVer)
- Breaking API changes require major version bump
- Document deprecations before removal

## Useful Resources

### Project Documentation
- [README.md](../README.md): Getting started and usage examples
- [CONTRIBUTING.md](../CONTRIBUTING.md): Contribution guidelines
- [DEPENDENCIES.md](../DEPENDENCIES.md): Dependency setup instructions
- [DEV_SETUP.md](DEV_SETUP.md): Development tools and CI setup

### HTCondor Documentation
- [HTCondor Manual](https://htcondor.readthedocs.io/)
- [HTCondor Python Bindings](https://htcondor.readthedocs.io/en/latest/apis/python-bindings/)
- [ClassAd Language](https://htcondor.readthedocs.io/en/latest/classad-attributes/)
- [Submit Description File](https://htcondor.readthedocs.io/en/latest/users-manual/submitting-a-job.html)

### External Dependencies
- [Cedar Protocol](https://github.com/bbockelm/cedar)
- [ClassAd Implementation](https://github.com/PelicanPlatform/classad)

## CI/CD

### GitHub Actions
The project uses GitHub Actions for continuous integration (`.github/workflows/ci.yml`):
- **Test Job**: Runs on Go 1.21, 1.22, 1.23 with race detector and coverage
- **Lint Job**: Runs golangci-lint with configuration from `.golangci.yml`
- **Build Job**: Verifies all packages and examples build successfully

### Running CI Locally
Before pushing, run: `make ci`

This runs the same checks as CI:
- `go mod tidy`: Ensure dependencies are clean
- `gofmt`: Format code
- `golangci-lint run`: Lint code
- `go test ./...`: Run all tests

## Development Tips

### Working with Submit Files
- Study existing tests in `submit_*_test.go` for examples
- Submit file syntax is complex - refer to HTCondor documentation
- Test macro expansion and queue statements thoroughly

### Protocol Debugging
- Cedar protocol operates at TCP level with specific command sequences
- Use network tools (tcpdump, Wireshark) for low-level debugging
- Compare with Python bindings behavior using strace/network capture

### Testing Without HTCondor
- Most unit tests use mocks and don't require HTCondor
- Integration tests automatically skip if HTCondor is not found
- Use mini HTCondor in demo mode for HTTP API testing

### Code Generation
- This project does not use code generation currently
- If adding codegen, document it clearly and update the build process
