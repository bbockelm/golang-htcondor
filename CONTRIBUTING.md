# Contributing to golang-htcondor

Thank you for your interest in contributing to golang-htcondor!

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/htcondor/golang-htcondor.git
cd golang-htcondor
```

2. Ensure you have Go 1.21 or later installed:
```bash
go version
```

3. Build the project:
```bash
go build ./...
```

4. Install pre-commit hooks (recommended):
```bash
# Install pre-commit (if not already installed)
pip install pre-commit

# Install the git hooks
pre-commit install

# (Optional) Run against all files
pre-commit run --all-files
```

5. Run tests:
```bash
go test ./...
```

## Project Structure

- `collector.go` - Collector client implementation
- `schedd.go` - Schedd client implementation
- `htcondor.go` - Main package file
- `*_test.go` - Test files
- `examples/` - Example usage code

## Dependencies

The project requires:
- `github.com/bbockelm/cedar` - Cedar protocol bindings
- `github.com/PelicanPlatform/classad` - ClassAd language implementation

These dependencies are currently under development. The code uses placeholder types until the dependencies are fully available.

## Testing

Run all tests:
```bash
go test ./...
```

Run tests with coverage:
```bash
go test -cover ./...
```

Run tests with race detector:
```bash
go test -race ./...
```

## Code Quality

### Pre-commit Hooks

This project uses pre-commit hooks to ensure code quality. The hooks will automatically:
- Format Go code with `gofmt`
- Organize imports with `goimports`
- Keep `go.mod` tidy
- Run `golangci-lint` to catch common issues
- Check for trailing whitespace and other issues

Install pre-commit hooks:
```bash
pip install pre-commit
pre-commit install
```

### Linting

We use `golangci-lint` for comprehensive linting. Install it:
```bash
# macOS
brew install golangci-lint

# Linux
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# Or using go install
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

Run the linter:
```bash
golangci-lint run
```

Configuration is in `.golangci.yml`.

## Code Style

- Follow standard Go conventions and formatting (use `gofmt`)
- Organize imports properly (use `goimports`)
- Write clear, concise comments
- Include tests for new functionality
- Keep API compatibility with HTCondor Python bindings where possible
- Address all linter warnings before submitting

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Ensure pre-commit hooks pass (or run `pre-commit run --all-files`)
5. Run tests and ensure they pass (`go test ./...`)
6. Run the linter and fix any issues (`golangci-lint run`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to your fork (`git push origin feature/amazing-feature`)
9. Submit a pull request

### Pull Request Guidelines

- Write a clear description of the changes
- Reference any related issues
- Ensure all CI checks pass
- Keep changes focused and atomic
- Update documentation as needed

## Questions?

Feel free to open an issue for questions or discussions.
