# Docker Setup for golang-htcondor

This project includes Docker support for development, particularly useful for GitHub Codespaces and local development on Mac laptops with Apple Silicon (arm64).

## Why Rocky Linux?

The Dockerfile uses Rocky Linux 9 (a RHEL-like distribution) because:
- HTCondor is available for arm64 on RHEL-like distributions
- This allows development and testing on Mac laptops with Apple Silicon
- Rocky Linux is a stable, open-source RHEL-compatible distribution

## Using with GitHub Codespaces

1. Open this repository in GitHub
2. Click the "Code" button and select "Create codespace on main"
3. The devcontainer will automatically build and set up the environment
4. Once ready, you can build and test the project:
   ```bash
   go build ./...
   go test ./...
   ```

## Local Development with Docker

### Using Makefile (Recommended)

The project includes convenient Makefile targets for Docker operations:

```bash
# Build the Docker image
make docker-build

# Run tests inside Docker
make docker-test

# Run integration tests with HTCondor inside Docker
make docker-test-integration

# Start an interactive shell in Docker
make docker-shell

# Clean up Docker images
make docker-clean
```

### Manual Docker Commands

### Build the Docker image:
```bash
docker build -t golang-htcondor:dev .
```

### Run the container:
```bash
docker run -it --rm -v $(pwd):/workspace golang-htcondor:dev
```

### Run with HTCondor services (requires privileged mode):
```bash
docker run -it --rm --privileged -v $(pwd):/workspace golang-htcondor:dev
```

## Using with VS Code Dev Containers

1. Install the "Dev Containers" extension in VS Code
2. Open this project in VS Code
3. Press `Cmd+Shift+P` (Mac) or `Ctrl+Shift+P` (Windows/Linux)
4. Select "Dev Containers: Reopen in Container"
5. VS Code will build and connect to the container

## What's Included

The Docker environment includes:
- **Go 1.24.0** - Latest Go version
- **HTCondor** - Full HTCondor installation from official repositories
- **Development tools**:
  - `gopls` - Go language server
  - `delve` - Go debugger
  - `staticcheck` - Go static analysis tool
  - `git`, `gcc`, `make`, and other build essentials

## Container Architecture

The container:
- Runs as a non-root user (`vscode`) for security
- Has sudo access for system operations
- Pre-installs Go development tools
- Configures GOPATH and Go environment
- Exposes port 9618 (HTCondor collector default)

## Testing HTCondor Integration

### Using Makefile
```bash
# Run integration tests with HTCondor (starts HTCondor automatically)
make docker-test-integration
```

### Manual Testing
To run integration tests that require HTCondor manually:

```bash
# Start HTCondor services (requires sudo in container)
sudo condor_master

# Wait for services to start
sleep 5

# Run integration tests
go test -v -tags=integration ./...
```

## Troubleshooting

### HTCondor not starting
```bash
# Check HTCondor configuration
condor_config_val -dump

# Check HTCondor status
condor_status

# View HTCondor logs
sudo tail -f /var/log/condor/*
```

### Permission issues
If you encounter permission issues, ensure you're running as the `vscode` user or use `sudo` for system operations.

### Go module cache
If you need to clear the Go module cache:
```bash
go clean -modcache
```

## Continuous Integration

The project includes GitHub Actions workflows that run tests inside Docker:

### Docker Test Workflow (`.github/workflows/docker-test.yml`)

This workflow runs on every push and pull request:

1. **Multi-architecture testing** - Tests on both `linux/amd64` and `linux/arm64` platforms
2. **Integration testing** - Runs integration tests with HTCondor in a privileged container
3. **Environment verification** - Validates Go, HTCondor, and development tools are properly installed

The workflow uses Docker BuildKit with caching for faster builds and tests the same environment you use locally.

### Viewing CI Results

- Check the "Actions" tab in the GitHub repository
- Look for "Docker Tests" workflow runs
- Each run shows results for different platforms and test types

This ensures that code works correctly in the containerized environment before deployment or use in Codespaces.
