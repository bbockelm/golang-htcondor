# Use Rocky Linux 9 as base - RHEL-like distro with arm64 support
FROM rockylinux:9

# Set environment variables
ENV GO_VERSION=1.25.7 \
    GOPATH=/go \
    PATH=/usr/local/go/bin:/go/bin:$PATH \
    CONDOR_CONFIG=/etc/condor/condor_config

# Install basic development tools and dependencies
RUN dnf update -y && \
    dnf install -y \
    wget \
    git \
    gcc \
    gcc-c++ \
    make \
    tar \
    which \
    procps-ng \
    vim \
    sudo \
    python3 \
    python3-pip \
    && dnf clean all

# Install Node.js 20 (required to build the embedded Web UI under frontend/).
# Pinned to the LTS series via NodeSource; matches Makefile's build-frontend
# target.
RUN curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - && \
    dnf install -y nodejs && \
    dnf clean all && \
    node --version && npm --version

# Install Go
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then GOARCH="arm64"; else GOARCH="amd64"; fi && \
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-${GOARCH}.tar.gz && \
    rm go${GO_VERSION}.linux-${GOARCH}.tar.gz

# Install golangci-lint (v2.6.1 or later)
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/local/bin v2.6.1

# Install pre-commit (Python-based)
RUN pip3 install --no-cache-dir pre-commit

# Add HTCondor repository
RUN dnf install -y 'dnf-command(config-manager)' && \
    dnf config-manager --set-enabled crb && \
    dnf install -y epel-release && \
    cd /etc/yum.repos.d && \
    wget https://htcss-downloads.chtc.wisc.edu/repo/25.x/htcondor-release-current.el9.noarch.rpm && \
    dnf install -y htcondor-release-current.el9.noarch.rpm && \
    dnf clean all

# Install HTCondor.
#
# Requires >= 25.7.2 for SHARED_PORT_HTTP_FORWARDING_ID — the
# integration test in sharedport_integration_test.go skips the HTTP
# forwarding portion gracefully on older builds, but rebuilding the
# container after a base-image bump should give us at least 25.7.2.
RUN dnf install -y 'condor >= 25.7.2' && \
    dnf clean all

# Create workspace directory
WORKDIR /workspace

# Create a non-root user for development (useful for Codespaces)
RUN useradd -m -s /bin/bash -u 1000 vscode && \
    echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/vscode && \
    mkdir -p /go && \
    chown -R vscode:vscode /go /workspace

# Accounts for the root-mode superuser integration test. A schedd started by
# root resolves every submitter to a real OS account before it will create a
# cluster, so these identities have to exist as users -- a personal condor
# never has to, which is why the ordinary integration run does not need them.
#
# Created here rather than by the test: a test that adds and removes system
# users can damage the machine it runs on, and leave it damaged when it fails
# part way. The test skips when they are absent.
RUN for u in jobowner superadmin plainadmin; do \
        useradd --no-create-home --shell /usr/sbin/nologin "$u"; \
    done

# Switch to non-root user
USER vscode

# Pre-download common Go dependencies (speeds up first build)
# Developer and CI tooling, at pinned versions.
#
# `@latest` resolves at build time to whatever was published moments
# earlier, which makes a compromised release of any of these -- or of
# anything in their dependency trees -- something this image executes
# before the compromise has been noticed. Pinning turns that into a
# deliberate, reviewable change. The go.sum-style checksum protection Go
# applies to a build does not help here: `go install pkg@latest` will
# happily verify the checksum of a version chosen for us.
#
# The versions carry their publication dates because the point is the
# cooldown, not the pin: each has been public long enough that a
# malicious release would likely have been reported. Dates are as of
# 2026-09-05.
#
# NOTE: Dependabot does not see these. It reads go.mod, GitHub Actions
# and Docker base images, not `go install` lines in a RUN. Bumping them
# is a manual, deliberate act -- see .github/dependabot.yml, where the
# ecosystems Dependabot DOES manage carry a matching cooldown.
#
# gotestsum is here rather than installed at container start: CI ran
# `go install gotest.tools/gotestsum@latest` in three separate
# containers on every run, which was both a supply-chain exposure and a
# repeated network fetch and compile.
RUN go install golang.org/x/tools/gopls@v0.23.0 && \
    go install github.com/go-delve/delve/cmd/dlv@v1.27.1 && \
    go install honnef.co/go/tools/cmd/staticcheck@v0.8.1 && \
    go install gotest.tools/gotestsum@v1.13.0

# Set working directory
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
