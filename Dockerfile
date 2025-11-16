# Use Rocky Linux 9 as base - RHEL-like distro with arm64 support
FROM rockylinux:9

# Set environment variables
ENV GO_VERSION=1.24.0 \
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
    && dnf clean all

# Install Go
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then GOARCH="arm64"; else GOARCH="amd64"; fi && \
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-${GOARCH}.tar.gz && \
    rm go${GO_VERSION}.linux-${GOARCH}.tar.gz

# Add HTCondor repository
RUN dnf install -y 'dnf-command(config-manager)' && \
    dnf config-manager --set-enabled crb && \
    dnf install -y epel-release && \
    cd /etc/yum.repos.d && \
    wget https://htcss-downloads.chtc.wisc.edu/repo/25.x/htcondor-release-current.el9.noarch.rpm && \
    dnf install -y htcondor-release-current.el9.noarch.rpm && \
    dnf clean all

# Install HTCondor
RUN dnf install -y condor && \
    dnf clean all

# Create workspace directory
WORKDIR /workspace

# Create a non-root user for development (useful for Codespaces)
RUN useradd -m -s /bin/bash -u 1000 vscode && \
    echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/vscode && \
    mkdir -p /go && \
    chown -R vscode:vscode /go /workspace

# Switch to non-root user
USER vscode

# Pre-download common Go dependencies (speeds up first build)
RUN go install golang.org/x/tools/gopls@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest && \
    go install honnef.co/go/tools/cmd/staticcheck@latest

# Set working directory
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
