# Dockerfile for golang-htcondor development and demo mode
FROM htcondor/mini_arm64:25.x-el9

# Install dependencies for Go and development
USER root
RUN dnf -y update && \
    dnf -y install wget ca-certificates sudo python3 python3-pip git make gcc gcc-c++ which && \
    dnf clean all

# Install Go (latest stable, ARM64)
RUN wget https://go.dev/dl/go1.22.2.linux-arm64.tar.gz && \
    tar -C /usr/local -xzf go1.22.2.linux-arm64.tar.gz && \
    rm go1.22.2.linux-arm64.tar.gz
ENV PATH="/usr/local/go/bin:$PATH"

WORKDIR /home/condor/app

# Copy project files (for build context)
COPY --chown=condor:condor . .

# Pre-download Go modules for the API server
RUN cd /home/condor/app/cmd/htcondor-api && go mod download

# Build the API server binary at image build time
RUN cd /home/condor/app/cmd/htcondor-api && go build -buildvcs=false -o /home/condor/app/htcondor-api

# create a user clock
RUN useradd -m -s /bin/bash clock && \
    echo 'clock ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    echo 'condor ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER clock

# Default command: run the built API server in demo mode
CMD ["/home/condor/app/htcondor-api", "--demo", "--user-header", "X-Remote-User"]
