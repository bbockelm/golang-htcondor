# HTTP API Configuration Example

This directory contains example HTCondor configuration files for the HTTP API server.

## Overview

The HTTP API server reads configuration from HTCondor's configuration system using standard HTCondor configuration parameters. No separate YAML or configuration file is needed.

## Configuration Parameters

### Required Parameters

```bash
# Schedd configuration (required for normal mode)
SCHEDD_NAME = local
SCHEDD_HOST = 127.0.0.1
SCHEDD_PORT = 9618
```

### HTTP Server Parameters

```bash
# Listen address (default: :8080)
HTTP_API_LISTEN_ADDR = :8443

# TLS/HTTPS configuration (optional - both required for TLS)
HTTP_API_TLS_CERT = /etc/condor/certs/server.crt
HTTP_API_TLS_KEY = /etc/condor/certs/server.key

# HTTP timeout configuration (optional, duration strings)
HTTP_API_READ_TIMEOUT = 30s      # Default: 30s
HTTP_API_WRITE_TIMEOUT = 30s     # Default: 30s
HTTP_API_IDLE_TIMEOUT = 2m       # Default: 120s

# User header for authentication (optional)
# When specified, the server extracts username from this header
HTTP_API_USER_HEADER = X-Forwarded-User

# JWT signing key path (optional, used in demo mode)
HTTP_API_SIGNING_KEY = /etc/condor/keys/jwt_signing.key
```

## Usage

### Basic HTTP Server

Create `/etc/condor/config.d/99-http-api.config`:

```bash
# Basic HTTP API configuration
HTTP_API_LISTEN_ADDR = :8080
```

Start the server:

```bash
htcondor-api --mode=normal
```

The server will listen on port 8080 with HTTP.

### HTTPS Server with TLS

Create `/etc/condor/config.d/99-http-api.config`:

```bash
# HTTPS API configuration
HTTP_API_LISTEN_ADDR = :8443
HTTP_API_TLS_CERT = /etc/condor/certs/server.crt
HTTP_API_TLS_KEY = /etc/condor/certs/server.key
HTTP_API_READ_TIMEOUT = 45s
HTTP_API_WRITE_TIMEOUT = 45s
HTTP_API_IDLE_TIMEOUT = 5m
```

Generate self-signed certificates (for testing):

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

Start the server:

```bash
htcondor-api --mode=normal
```

The server will listen on port 8443 with HTTPS.

### Behind Reverse Proxy

If running behind a reverse proxy that sets authentication headers:

```bash
# Reverse proxy configuration
HTTP_API_LISTEN_ADDR = 127.0.0.1:8080
HTTP_API_USER_HEADER = X-Forwarded-User
HTTP_API_READ_TIMEOUT = 60s
HTTP_API_WRITE_TIMEOUT = 60s
```

The server will extract the authenticated username from the `X-Forwarded-User` header.

## Timeout Configuration

Timeouts are specified as duration strings:
- `30s` - 30 seconds
- `1m` - 1 minute
- `1h30m` - 1 hour 30 minutes

### Read Timeout
Maximum duration for reading the entire request (including body).

### Write Timeout
Maximum duration before timing out writes of the response.

### Idle Timeout
Maximum duration to wait for the next request when keep-alives are enabled.

## TLS Certificate Management

For production use, obtain certificates from a trusted Certificate Authority (CA):

1. **Let's Encrypt**: Free automated certificates
2. **Corporate CA**: Internal CA certificates
3. **Commercial CA**: Purchased certificates

### Self-Signed Certificates (Testing Only)

Generate self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=schedd.example.com"
```

Set permissions:

```bash
chmod 600 server.key
chmod 644 server.crt
```

## Security Considerations

1. **TLS Certificates**: Always use valid certificates in production
2. **Private Keys**: Protect private key files (chmod 600)
3. **Token Authentication**: Enable HTCondor token authentication
4. **Firewall**: Restrict access to API port
5. **Reverse Proxy**: Consider nginx/Apache for additional security layers

## Complete Example

`/etc/condor/config.d/99-http-api.config`:

```bash
# HTCondor HTTP API Configuration

# Server configuration
HTTP_API_LISTEN_ADDR = :8443

# TLS/HTTPS (production)
HTTP_API_TLS_CERT = /etc/condor/certs/server.crt
HTTP_API_TLS_KEY = /etc/condor/certs/server.key

# Timeouts
HTTP_API_READ_TIMEOUT = 30s
HTTP_API_WRITE_TIMEOUT = 30s
HTTP_API_IDLE_TIMEOUT = 120s

# Authentication (if behind reverse proxy)
# HTTP_API_USER_HEADER = X-Forwarded-User

# Demo mode JWT signing key (optional)
# HTTP_API_SIGNING_KEY = /etc/condor/keys/jwt_signing.key
```

## Testing Configuration

Test your configuration:

```bash
# View current configuration
condor_config_val HTTP_API_LISTEN_ADDR
condor_config_val HTTP_API_TLS_CERT
condor_config_val HTTP_API_TLS_KEY

# Start server
htcondor-api --mode=normal

# Test HTTP endpoint
curl http://localhost:8080/openapi.json

# Test HTTPS endpoint
curl --insecure https://localhost:8443/openapi.json
```

## Command Line Overrides

Command-line flags take precedence over configuration file values:

```bash
# Override listen address
htcondor-api --mode=normal --listen=:9090

# Override user header
htcondor-api --mode=normal --user-header=X-Auth-User
```
