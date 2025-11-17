# Device Code Authorization Flow

This document describes the OAuth 2.0 Device Authorization Grant (RFC 8628) implementation in the HTCondor HTTP server.

## Overview

The device code flow is designed for devices that either lack a browser or have limited input capabilities. It allows users to authorize a device using a separate device with better input capabilities (like a smartphone or computer).

## Flow Diagram

```
+----------+                                +----------------+
|          |>---(1) Client Identifier ---->|                |
|          |                                |                |
|          |<---(2) Device Code,        ---|                |
|  Device  |        User Code,              | Authorization  |
|  Client  |        & Verification URI      |     Server     |
|          |                                |                |
|          |  [polling]                     |                |
|          |>---(5) Device Code         --->|                |
|          |     & Client Identifier        |                |
|          |                                |                |
|          |<---(6) Access Token        ---|                |
+----------+   (& Optional Refresh Token)   +----------------+
      v                                            ^
      :                                            |
     (3) User Code & Verification URI              |
      :                                            |
      v                                            |
+----------+                                       |
| End User |                                       |
|    at    |<---(4) Authenticate                --+
|  Browser |
+----------+
```

## API Endpoints

### 1. Device Authorization Endpoint

**Endpoint:** `POST /mcp/oauth2/device/authorize`

**Request:**
```bash
curl -X POST http://localhost:8080/mcp/oauth2/device/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_CLIENT_ID&scope=openid mcp:read mcp:write"
```

**Response:**
```json
{
  "device_code": "aAH140Fj32bBh76xfKzMo1CFR6VlxlPgfOjtXffVP9c=",
  "user_code": "ADXL-GENT",
  "verification_uri": "http://localhost:8080/mcp/oauth2/device/verify",
  "verification_uri_complete": "http://localhost:8080/mcp/oauth2/device/verify?user_code=ADXL-GENT",
  "expires_in": 600,
  "interval": 5
}
```

### 2. User Verification Endpoint

**Endpoint:** `GET /mcp/oauth2/device/verify`

Users visit this URL in a browser to enter their user code and approve the device.

**Query Parameters:**
- `user_code` (optional): Pre-filled user code

### 3. Token Endpoint (Polling)

**Endpoint:** `POST /mcp/oauth2/token`

**Request:**
```bash
curl -X POST http://localhost:8080/mcp/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=DEVICE_CODE&client_id=YOUR_CLIENT_ID"
```

**Responses:**

While pending:
```json
{
  "error": "authorization_pending",
  "error_description": "Authorization pending"
}
```

On success:
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGc...",
  "scope": "openid mcp:read mcp:write"
}
```

## Usage Example

### Step 1: Initiate Device Authorization

```bash
response=$(curl -s -X POST http://localhost:8080/mcp/oauth2/device/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_CLIENT_ID&scope=openid mcp:read mcp:write")

device_code=$(echo $response | jq -r '.device_code')
user_code=$(echo $response | jq -r '.user_code')
verification_uri=$(echo $response | jq -r '.verification_uri')

echo "Please visit: $verification_uri"
echo "And enter code: $user_code"
```

### Step 2: Poll for Token

```bash
while true; do
  response=$(curl -s -X POST http://localhost:8080/mcp/oauth2/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=$device_code&client_id=YOUR_CLIENT_ID")
  
  error=$(echo $response | jq -r '.error // empty')
  
  if [ "$error" = "authorization_pending" ]; then
    echo "Waiting for user authorization..."
    sleep 5
  elif [ -z "$error" ]; then
    access_token=$(echo $response | jq -r '.access_token')
    echo "Success! Access token: $access_token"
    break
  else
    echo "Error: $error"
    break
  fi
done
```

### Step 3: Use the Access Token

```bash
curl -X POST http://localhost:8080/mcp/message \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "device-client", "version": "1.0"}
    }
  }'
```

## Client Registration

To use the device code flow, you need to register an OAuth2 client with the appropriate grant type:

```bash
curl -X POST http://localhost:8080/mcp/oauth2/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Device Client",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
    "scope": ["openid", "mcp:read", "mcp:write"]
  }'
```

Response:
```json
{
  "client_id": "client_1234567890",
  "client_secret": "secret_here",
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
  "scope": "openid mcp:read mcp:write"
}
```

## Error Codes

- `authorization_pending`: The authorization request is still pending; the device should continue polling
- `slow_down`: The device is polling too frequently; increase the polling interval
- `access_denied`: The end user denied the authorization request
- `expired_token`: The device code has expired
- `invalid_grant`: The device code is invalid, expired, or has already been used

## Configuration

The device code flow is automatically enabled when OAuth2 is configured on the server:

```go
server, err := httpserver.NewServer(httpserver.Config{
    ListenAddr:   "127.0.0.1:8080",
    EnableMCP:    true,
    OAuth2DBPath: "/path/to/oauth2.db",
    OAuth2Issuer: "http://localhost:8080",
    // ... other config
})
```

## Security Considerations

1. **Device Code Expiration**: Device codes expire after 10 minutes by default
2. **One-Time Use**: Device codes can only be used once to obtain tokens
3. **User Approval Required**: All device authorizations require explicit user approval
4. **Scope Validation**: Requested scopes are validated against supported scopes
5. **Polling Rate Limiting**: Clients should respect the `interval` value to avoid overloading the server

## Testing

### Unit Tests

```bash
go test ./httpserver -v -run TestDeviceCode
```

### Integration Tests

```bash
# Requires HTCondor to be installed
go test -tags=integration ./httpserver -v -run TestDeviceCodeFlowIntegration
```

## References

- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.0 Device Flow - Best Practices](https://oauth.net/2/device-flow/)
