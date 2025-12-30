# HTTP Server Handler Embedding

## Overview

The `httpserver` package has been refactored to allow embedding the HTCondor HTTP API handler inside another HTTP server. This provides flexibility for users who want to integrate HTCondor functionality into their existing web applications.

## Architecture

### Handler

The `Handler` type contains all the business logic for handling HTCondor HTTP API requests. It implements `http.Handler` and can be used independently.

```go
type Handler struct {
    // All business logic fields (schedd, collector, logger, etc.)
}

func NewHandler(cfg HandlerConfig) (*Handler, error)
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

### Server

The `Server` type wraps a `Handler` and adds HTTP server functionality (listening, TLS, lifecycle management).

```go
type Server struct {
    *Handler         // Embedded handler
    httpServer *http.Server
    listener   net.Listener
}

func NewServer(cfg Config) (*Server, error)
func (s *Server) Start() error
func (s *Server) StartTLS(certFile, keyFile string) error
func (s *Server) Shutdown(ctx context.Context) error
```

## Usage

### Standalone Handler (New Feature)

Create a handler and embed it in your own HTTP server:

```go
handler, err := httpserver.NewHandler(httpserver.HandlerConfig{
    ScheddName: "my-schedd",
    ScheddAddr: "localhost:9618",
    Collector:  collector,
})
if err != nil {
    log.Fatal(err)
}

// Use in your custom server
mux := http.NewServeMux()
mux.Handle("/condor/", http.StripPrefix("/condor", handler))
mux.HandleFunc("/custom", myCustomHandler)

server := &http.Server{
    Addr:    ":8080",
    Handler: mux,
}
server.ListenAndServe()
```

### Complete Server (Existing API)

Use the `Server` type for a complete, ready-to-use HTTP server:

```go
server, err := httpserver.NewServer(httpserver.Config{
    ListenAddr: ":8080",
    ScheddName: "my-schedd",
    ScheddAddr: "localhost:9618",
})
if err != nil {
    log.Fatal(err)
}

// Start the server
if err := server.Start(); err != nil {
    log.Fatal(err)
}
```

## Configuration

### HandlerConfig

Contains configuration for the handler's functionality:
- Schedd connection settings
- Authentication settings
- OAuth2/MCP settings
- Metrics settings
- Logger configuration

### Config

Extends `HandlerConfig` with HTTP server settings:
- Listen address
- TLS certificates
- HTTP timeouts
- All `HandlerConfig` fields

## Backward Compatibility

The existing `Server` API remains unchanged. All existing code using `NewServer()` will continue to work without modifications.

## Migration Guide

If you previously wanted to embed the server but couldn't:

**Before** (Not possible):
```go
// Could not use httpserver with existing HTTP infrastructure
```

**After**:
```go
handler, err := httpserver.NewHandler(config)
// Now you can mount the handler anywhere in your HTTP routing
```

## Implementation Notes

- `Server` embeds `Handler` to avoid code duplication
- All handler methods remain on `Handler` for standalone use
- Server-specific functionality (lifecycle, background tasks) stays in `Server`
- Routes are set up through `Handler.SetupRoutes()` which accepts a setup function
- Access logging is applied at the Server level via middleware

## Testing

Tests may need updates to account for the new structure. When constructing test servers, use:

```go
handler := &httpserver.Handler{
    // Initialize handler fields
}
server := &httpserver.Server{
    Handler: handler,
    // Initialize server-specific fields
}
```

Or use the constructor functions:
```go
server, err := httpserver.NewServer(config)
```
