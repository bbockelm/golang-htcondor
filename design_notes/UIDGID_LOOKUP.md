# UID/GID Lookup System

The droppriv package includes a robust UID/GID lookup system with multiple strategies and caching.

## Features

- **Multiple lookup strategies**: Automatically selects the best available method
- **1-minute caching**: Reduces system call overhead
- **CGO optimization**: When CGO is enabled, uses `getpwnam_r` automatically via Go's stdlib
- **Fallback support**: Gracefully degrades to simpler methods when advanced features unavailable

## Strategies (in priority order)

**With CGO enabled:**
- **Go's os/user package exclusively**
  - Uses `getpwnam_r` and standard C library functions
  - Supports NSS modules (LDAP, NIS, SSSD, etc.) for glibc
  - Best performance and compatibility

**Without CGO:**

1. **systemd-userdbd** (via varlink protocol)
   - Modern Linux systems with systemd managing users (typically, non-RHEL)
   - Socket: `/run/systemd/userdb/io.systemd.UserDatabase`

2. **SSSD InfoPipe** (via D-Bus)
   - Any Linux with SSSD configured and the `ifp` provider enabled
   - D-Bus service: `org.freedesktop.sssd.infopipe`
   - Provides access to centralized user databases (LDAP, AD, etc.)

3. **Go's os/user package**
   - Parses `/etc/passwd` and `/etc/group`
   - Works for local users only
   - Always available (ultimate fallback)

## Usage

### Simple lookup
```go
import "github.com/bbockelm/golang-htcondor/droppriv"

// Look up a user
info, err := droppriv.LookupUser("nobody")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("UID: %d, GID: %d\n", info.UID, info.GID)
```

### Custom strategy
```go
// Create a specific strategy
strategy, err := droppriv.NewGoLookup()
if err != nil {
    log.Fatal(err)
}

// Use it directly
info, err := strategy.LookupUser("nobody")
```

### Custom caching
```go
// Create cached lookup with custom TTL
strategy, _ := droppriv.NewGoLookup()
cached := droppriv.NewCachedLookup(strategy, 5*time.Minute)

info, err := cached.LookupUser("nobody")
```

## Integration with droppriv Manager

The Manager automatically uses this lookup system when resolving usernames:

```go
// Manager internally uses LookupUser() for all username resolutions
mgr, err := droppriv.NewManager(droppriv.Config{
    Enabled:    true,
    CondorUser: "condor",  // Resolved via LookupUser()
})

// Operations also use the lookup system
err = mgr.OpenFile("nobody", "/path/to/file", os.O_CREATE|os.O_WRONLY, 0644)
```

## Cache Behavior

- Default TTL: 1 minute
- Thread-safe
- Per-username caching
- Automatic expiration
- Manual clear available via `ClearCache()`

## CGO Note

**When CGO is enabled**, Go's `user.Lookup()` automatically uses `getpwnam_r` and other optimized C library functions. This provides:
- Thread-safe lookups
- Support for NSS modules (LDAP, NIS, etc.)
- Better performance than parsing files
- Compatibility with all authentication backends

**When CGO is disabled**, Go falls back to parsing `/etc/passwd`, which:
- Works for local users
- May not see network-based users (LDAP, etc.)
- Still functional but less feature-complete

## Error Handling

```go
info, err := droppriv.LookupUser("nonexistent")
if err != nil {
    if _, ok := err.(*droppriv.ErrUserNotFound); ok {
        fmt.Println("User not found")
    } else {
        fmt.Printf("Lookup error: %v\n", err)
    }
}
```

## Strategy Detection

Check which strategy is being used:

```go
lookup := droppriv.DefaultLookup()
fmt.Printf("Using strategy: %s\n", lookup.Name())
// Output might be: "go-os-user", "systemd-userdbd-varlink", etc.
```
