# Built-in Identity Provider (IDP)

The golang-htcondor HTTP server includes a built-in OAuth2/OIDC Identity Provider (IDP) that can be used for authentication in development, testing, and demo scenarios.

## Features

- **OAuth2/OIDC Compliant**: Full OAuth2 authorization code flow with OIDC support
- **Username/Password Authentication**: Simple login form with bcrypt-hashed passwords
- **Separate Storage**: Uses dedicated SQLite tables (prefixed with `idp_*`)
- **OIDC Discovery**: Metadata available at `/.well-known/openid-configuration`
- **Auto-Configuration**: Automatically creates admin user and OAuth2 client on first startup

## Demo Mode

In demo mode (`htcondor-api --demo`), the IDP is **always enabled**. On first startup:

1. An `admin` user is created with a randomly generated password
2. Credentials are printed to the terminal
3. An OAuth2 client is auto-generated with proper redirect URI

Example output:
```
========================================
IDP Admin Credentials
========================================
Username: admin
Password: YG12b45NsPqVfHronFmI
========================================
```

Note: Client credentials are used internally and are not printed to the terminal.

## Normal Mode

In normal mode, the IDP is **conditionally enabled** via HTCondor configuration:

```bash
# Enable the built-in IDP
HTTP_API_ENABLE_IDP = true

# Optional: Specify custom database path (default: same as OAuth2 database)
HTTP_API_IDP_DB_PATH = /var/lib/condor/oauth2.db

# Optional: Specify custom issuer URL (default: derived from listen address)
HTTP_API_IDP_ISSUER = https://htcondor.example.com
```

## Endpoints

The IDP provides the following endpoints:

### OIDC Discovery
- `GET /idp/.well-known/openid-configuration` - OIDC metadata
- `GET /idp/.well-known/jwks.json` - JSON Web Key Set

### Authentication
- `GET /idp/login` - Login form
- `POST /idp/login` - Login submission

### OAuth2 Flow
- `GET /idp/authorize` - Authorization endpoint
- `POST /idp/token` - Token endpoint
- `GET /idp/userinfo` - UserInfo endpoint

## Usage Example

### 1. Start the server in demo mode

```bash
htcondor-api --demo
```

Note the printed admin credentials.

### 2. Access the login page

Navigate to `http://localhost:8080/idp/login` and log in with the admin credentials.

### 3. OAuth2 Authorization Code Flow

```bash
# 1. Get authorization code (will redirect to login if not authenticated)
curl -L "http://localhost:8080/idp/authorize?client_id=htcondor-server&response_type=code&redirect_uri=http://localhost:8080/idp/callback&scope=openid+profile&state=random-state-string"

# 2. Exchange code for tokens
curl -X POST http://localhost:8080/idp/token \
  -d "grant_type=authorization_code" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=http://localhost:8080/idp/callback" \
  -d "client_id=htcondor-server"

# 3. Use the access token
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:8080/idp/userinfo
```

## User Management

Currently, user management is manual. To add users:

1. Connect to the SQLite database:
   ```bash
   sqlite3 idp.db
   ```

2. Use the `CreateUser` function in the code, or directly insert hashed passwords:
   ```sql
   -- Password should be bcrypt-hashed
   INSERT INTO idp_users (username, password_hash) VALUES ('user', '<bcrypt_hash>');
   ```

Future enhancements may include user management APIs.

## Security Considerations

### Demo Mode
- **Not for production**: Demo mode uses HTTP (not HTTPS) and auto-generated credentials
- Credentials are printed to stdout (visible in logs)
- Database is in a temporary directory (cleared on shutdown)

### Normal Mode
- Use HTTPS in production (configure TLS certificates)
- Store database in a secure location with proper file permissions
- Consider using a reverse proxy (nginx, Apache) for additional security
- Rotate client secrets regularly
- Rate limiting is automatically enabled for login attempts (5 requests/second per IP with burst of 10)
- Monitor failed login attempts

### Demo Mode
- Automatically generates self-signed TLS certificate for HTTPS
- If self-signed cert generation fails, falls back to HTTP (less secure)
- Credentials are printed to stdout (visible in logs)
- Database is in a temporary directory (cleared on shutdown)

## Database Schema

The IDP uses the following tables (all prefixed with `idp_`):

- `idp_users` - User accounts with bcrypt-hashed passwords
- `idp_clients` - OAuth2 clients
- `idp_access_tokens` - Access token sessions
- `idp_refresh_tokens` - Refresh token sessions
- `idp_authorization_codes` - Authorization code sessions
- `idp_oidc_sessions` - OpenID Connect sessions
- `idp_rsa_keys` - RSA private key for token signing
- `idp_hmac_secrets` - HMAC secret for token generation
- `idp_jwt_assertions` - JWT assertion replay prevention

## Testing

Run the IDP tests:

```bash
go test -v ./httpserver -run TestIDP
```

This will test:
- Authorization code flow
- Refresh token flow
- Login form rendering
- OIDC metadata discovery
- User authentication

## Limitations

- Single-tenant: All users share the same database
- No user registration API (manual user creation only)
- No password reset functionality
- No multi-factor authentication
- No session management UI
- No user profile management

## Future Enhancements

Potential improvements for future releases:

- User management API (CRUD operations)
- Password reset via email
- Session management dashboard
- OAuth2 client management UI
- Group/role-based access control
- Integration with external identity providers (LDAP, SAML)
- Audit logging for authentication events
