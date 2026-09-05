package httpserver

import (
	"encoding/json"
	"net/http"

	"github.com/bbockelm/golang-htcondor/logging"
)

// OpenAPI schema for the HTCondor RESTful API
const openAPISchema = `{
  "openapi": "3.0.0",
  "info": {
    "title": "HTCondor RESTful API",
    "description": "RESTful API for managing HTCondor jobs",
    "version": "1.0.0"
  },
  "servers": [
    {
      "url": "/api/v1",
      "description": "API v1"
    }
  ],
  "security": [
    {
      "bearerAuth": []
    },
    {
      "oauth2": ["openid", "profile", "email"]
    }
  ],
  "tags": [
    {
      "name": "placement",
      "description": "condor_placementd: issue and audit access-point credentials for identities that authenticate elsewhere. Admin-only — the daemon registers its commands at ADMINISTRATOR and this server calls it as the access point's own identity, so these endpoints require membership in the web UI admin group. Absent a placementd, every one of them but /placement/status returns 503."
    }
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "TOKEN",
        "description": "HTCondor TOKEN authentication. The bearer token is used to authenticate with the schedd on behalf of the user."
      },
      "oauth2": {
        "type": "oauth2",
        "description": "OAuth2 Authorization Code Flow",
        "flows": {
          "authorizationCode": {
            "authorizationUrl": "/mcp/oauth2/authorize",
            "tokenUrl": "/mcp/oauth2/token",
            "scopes": {
              "openid": "OpenID Connect",
              "profile": "User Profile",
              "email": "User Email"
            }
          }
        }
      }
    },
    "schemas": {
      "Error": {
        "type": "object",
        "properties": {
          "error": {
            "type": "string",
            "description": "Error type"
          },
          "message": {
            "type": "string",
            "description": "Error message"
          },
          "code": {
            "type": "integer",
            "description": "HTTP status code"
          }
        }
      },
      "JobSubmitRequest": {
        "type": "object",
        "required": ["submit_file"],
        "properties": {
          "submit_file": {
            "type": "string",
            "description": "HTCondor submit file content. Basic format: executable, arguments, output, error, log, and queue directive."
          }
        },
        "example": {
          "submit_file": "executable = /bin/echo\narguments = Hello World\noutput = hello.out\nerror = hello.err\nlog = hello.log\nqueue"
        }
      },
      "JobSubmitResponse": {
        "type": "object",
        "properties": {
          "cluster_id": {
            "type": "integer",
            "description": "Cluster ID of submitted job(s)"
          },
          "job_ids": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "description": "Array of job IDs in cluster.proc format"
          }
        }
      },
      "JobListResponse": {
        "type": "object",
        "properties": {
          "jobs": {
            "type": "array",
            "items": {
              "type": "object",
              "description": "Job ClassAd as a JSON object"
            },
            "description": "Array of job ClassAds"
          },
          "total_returned": {
            "type": "integer",
            "description": "Number of jobs returned in this response"
          },
          "has_more": {
            "type": "boolean",
            "description": "Whether there are more results available"
          },
          "next_page_token": {
            "type": "string",
            "description": "Token to use for fetching the next page (only present if has_more is true)"
          },
          "error": {
            "type": "string",
            "description": "Error message if an error occurred during streaming. When present, the jobs array contains all successfully streamed jobs before the error."
          }
        }
      },
      "WhoAmIResponse": {
        "type": "object",
        "required": ["authenticated"],
        "properties": {
          "authenticated": {
            "type": "boolean",
            "description": "Whether the request was authenticated"
          },
          "user": {
            "type": "string",
            "description": "The authenticated username (only present if authenticated is true)"
          }
        }
      },
      "VersionResponse": {
        "type": "object",
        "required": ["version", "commit", "start_time", "uptime_seconds"],
        "properties": {
          "version": {
            "type": "string",
            "description": "Version string derived from the most recent git tag (output of 'git describe --tags --always --dirty'). Defaults to 'dev' if not set at build time."
          },
          "commit": {
            "type": "string",
            "description": "Short git SHA of the commit the binary was built from. Defaults to 'unknown' if not set at build time."
          },
          "start_time": {
            "type": "string",
            "format": "date-time",
            "description": "When this server process came up, RFC3339 in UTC."
          },
          "uptime_seconds": {
            "type": "integer",
            "format": "int64",
            "description": "Seconds elapsed since start_time, measured by the server."
          }
        }
      },
      "AdvertiseRequest": {
        "type": "object",
        "properties": {
          "ad": {
            "type": "object",
            "description": "ClassAd to advertise (JSON format)"
          },
          "command": {
            "type": "string",
            "description": "Optional UPDATE command (e.g., 'UPDATE_STARTD_AD'). If not specified, determined from ad's MyType",
            "enum": ["UPDATE_STARTD_AD", "UPDATE_SCHEDD_AD", "UPDATE_MASTER_AD", "UPDATE_SUBMITTOR_AD", "UPDATE_COLLECTOR_AD", "UPDATE_NEGOTIATOR_AD", "UPDATE_LICENSE_AD", "UPDATE_STORAGE_AD", "UPDATE_ACCOUNTING_AD", "UPDATE_GRID_AD", "UPDATE_HAD_AD", "UPDATE_AD_GENERIC", "UPDATE_STARTD_AD_WITH_ACK"]
          },
          "with_ack": {
            "type": "boolean",
            "description": "Request acknowledgment from collector (forces TCP)",
            "default": false
          }
        }
      },
      "AdvertiseResponse": {
        "type": "object",
        "required": ["success", "succeeded", "failed"],
        "properties": {
          "success": {
            "type": "boolean",
            "description": "Whether all advertisements succeeded"
          },
          "message": {
            "type": "string",
            "description": "Human-readable status message"
          },
          "succeeded": {
            "type": "integer",
            "description": "Number of ads successfully advertised"
          },
          "failed": {
            "type": "integer",
            "description": "Number of ads that failed to advertise"
          },
          "errors": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "description": "Error messages for failed ads (if any)"
          }
        }
      },
      "HistoryListResponse": {
        "type": "object",
        "properties": {
          "records": {
            "type": "array",
            "items": {
              "type": "object",
              "description": "History record ClassAd as a JSON object"
            },
            "description": "Array of history ClassAds (only present in non-streaming mode)"
          },
          "error": {
            "type": "string",
            "description": "Error message if an error occurred during streaming. When present in streaming mode, records up to the error were already sent."
          }
        },
        "description": "History records response. In non-streaming mode, returns a JSON object with 'records' array. In streaming mode (stream_results=true), returns JSON Lines format with one record per line."
      },
      "CredentialStatus": {
        "type": "object",
        "properties": {
          "exists": {
            "type": "boolean",
            "description": "Whether the credential exists"
          },
          "updated_at": {
            "type": "string",
            "format": "date-time",
            "description": "When the credential was last updated"
          }
        }
      },
      "UserCredentialRequest": {
        "type": "object",
        "required": ["cred_type", "credential"],
        "properties": {
          "cred_type": {
            "type": "string",
            "enum": ["Kerberos"],
            "description": "Credential type (Kerberos)"
          },
          "credential": {
            "type": "string",
            "description": "Credential payload (base64 or plain string)"
          },
          "user": {
            "type": "string",
            "description": "Optional user. Defaults to the authenticated user."
          }
        }
      },
      "ServiceCredentialRequest": {
        "type": "object",
        "required": ["cred_type", "credential", "service"],
        "properties": {
          "cred_type": {
            "type": "string",
            "enum": ["OAuth"],
            "description": "Credential type (OAuth only)"
          },
          "credential": {
            "type": "string",
            "description": "Credential payload: a JSON document such as {\"access_token\":\"...\"}, optionally base64-encoded. A bare token string is rejected -- the credd would store it and then fail every later read. Empty requests a credmon-minted token instead of supplying one."
          },
          "service": {
            "type": "string",
            "description": "Service identifier"
          },
          "handle": {
            "type": "string",
            "description": "Optional handle to distinguish multiple credentials for the same service"
          },
          "user": {
            "type": "string",
            "description": "Optional user. Defaults to the authenticated user."
          },
          "refresh": {
            "type": "boolean",
            "description": "Whether this is a refresh token that needs processing by CredMon"
          }
        }
      },
      "ServiceStatus": {
        "type": "object",
        "properties": {
          "service": {"type": "string"},
          "handle": {"type": "string"},
          "exists": {"type": "boolean"},
          "updated_at": {"type": "string", "format": "date-time"}
        }
      },
      "OAuthCredentialResponse": {
        "type": "object",
        "properties": {
          "credential": {
            "type": "string",
            "description": "OAuth credential payload"
          }
        }
      },
      "PlacementUser": {
        "type": "object",
        "description": "A foreign identity known to the placementd, merged with its newest live token.",
        "properties": {
          "username": {"type": "string", "description": "Foreign identity, as it appears in the placementd map file."},
          "ap_user_id": {"type": "string", "description": "Local AP account the identity maps to; the token subject."},
          "token_expiration": {"type": "string", "format": "date-time", "description": "Expiration of this user's newest unexpired token. Absent when they hold none."},
          "mapping_expiration": {"type": "string", "format": "date-time", "description": "When the map-file entry stops being honored. Absent means never."},
          "projects": {"type": "array", "items": {"type": "string"}, "description": "AP projects the user may bind a token to."},
          "authorizations": {"type": "array", "items": {"type": "string"}, "description": "Authorizations the map file grants."},
          "authorized": {"type": "boolean", "description": "False for a user who still holds a live token but is no longer in the map file: existing tokens keep working, but they cannot log in again."}
        }
      },
      "PlacementToken": {
        "type": "object",
        "description": "An issued token as recorded by the placementd. The token string itself is not stored and is never returned here.",
        "properties": {
          "token_id": {"type": "string", "description": "The token's jti claim."},
          "username": {"type": "string", "description": "Foreign identity the token was issued for."},
          "ap_user_id": {"type": "string", "description": "Local AP account named in the token's subject."},
          "requester": {"type": "string", "description": "Who asked for the token; differs from username only for instructor-issued tokens."},
          "authorizations": {"type": "array", "items": {"type": "string"}, "description": "The token's bounding set."},
          "project": {"type": "string", "description": "The token's project claim, if any."},
          "expiration": {"type": "string", "format": "date-time"},
          "expired": {"type": "boolean", "description": "Whether the expiration is already in the past, computed server-side."}
        }
      },
      "PlacementAuthorization": {
        "type": "object",
        "description": "An authorization the placementd can grant, with the display metadata from its authorizations map file.",
        "properties": {
          "name": {"type": "string", "description": "The authorization as it appears in a token's bounding set."},
          "label": {"type": "string", "description": "Human-readable name to display instead of the raw name."},
          "color": {"type": "string", "description": "Operator-supplied display color. Whatever the map file says, so treat it as a hint and keep a fallback."},
          "description": {"type": "string"}
        }
      },
      "PlacementLoginRequest": {
        "type": "object",
        "required": ["username"],
        "properties": {
          "username": {"type": "string", "description": "Foreign identity to log in. Must appear in the placementd map file."},
          "authorizations": {"type": "array", "items": {"type": "string"}, "description": "Narrows the token's bounding set. EVERY entry must be one the user is entitled to, or the whole request is refused. Omit for the user's full set."},
          "project": {"type": "string", "description": "Ties the token, and the jobs submitted with it, to an AP project the user is authorized for."},
          "requester": {"type": "string", "description": "Identity asking on the user's behalf. Must itself be mapped and hold the INSTRUCTOR authorization."}
        }
      },
      "PlacementLoginResponse": {
        "type": "object",
        "properties": {
          "token": {"type": "string", "description": "The signed IDToken. A bearer credential for the AP identity it names: it is returned exactly once and is not recoverable afterwards."}
        }
      },
      "AdminClientUse": {
        "type": "object",
        "description": "One entry of a client's recent-users sample.",
        "properties": {
          "subject": {"type": "string"},
          "at": {"type": "string", "format": "date-time"}
        }
      },
      "AdminClient": {
        "type": "object",
        "description": "An OAuth2 client as the admin UI sees it. Secrets are never returned.",
        "properties": {
          "id": {"type": "string", "description": "Client id. A dynamically registered one looks like \"client_<unixnano>\" and says nothing about the app -- which is what name, notes and origin are for."},
          "name": {"type": "string", "description": "What the client called itself at registration (RFC 7591 client_name). Absent for seeded clients and for anything registered before this was kept."},
          "notes": {"type": "string", "description": "Operator annotation, editable via PATCH. Often the only identifying information for a client that predates provenance tracking."},
          "origin": {"type": "string", "enum": ["dynamic", "seeded", ""], "description": "How the client came to exist: \"dynamic\" registered itself through /mcp/oauth2/register, \"seeded\" was created by this server. EMPTY MEANS UNKNOWN, not \"not dynamic\" -- the row predates the field and nobody recorded the answer."},
          "last_used_at": {"type": "string", "format": "date-time", "description": "When this client last obtained a token. Absent means never. Written on a debounced background flush, so it may lag real usage; it is a \"roughly when\", not an audit record."},
          "recent_users": {"type": "array", "items": {"$ref": "#/components/schemas/AdminClientUse"}, "description": "Rolling sample of the last few distinct subjects to obtain a token through this client, newest first."},
          "refresh_blocked_by": {"type": "array", "items": {"type": "string"}, "description": "What stops this client from ever receiving a refresh token, so its users re-authorize on every access-token expiry: the refresh_token grant, the offline_access scope, or both. Nothing errors when this is misconfigured -- the client simply never gets a refresh token. Absent means nothing blocks it, OR that the client has no interactive flow and so has no user to inconvenience."},
          "redirect_uris": {"type": "array", "items": {"type": "string"}},
          "grant_types": {"type": "array", "items": {"type": "string"}},
          "response_types": {"type": "array", "items": {"type": "string"}},
          "scopes": {"type": "array", "items": {"type": "string"}},
          "public": {"type": "boolean"},
          "created_at": {"type": "string", "format": "date-time"}
        }
      },
      "DBMirrorRoutingCount": {
        "type": "object",
        "description": "One routing tally since process start.",
        "properties": {
          "table": {"type": "string", "description": "Which read was being routed: jobs or history."},
          "decision": {"type": "string", "enum": ["served", "declined"]},
          "reason": {"type": "string", "description": "Why. \"served\" for a mirror read; otherwise the decline reason (stale, no_mirror, history_gap, unsupported_query, ...)."},
          "count": {"type": "integer", "format": "int64"}
        }
      },
      "DBMirrorTest": {
        "type": "object",
        "properties": {
          "ok": {"type": "boolean", "description": "Whether every stage succeeded."},
          "constraint": {"type": "string", "description": "The constraint used, echoed so the page can show what was asked. Matches nothing by design."},
          "total_millis": {"type": "integer", "format": "int64"},
          "stages": {
            "type": "array",
            "description": "One entry per step attempted, in order. The probe stops at the first failure and does not invent the stages after it.",
            "items": {
              "type": "object",
              "properties": {
                "name": {"type": "string", "description": "configured, discover, connect, or query."},
                "ok": {"type": "boolean"},
                "detail": {"type": "string", "description": "The outcome worth reading: the mirror found, the row count."},
                "error": {"type": "string"},
                "millis": {"type": "integer", "format": "int64", "description": "How long the stage took. A dial that takes ten seconds and then succeeds is a different problem from one that fails."}
              }
            }
          }
        }
      },
      "DBMirrorHealth": {
        "type": "object",
        "properties": {
          "status": {"type": "string", "enum": ["ok", "warning", "down", "unknown"], "description": "\"ok\" only when reads are actually routing right now. A mirror that is up but too far behind to serve is \"warning\" -- it is running, not working. \"unknown\" means discovery has not run yet, which is not the same as failing."},
          "required": {"type": "boolean", "description": "HTTP_API_DBMIRROR_REQUIRED: a read the mirror cannot serve fails instead of falling back to the schedd."},
          "name": {"type": "string", "description": "The mirror actually in use."},
          "address": {"type": "string"},
          "pinned_name": {"type": "string", "description": "Configured targeting, echoed so a typo is visible next to the empty result it produced."},
          "pinned_address": {"type": "string"},
          "discovered": {"type": "boolean", "description": "Whether an advertisement was read. When false the staleness fields are absent rather than zero -- a 0 would read as \"perfectly caught up\" for a mirror nobody has found."},
          "ad_age_seconds": {"type": "integer", "format": "int64", "description": "How long ago the advertisement was discovered -- the age of this information, not of the mirror's data. Everything the mirror reports about itself was measured when it built the ad; it keeps syncing between advertisements, so an aging ad does not mean a lagging mirror."},
          "job_queue_caught_up": {"type": "boolean"},
          "job_queue_staleness_seconds": {"type": "integer", "format": "int64", "description": "How far the mirror's job queue was behind the schedd when it built its advertisement. Absent when nothing was discovered. Pair with ad_age_seconds, which says how old that measurement is."},
          "history_staleness_seconds": {"type": "integer", "format": "int64", "description": "How far the mirror's history was behind when it built its advertisement. Absent when nothing was discovered."},
          "history_gap": {"type": "boolean", "description": "A history durability gap, which stops all history routing."},
          "jobs_tolerance_seconds": {"type": "integer", "format": "int64", "description": "Live job reads route to the mirror only below this staleness."},
          "history_tolerance_seconds": {"type": "integer", "format": "int64"},
          "last_error": {"type": "string", "description": "Why discovery last failed. Empty does not mean reads are working -- see dial_error."},
          "dial_error": {"type": "string", "description": "Why the last attempt to connect to the mirror failed. Separate from last_error because discovery and dialing fail independently: a good, fresh ad for a database this daemon cannot authenticate to declines every read with dial_failed while discovery reports no error."},
          "dial_last_attempt": {"type": "string", "format": "date-time"},
          "dial_last_success": {"type": "string", "format": "date-time", "description": "When a connection last succeeded. Absent means none has since this server started."},
          "last_attempt": {"type": "string", "format": "date-time", "description": "When discovery last queried the collector. Absent when it never has, which is the whole explanation for a status of \"unknown\"."},
          "last_success": {"type": "string", "format": "date-time", "description": "When discovery last found a mirror."}
        }
      },
      "DBMirrorStatus": {
        "type": "object",
        "properties": {
          "enabled": {"type": "boolean", "description": "Whether routing can run at all. It needs both a collector to discover through and the HTCondor config whose SEC_* knobs authenticate the connection."},
          "health": {"$ref": "#/components/schemas/DBMirrorHealth"},
          "routing": {"type": "array", "items": {"$ref": "#/components/schemas/DBMirrorRoutingCount"}},
          "served_total": {"type": "integer", "format": "int64"},
          "declined_total": {"type": "integer", "format": "int64"}
        }
      },
      "PlacementStatus": {
        "type": "object",
        "properties": {
          "available": {"type": "boolean"},
          "address": {"type": "string", "description": "Sinful string of the placementd in use."},
          "reason": {"type": "string", "description": "Why the placementd is unavailable, when it is."}
        }
      }
    }
  },
  "paths": {
    "/admin/oauth2/clients": {
      "get": {
        "summary": "List OAuth2 clients",
        "description": "Every registered OAuth2 client, newest first, with the provenance fields that make the list readable: the name the client registered under, the operator's notes, how it came to exist, when it last obtained a token, and who for. Requires membership in the web UI admin group.",
        "operationId": "listAdminClients",
        "responses": {
          "200": {"description": "Clients", "content": {"application/json": {"schema": {"type": "object", "properties": {"clients": {"type": "array", "items": {"$ref": "#/components/schemas/AdminClient"}}}}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/admin/oauth2/clients/{id}": {
      "patch": {
        "summary": "Annotate an OAuth2 client",
        "description": "Set the operator's note for a client. The note is the ONLY editable field: everything else is either the client's own assertion at registration or something this server derived, and letting an admin rewrite those would turn the provenance columns into a record of a belief rather than a fact. Requires membership in the web UI admin group.",
        "operationId": "updateAdminClient",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"notes": {"type": "string", "maxLength": 4096}}}}}},
        "responses": {
          "200": {"description": "Updated", "content": {"application/json": {"schema": {"type": "object", "properties": {"notes": {"type": "string"}}}}}},
          "400": {"description": "Malformed body or notes over the length limit", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such client", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "Delete an OAuth2 client",
        "description": "Removes the client and every token issued under it. Useful for clearing dynamic-registration churn. Requires membership in the web UI admin group.",
        "operationId": "deleteAdminClient",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Deleted"},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such client", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/dbmirror/test": {
      "post": {
        "summary": "Test the htcondordb mirror",
        "description": "Runs one real read against the mirror -- discover, connect, query -- and reports each stage separately. The query uses a constraint matching nothing, so the probe moves no rows and is safe to repeat while chasing a misconfiguration. Answers a different question from /dbmirror/status: that reports whether the mirror looks healthy, this reports what happens when a read actually tries, and which step fails. Admin only.",
        "operationId": "testDBMirror",
        "responses": {
          "200": {
            "description": "The probe ran. ok=false with the failing stage is a normal response, not an error.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/DBMirrorTest"}}}
          },
          "403": {"description": "Not an admin"}
        }
      }
    },
    "/dbmirror/status": {
      "get": {
        "summary": "htcondordb mirror routing status",
        "description": "Whether reads are being served from an htcondordb mirror rather than the schedd, and if not, why. The same data is on /readyz and /metrics, but both of those answer a monitoring system; this is shaped for the admin UI and adds the per-decision counts that turn \"a mirror exists\" into \"a mirror is answering queries\". Counts are cumulative since process start. Requires membership in the web UI admin group.",
        "operationId": "dbMirrorStatus",
        "responses": {
          "200": {"description": "Routing status", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/DBMirrorStatus"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "Admin UI is not configured", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/status": {
      "get": {
        "summary": "Placement feature status",
        "description": "Whether a condor_placementd was found, so a UI can decide whether to offer the placement pages. Unlike the other placement endpoints this one answers even when no daemon is available. Requires membership in the web UI admin group.",
        "operationId": "placementStatus",
        "tags": ["placement"],
        "responses": {
          "200": {"description": "Status", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementStatus"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "Admin UI is not configured", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/users": {
      "get": {
        "summary": "List placement users",
        "description": "Everyone in the placementd map file, plus anyone still holding an unexpired token even if their mapping is gone (those come back with authorized=false). Requires membership in the web UI admin group.",
        "operationId": "listPlacementUsers",
        "tags": ["placement"],
        "parameters": [
          {"name": "username", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Restrict to one foreign identity. An unknown identity yields an empty list, not an error."}
        ],
        "responses": {
          "200": {"description": "Users", "content": {"application/json": {"schema": {"type": "object", "properties": {"users": {"type": "array", "items": {"$ref": "#/components/schemas/PlacementUser"}}}}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/tokens": {
      "get": {
        "summary": "List issued placement tokens",
        "description": "Tokens the placementd has issued. It never deletes rows, so an unfiltered query includes expired tokens; pass valid_only=true for live ones. Requires membership in the web UI admin group.",
        "operationId": "listPlacementTokens",
        "tags": ["placement"],
        "parameters": [
          {"name": "username", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Restrict to tokens issued for one foreign identity."},
          {"name": "token_id", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Restrict to a single jti. Takes precedence over the other filters."},
          {"name": "valid_only", "in": "query", "required": false, "schema": {"type": "boolean"}, "description": "Drop tokens that have already expired."}
        ],
        "responses": {
          "200": {"description": "Tokens", "content": {"application/json": {"schema": {"type": "object", "properties": {"tokens": {"type": "array", "items": {"$ref": "#/components/schemas/PlacementToken"}}}}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/authorizations": {
      "get": {
        "summary": "List grantable authorizations",
        "description": "The authorizations the placementd can put in a token's bounding set, with the label, color and description its map file carries for display. Requires membership in the web UI admin group.",
        "operationId": "listPlacementAuthorizations",
        "tags": ["placement"],
        "parameters": [
          {"name": "username", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Narrow the list to what one user may request. Fails with 403 if that user is not mapped."}
        ],
        "responses": {
          "200": {"description": "Authorizations", "content": {"application/json": {"schema": {"type": "object", "properties": {"authorizations": {"type": "array", "items": {"$ref": "#/components/schemas/PlacementAuthorization"}}}}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator, or the named user is not authorized", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/login": {
      "post": {
        "summary": "Mint a placement token",
        "description": "Ask the placementd for an IDToken for a foreign identity. Beyond returning the token this creates the AP user record -- and the project record, when a project is named -- in the schedd if they do not exist; a login against a DISABLED user or project fails rather than re-enabling it. The response is the only time the token is available. Requires membership in the web UI admin group.",
        "operationId": "placementLogin",
        "tags": ["placement"],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementLoginRequest"}}}},
        "responses": {
          "201": {"description": "Token issued", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementLoginResponse"}}}},
          "400": {"description": "Malformed request or missing username", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "The placementd refused: unknown or expired user, an authorization or project the user is not entitled to, or a requester lacking INSTRUCTOR", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "The placementd could not record the token, or the connection was not encrypted", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached, or its schedd leg failed", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/creds/user": {
      "get": {
        "summary": "Query user credential",
        "description": "Check if a user credential exists for the given type.",
        "operationId": "queryUserCred",
        "parameters": [
          {"name": "cred_type", "in": "query", "required": true, "schema": {"type": "string", "enum": ["Kerberos"]}},
          {"name": "user", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Credential status", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CredentialStatus"}}}},
          "400": {"description": "Bad request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "post": {
        "summary": "Add user credential",
        "description": "Store a user credential (Password or Kerberos).",
        "operationId": "addUserCred",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/UserCredentialRequest"}}}},
        "responses": {
          "201": {"description": "Stored", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CredentialStatus"}}}},
          "400": {"description": "Bad request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "Delete user credential",
        "description": "Delete a user credential.",
        "operationId": "deleteUserCred",
        "parameters": [
          {"name": "cred_type", "in": "query", "required": true, "schema": {"type": "string", "enum": ["Kerberos"]}},
          {"name": "user", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Deleted", "content": {"application/json": {"schema": {"type": "object", "properties": {"deleted": {"type": "boolean"}}}}}},
          "404": {"description": "Not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "400": {"description": "Bad request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/creds/service": {
      "get": {
        "summary": "List service credentials",
        "description": "List stored OAuth service credentials for the authenticated user (or provided user).",
        "operationId": "listServiceCreds",
        "parameters": [
          {"name": "user", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Service credentials", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/ServiceStatus"}}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/creds/service/{service}": {
      "get": {
        "summary": "Query service credential",
        "description": "Check if an OAuth service credential exists for a service/handle.",
        "operationId": "queryServiceCred",
        "parameters": [
          {"name": "service", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "handle", "in": "query", "required": false, "schema": {"type": "string"}},
          {"name": "user", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Credential status", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CredentialStatus"}}}},
          "404": {"description": "Not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "post": {
        "summary": "Add or replace service credential",
        "description": "Store an OAuth service credential for the given service (handle optional).",
        "operationId": "addServiceCred",
        "parameters": [
          {"name": "service", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ServiceCredentialRequest"}}}},
        "responses": {
          "201": {"description": "Stored", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CredentialStatus"}}}},
          "400": {"description": "Bad request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "Delete service credential",
        "description": "Delete an OAuth service credential for the given service/handle.",
        "operationId": "deleteServiceCred",
        "parameters": [
          {"name": "service", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "handle", "in": "query", "required": false, "schema": {"type": "string"}},
          {"name": "user", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Deleted", "content": {"application/json": {"schema": {"type": "object", "properties": {"deleted": {"type": "boolean"}}}}}},
          "404": {"description": "Not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/creds/service/{service}/credential": {
      "get": {
        "summary": "Fetch OAuth credential",
        "description": "Return the stored OAuth credential for the service (optional handle via query).",
        "operationId": "getServiceCredential",
        "parameters": [
          {"name": "service", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "handle", "in": "query", "required": false, "schema": {"type": "string"}},
          {"name": "user", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Credential", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OAuthCredentialResponse"}}}},
          "404": {"description": "Not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/creds/service/{service}/{handle}": {
      "get": {
        "summary": "Query service credential (handle)",
        "description": "Check if an OAuth service credential exists for a specific handle.",
        "operationId": "queryServiceCredHandle",
        "parameters": [
          {"name": "service", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "handle", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "user", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Credential status", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CredentialStatus"}}}},
          "404": {"description": "Not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "post": {
        "summary": "Add or replace service credential (handle)",
        "description": "Store an OAuth service credential for the given service and handle.",
        "operationId": "addServiceCredHandle",
        "parameters": [
          {"name": "service", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "handle", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ServiceCredentialRequest"}}}},
        "responses": {
          "201": {"description": "Stored", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CredentialStatus"}}}},
          "400": {"description": "Bad request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "Delete service credential (handle)",
        "description": "Delete an OAuth service credential for the given service and handle.",
        "operationId": "deleteServiceCredHandle",
        "parameters": [
          {"name": "service", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "handle", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "user", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Deleted", "content": {"application/json": {"schema": {"type": "object", "properties": {"deleted": {"type": "boolean"}}}}}},
          "404": {"description": "Not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/creds/service/{service}/{handle}/credential": {
      "get": {
        "summary": "Fetch OAuth credential (handle)",
        "description": "Return the stored OAuth credential for the service and handle.",
        "operationId": "getServiceCredentialHandle",
        "parameters": [
          {"name": "service", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "handle", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "user", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Credential", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OAuthCredentialResponse"}}}},
          "404": {"description": "Not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "500": {"description": "Internal server error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/jobs": {
      "get": {
        "summary": "List jobs",
        "description": "Query the schedd for jobs matching the constraint. Returns up to 50 jobs by default.",
        "operationId": "listJobs",
        "parameters": [
          {
            "name": "constraint",
            "in": "query",
            "description": "ClassAd constraint expression (default: 'true' for all jobs)",
            "required": false,
            "schema": {
              "type": "string",
              "default": "true"
            }
          },
          {
            "name": "projection",
            "in": "query",
            "description": "Comma-separated list of attributes to return. Use '*' for all attributes. Default returns: ClusterId, ProcId, Owner, JobStatus, Cmd, Args",
            "required": false,
            "schema": {
              "type": "string"
            },
            "example": "ClusterId,ProcId,Owner,JobStatus"
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of results to return (default: 50). Use '*' for unlimited results.",
            "required": false,
            "schema": {
              "type": "string"
            },
            "example": "100"
          },
          {
            "name": "page_token",
            "in": "query",
            "description": "Pagination token from a previous response to fetch the next page of results",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "owned_by_me",
            "in": "query",
            "description": "Filter jobs to only those owned by the authenticated user. Default: true for security. Set to false to see all jobs (requires appropriate permissions).",
            "required": false,
            "schema": {
              "type": "boolean",
              "default": true
            }
          }
        ],
        "responses": {
          "200": {
            "description": "List of jobs",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/JobListResponse"
                }
              }
            }
          },
          "401": {
            "description": "Authentication failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Internal server error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "post": {
        "summary": "Submit a job",
        "description": "Submit a new job to the schedd using SubmitRemote. Jobs are submitted with input file spooling enabled and start in HELD status until input files are uploaded via PUT /jobs/{jobId}/input. After uploading input files, poll GET /jobs/{jobId} to check job status (JobStatus: 1=Idle, 2=Running, 3=Removed, 4=Completed, 5=Held).",
        "operationId": "submitJob",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/JobSubmitRequest"
              },
              "examples": {
                "hello_world": {
                  "summary": "Simple Hello World job",
                  "description": "A minimal job that prints Hello World to stdout",
                  "value": {
                    "submit_file": "executable = /bin/echo\narguments = Hello World\noutput = hello.out\nerror = hello.err\nlog = hello.log\nqueue"
                  }
                },
                "sleep_job": {
                  "summary": "Sleep job for testing",
                  "description": "A job that sleeps for 30 seconds - useful for testing job management",
                  "value": {
                    "submit_file": "executable = /bin/sleep\narguments = 30\noutput = sleep.out\nerror = sleep.err\nlog = sleep.log\nqueue"
                  }
                },
                "custom_script": {
                  "summary": "Custom script job",
                  "description": "Job with a custom executable script - upload script via PUT /jobs/{jobId}/input",
                  "value": {
                    "submit_file": "executable = my_script.sh\narguments = arg1 arg2\ntransfer_input_files = data.txt\noutput = output.txt\nerror = errors.txt\nlog = job.log\nqueue"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Job submitted successfully",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/JobSubmitResponse"
                }
              }
            }
          },
          "400": {
            "description": "Invalid request",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Authentication failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Job submission failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/{jobId}": {
      "get": {
        "summary": "Get job details",
        "description": "Retrieve the ClassAd for a specific job",
        "operationId": "getJob",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Job ClassAd",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "description": "Job ClassAd as a JSON object"
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Authentication failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Job not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Query failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "delete": {
        "summary": "Remove a job",
        "description": "Remove a job from the schedd (NOT YET IMPLEMENTED)",
        "operationId": "deleteJob",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "501": {
            "description": "Not implemented",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      },
      "patch": {
        "summary": "Edit a job",
        "description": "Edit job attributes (NOT YET IMPLEMENTED)",
        "operationId": "editJob",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "description": "Job attributes to update"
              }
            }
          }
        },
        "responses": {
          "501": {
            "description": "Not implemented",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/{jobId}/input": {
      "put": {
        "summary": "Upload job input files",
        "description": "Upload a tarfile containing the job's input sandbox. This triggers input file spooling and releases the job from HELD status.",
        "operationId": "uploadJobInput",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/x-tar": {
              "schema": {
                "type": "string",
                "format": "binary"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Input files uploaded successfully",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "job_id": {
                      "type": "string"
                    }
                  }
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Authentication failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Job not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Failed to spool job files",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/{jobId}/input/multipart": {
      "post": {
        "summary": "Upload job input files via multipart form-data",
        "description": "Upload input files using multipart/form-data. Files are converted to a tarball server-side and spooled to the job. Use 'executable' field name for executable files (0755 permissions), all other files get 0644 permissions. Streaming implementation ensures no memory buffering.",
        "operationId": "uploadJobInputMultipart",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "multipart/form-data": {
              "schema": {
                "type": "object",
                "properties": {
                  "executable": {
                    "type": "string",
                    "format": "binary",
                    "description": "Executable file (will have 0755 permissions)"
                  },
                  "file": {
                    "type": "string",
                    "format": "binary",
                    "description": "Input file (will have 0644 permissions)"
                  }
                },
                "description": "Multiple files can be uploaded. Use 'executable' as field name for executable files, any other field name for regular files."
              },
              "encoding": {
                "executable": {
                  "contentType": "application/octet-stream"
                },
                "file": {
                  "contentType": "application/octet-stream"
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Input files uploaded successfully",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "job_id": {
                      "type": "string"
                    }
                  }
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID or multipart form",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Authentication failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Job not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Failed to spool job files",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/{jobId}/output": {
      "get": {
        "summary": "Download job output files",
        "description": "Download the job's output sandbox as a tarfile",
        "operationId": "downloadJobOutput",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Job output tarfile",
            "content": {
              "application/x-tar": {
                "schema": {
                  "type": "string",
                  "format": "binary"
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Authentication failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/{jobId}/stdout": {
      "get": {
        "summary": "Retrieve job stdout",
        "description": "Retrieve the standard output (stdout) file content for a specific job",
        "operationId": "getJobStdout",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Job stdout content",
            "content": {
              "text/plain": {
                "schema": {
                  "type": "string",
                  "description": "The stdout file content as plain text"
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Job not found or stdout file not available",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Failed to retrieve stdout",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/{jobId}/stderr": {
      "get": {
        "summary": "Retrieve job stderr",
        "description": "Retrieve the standard error (stderr) file content for a specific job",
        "operationId": "getJobStderr",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Job stderr content",
            "content": {
              "text/plain": {
                "schema": {
                  "type": "string",
                  "description": "The stderr file content as plain text"
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Job not found or stderr file not available",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Failed to retrieve stderr",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/{jobId}/ssh": {
      "get": {
        "summary": "Open an interactive SSH session inside a running job",
        "description": "Equivalent to condor_ssh_to_job, but exposed as a WebSocket so the resulting terminal can be driven from a browser. The HTTP request must be a WebSocket upgrade (Upgrade: websocket). Authentication happens before the upgrade — a 401 response means re-authenticate.\n\nWebSocket framing:\n  * Binary frames carry raw stdio bytes in either direction (client→server is keystrokes, server→client is terminal output with stdout+stderr merged).\n  * Text frames carry small JSON control messages: {\"type\":\"resize\",\"cols\":N,\"rows\":M}, {\"type\":\"signal\",\"name\":\"INT\"}, {\"type\":\"close\"}.\n  * On exit the server emits a final {\"type\":\"exit\",\"code\":N,\"reason\":\"...\"} text frame and closes with a normal-closure frame.",
        "operationId": "openJobSSH",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {"type": "string"}
          },
          {
            "name": "cols",
            "in": "query",
            "required": false,
            "description": "Initial terminal width in columns. Default 80. The client should send a resize control frame as soon as the WebSocket is open.",
            "schema": {"type": "integer", "default": 80, "minimum": 1, "maximum": 1000}
          },
          {
            "name": "rows",
            "in": "query",
            "required": false,
            "description": "Initial terminal height in rows. Default 24.",
            "schema": {"type": "integer", "default": 24, "minimum": 1, "maximum": 1000}
          }
        ],
        "responses": {
          "101": {
            "description": "Switching protocols — the connection has been upgraded to a WebSocket carrying the SSH session."
          },
          "400": {
            "description": "Invalid job ID",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "401": {
            "description": "Authentication required",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "502": {
            "description": "The schedd or starter refused the connection, or the SSH handshake failed. The error message describes which step failed.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "503": {
            "description": "Schedd is not configured on this server.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          }
        }
      }
    },
    "/jobs/{jobId}/hold": {
      "post": {
        "summary": "Hold a job",
        "description": "Hold a specific job by its ID",
        "operationId": "holdJob",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "requestBody": {
          "required": false,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "reason": {
                    "type": "string",
                    "description": "Optional reason for holding the job"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Job held successfully",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "job_id": {
                      "type": "string"
                    },
                    "results": {
                      "type": "object",
                      "properties": {
                        "total": {"type": "integer"},
                        "success": {"type": "integer"}
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID or job cannot be held",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Authentication failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Job not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/{jobId}/release": {
      "post": {
        "summary": "Release a held job",
        "description": "Release a specific held job by its ID",
        "operationId": "releaseJob",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          }
        ],
        "requestBody": {
          "required": false,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "reason": {
                    "type": "string",
                    "description": "Optional reason for releasing the job"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Job released successfully",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "job_id": {
                      "type": "string"
                    },
                    "results": {
                      "type": "object",
                      "properties": {
                        "total": {"type": "integer"},
                        "success": {"type": "integer"}
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID or job cannot be released",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Authentication failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Job not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/{jobId}/files/{filename}": {
      "get": {
        "summary": "Download a specific file from job output sandbox",
        "description": "Download a specific file from the job's output sandbox by filename. Uses http.DetectContentType to set the appropriate Content-Type header based on file content.",
        "operationId": "downloadJobFile",
        "parameters": [
          {
            "name": "jobId",
            "in": "path",
            "required": true,
            "description": "Job ID in cluster.proc format (e.g., 23.4)",
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "filename",
            "in": "path",
            "required": true,
            "description": "Name of the file to download from the job sandbox (e.g., 'output.txt', 'result.json'). Path traversal characters are not allowed.",
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "File content with auto-detected Content-Type",
            "content": {
              "*/*": {
                "schema": {
                  "type": "string",
                  "format": "binary"
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID or filename",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Authentication failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "Job or file not found in sandbox",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "405": {
            "description": "Method not allowed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Failed to download sandbox or read file",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/hold": {
      "post": {
        "summary": "Hold jobs by constraint",
        "description": "Hold multiple jobs matching a ClassAd constraint",
        "operationId": "bulkHoldJobs",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["constraint"],
                "properties": {
                  "constraint": {
                    "type": "string",
                    "description": "ClassAd constraint expression"
                  },
                  "reason": {
                    "type": "string",
                    "description": "Optional reason for holding the jobs"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Bulk hold operation completed",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "constraint": {
                      "type": "string"
                    },
                    "results": {
                      "type": "object",
                      "properties": {
                        "total": {"type": "integer"},
                        "success": {"type": "integer"},
                        "not_found": {"type": "integer"},
                        "permission_denied": {"type": "integer"},
                        "bad_status": {"type": "integer"},
                        "already_done": {"type": "integer"},
                        "error": {"type": "integer"}
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            "description": "Invalid request",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "No jobs matched the constraint",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/release": {
      "post": {
        "summary": "Release jobs by constraint",
        "description": "Release multiple held jobs matching a ClassAd constraint",
        "operationId": "bulkReleaseJobs",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["constraint"],
                "properties": {
                  "constraint": {
                    "type": "string",
                    "description": "ClassAd constraint expression"
                  },
                  "reason": {
                    "type": "string",
                    "description": "Optional reason for releasing the jobs"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Bulk release operation completed",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "constraint": {
                      "type": "string"
                    },
                    "results": {
                      "type": "object",
                      "properties": {
                        "total": {"type": "integer"},
                        "success": {"type": "integer"},
                        "not_found": {"type": "integer"},
                        "permission_denied": {"type": "integer"},
                        "bad_status": {"type": "integer"},
                        "already_done": {"type": "integer"},
                        "error": {"type": "integer"}
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            "description": "Invalid request",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "404": {
            "description": "No jobs matched the constraint",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/archive": {
      "get": {
        "summary": "Query job archive",
        "description": "Query archived (completed) job records. Served from the schedd's history file, or from a synchronized htcondordb mirror when one is current and the schedd has identified the caller \u2014 the response's source field names which answered.",
        "operationId": "queryJobArchive",
        "parameters": [
          {
            "name": "constraint",
            "in": "query",
            "description": "ClassAd constraint expression (default: 'true' for all archived jobs)",
            "required": false,
            "schema": {
              "type": "string",
              "default": "true"
            }
          },
          {
            "name": "projection",
            "in": "query",
            "description": "Comma-separated list of attributes to return. Default: ClusterId,ProcId,Owner,JobStatus,EnteredCurrentStatus,CompletionDate,RemoveReason",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of archived records to return (use * for unlimited)",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "owned_by_me",
            "in": "query",
            "description": "Restrict the query to the authenticated user's own records. Default: false for API callers; always applied to a browser session that is not a Web UI admin. It does not affect whether an htcondordb mirror may answer \u2014 that turns on the schedd having identified the caller, and a mirror read is confined exactly as the request was.",
            "required": false,
            "schema": {
              "type": "boolean",
              "default": false
            }
          },
          {
            "name": "scan_limit",
            "in": "query",
            "description": "Maximum number of archived records to scan before stopping",
            "required": false,
            "schema": {
              "type": "integer"
            }
          },
          {
            "name": "backwards",
            "in": "query",
            "description": "Scan history backwards from most recent (default: true)",
            "required": false,
            "schema": {
              "type": "boolean",
              "default": true
            }
          },
          {
            "name": "stream_results",
            "in": "query",
            "description": "Stream results line-by-line in JSON Lines format (default: false)",
            "required": false,
            "schema": {
              "type": "boolean",
              "default": false
            }
          },
          {
            "name": "since",
            "in": "query",
            "description": "Only return records after this timestamp (ISO8601 format)",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Job history records (JSON array or JSON Lines stream)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HistoryListResponse"
                }
              }
            }
          },
          "400": {
            "description": "Invalid request",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "Rate limit exceeded",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Internal server error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/epochs": {
      "get": {
        "summary": "Query job epoch history",
        "description": "Query the HTCondor schedd for job epoch records. Each job epoch represents a restart or execution attempt.",
        "operationId": "queryJobEpochs",
        "parameters": [
          {
            "name": "constraint",
            "in": "query",
            "description": "ClassAd constraint expression (default: 'true' for all epochs)",
            "required": false,
            "schema": {
              "type": "string",
              "default": "true"
            }
          },
          {
            "name": "projection",
            "in": "query",
            "description": "Comma-separated list of attributes to return. Default: ClusterId,ProcId,EpochNumber,Owner,JobStartDate,JobCurrentStartDate,RemoteHost",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of epoch records to return (use * for unlimited)",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "scan_limit",
            "in": "query",
            "description": "Maximum number of epoch records to scan before stopping",
            "required": false,
            "schema": {
              "type": "integer"
            }
          },
          {
            "name": "backwards",
            "in": "query",
            "description": "Scan history backwards from most recent (default: true)",
            "required": false,
            "schema": {
              "type": "boolean",
              "default": true
            }
          },
          {
            "name": "stream_results",
            "in": "query",
            "description": "Stream results line-by-line in JSON Lines format (default: false)",
            "required": false,
            "schema": {
              "type": "boolean",
              "default": false
            }
          },
          {
            "name": "since",
            "in": "query",
            "description": "Only return records after this timestamp (ISO8601 format)",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Job epoch records (JSON array or JSON Lines stream)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HistoryListResponse"
                }
              }
            }
          },
          "400": {
            "description": "Invalid request",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "Rate limit exceeded",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Internal server error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jobs/transfers": {
      "get": {
        "summary": "Query transfer history",
        "description": "Query the HTCondor schedd for file transfer history records.",
        "operationId": "queryTransferHistory",
        "parameters": [
          {
            "name": "constraint",
            "in": "query",
            "description": "ClassAd constraint expression (default: 'true' for all transfers)",
            "required": false,
            "schema": {
              "type": "string",
              "default": "true"
            }
          },
          {
            "name": "projection",
            "in": "query",
            "description": "Comma-separated list of attributes to return. Default: ClusterId,ProcId,TransferType,TransferStartTime,TransferEndTime,TransferSuccess,TransferFileBytes",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of transfer records to return (use * for unlimited)",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "scan_limit",
            "in": "query",
            "description": "Maximum number of transfer records to scan before stopping",
            "required": false,
            "schema": {
              "type": "integer"
            }
          },
          {
            "name": "backwards",
            "in": "query",
            "description": "Scan history backwards from most recent (default: true)",
            "required": false,
            "schema": {
              "type": "boolean",
              "default": true
            }
          },
          {
            "name": "stream_results",
            "in": "query",
            "description": "Stream results line-by-line in JSON Lines format (default: false)",
            "required": false,
            "schema": {
              "type": "boolean",
              "default": false
            }
          },
          {
            "name": "since",
            "in": "query",
            "description": "Only return records after this timestamp (ISO8601 format)",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "transfer_types",
            "in": "query",
            "description": "Comma-separated list of transfer types to include (INPUT_FILES, OUTPUT_FILES, CHECKPOINT_FILES)",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Transfer history records (JSON array or JSON Lines stream)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HistoryListResponse"
                }
              }
            }
          },
          "400": {
            "description": "Invalid request",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "429": {
            "description": "Rate limit exceeded",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Internal server error",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/whoami": {
      "get": {
        "summary": "Get current authenticated user",
        "description": "Returns the currently-authenticated user based on the authentication with the schedd",
        "operationId": "whoami",
        "responses": {
          "200": {
            "description": "User information",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/WhoAmIResponse"
                }
              }
            }
          }
        }
      }
    },
    "/version": {
      "get": {
        "summary": "Get server build information",
        "description": "Returns the version and git commit SHA embedded in the running binary at build time, plus when the server started and how long it has been up. Requires authentication.",
        "operationId": "getVersion",
        "responses": {
          "200": {
            "description": "Build information",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/VersionResponse"
                },
                "example": {
                  "version": "v0.1.0-3-g7240eb5",
                  "commit": "7240eb5",
                  "start_time": "2026-01-02T15:04:05Z",
                  "uptime_seconds": 93784
                }
              }
            }
          },
          "401": {
            "description": "Authentication required",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/jupyter/instances": {
      "post": {
        "summary": "Launch a JupyterLab instance in the pool",
        "description": "Submits a Docker-universe HTCondor job that runs JupyterLab inside a per-job Unix domain socket and connects back to this server via an outbound websocket reverse tunnel. Returns immediately with the instance id and cluster id; clients should subscribe to /jupyter/instances/{id}/events to learn when the tunnel is up, then iframe /jupyter/instances/{id}/proxy/.",
        "operationId": "createJupyterInstance",
        "requestBody": {
          "required": false,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "image":     {"type": "string", "description": "Docker image. Default quay.io/jupyter/scipy-notebook:latest"},
                  "cpus":      {"type": "integer", "description": "CPU cores requested. Default 2", "minimum": 1, "maximum": 64},
                  "memory_mb": {"type": "integer", "description": "Memory in MiB. Default 4096", "minimum": 256},
                  "disk_mb":   {"type": "integer", "description": "Scratch disk in MiB. Default 4096", "minimum": 256}
                }
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Job submitted; tunnel is not yet connected.",
            "content": {"application/json": {"schema": {
              "type": "object",
              "required": ["instance_id", "cluster_id", "proxy_path"],
              "properties": {
                "instance_id": {"type": "string", "description": "32-char hex id; use this for /events and /proxy"},
                "cluster_id":  {"type": "string"},
                "proxy_path":  {"type": "string", "description": "Path to iframe once the tunnel reports ready"}
              }
            }}}
          },
          "400": {"description": "Invalid request body", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "401": {"description": "Authentication required", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "Schedd refused submit", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "JupyterLab feature is not configured (no helper binary)", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/jupyter/instances/{id}/events": {
      "get": {
        "summary": "Subscribe to JupyterLab instance lifecycle events (SSE)",
        "description": "text/event-stream of JSON-encoded events. Event names: 'created', 'tunnel-connected', 'closed'. The browser should mount the iframe on receiving 'tunnel-connected'.",
        "operationId": "streamJupyterEvents",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {
            "description": "Event stream open. Each event is a JSON object {kind, at, meta?}.",
            "content": {"text/event-stream": {"schema": {"type": "string"}}}
          },
          "401": {"description": "Authentication required", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such instance (or caller is not its owner)", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/jupyter/instances/{id}/proxy/{rest}": {
      "get": {
        "summary": "Reverse-proxy into a running JupyterLab instance",
        "description": "Owner-only HTTP reverse proxy through the established yamux tunnel. WebSocket upgrades pass through transparently for kernel comms. Path beyond /proxy/ is rewritten to the upstream Jupyter base URL.",
        "operationId": "proxyJupyter",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "rest", "in": "path", "required": true, "schema": {"type": "string"}, "description": "Path inside the Jupyter app"}
        ],
        "responses": {
          "200": {"description": "Proxied response from JupyterLab"},
          "401": {"description": "Authentication required", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such instance (or caller is not its owner)", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "Tunnel not connected (helper has not phoned home yet)", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/collector/ads": {
      "get": {
        "summary": "Query collector for all ads",
        "description": "Query the HTCondor collector for daemon advertisements. Returns up to 50 ads by default.",
        "operationId": "listCollectorAds",
        "parameters": [
          {
            "name": "constraint",
            "in": "query",
            "description": "ClassAd constraint expression (default: 'true' for all ads)",
            "required": false,
            "schema": {
              "type": "string",
              "default": "true"
            }
          },
          {
            "name": "projection",
            "in": "query",
            "description": "Comma-separated list of attributes to return. Use '*' for all attributes. Default returns: ClusterId, ProcId, Owner, JobStatus, Cmd, Args",
            "required": false,
            "schema": {
              "type": "string"
            },
            "example": "ClusterId,ProcId,Owner,JobStatus"
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of results to return (default: 50). Use '*' for unlimited results.",
            "required": false,
            "schema": {
              "type": "string"
            },
            "example": "100"
          },
          {
            "name": "page_token",
            "in": "query",
            "description": "Pagination token from a previous response to fetch the next page of results",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "List of collector ads",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ads": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "description": "ClassAd as a JSON object"
                      }
                    },
                    "total_returned": {
                      "type": "integer",
                      "description": "Number of ads returned in this response"
                    },
                    "has_more": {
                      "type": "boolean",
                      "description": "Whether there are more results available"
                    },
                    "next_page_token": {
                      "type": "string",
                      "description": "Token to use for fetching the next page (only present if has_more is true)"
                    },
                    "error": {
                      "type": "string",
                      "description": "Error message if an error occurred during streaming. When present, the ads array contains all successfully streamed ads before the error."
                    }
                  }
                }
              }
            }
          },
          "500": {
            "description": "Query failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "501": {
            "description": "Collector not configured",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/collector/ads/{adType}": {
      "get": {
        "summary": "Query collector for ads of specific type",
        "description": "Query the HTCondor collector for daemon advertisements of a specific type. Returns up to 50 ads by default.",
        "operationId": "listCollectorAdsByType",
        "parameters": [
          {
            "name": "adType",
            "in": "path",
            "required": true,
            "description": "Ad type (e.g., 'startd', 'schedd', 'master', 'all')",
            "schema": {
              "type": "string",
              "enum": ["all", "startd", "schedd", "master", "submitter", "negotiator", "collector", "machines", "schedds", "masters", "submitters", "negotiators", "collectors"]
            }
          },
          {
            "name": "constraint",
            "in": "query",
            "description": "ClassAd constraint expression (default: 'true' for all ads of this type)",
            "required": false,
            "schema": {
              "type": "string",
              "default": "true"
            }
          },
          {
            "name": "projection",
            "in": "query",
            "description": "Comma-separated list of attributes to return. Use '*' for all attributes. Default returns: Name, Machine, MyType, State, Activity, MyAddress",
            "required": false,
            "schema": {
              "type": "string"
            },
            "example": "Name,Machine,State"
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of results to return (default: 50). Use '*' for unlimited results.",
            "required": false,
            "schema": {
              "type": "string"
            },
            "example": "100"
          },
          {
            "name": "page_token",
            "in": "query",
            "description": "Pagination token from a previous response to fetch the next page of results",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "List of collector ads of specified type",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "ads": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "description": "ClassAd as a JSON object"
                      }
                    },
                    "total_returned": {
                      "type": "integer",
                      "description": "Number of ads returned in this response"
                    },
                    "has_more": {
                      "type": "boolean",
                      "description": "Whether there are more results available"
                    },
                    "next_page_token": {
                      "type": "string",
                      "description": "Token to use for fetching the next page (only present if has_more is true)"
                    },
                    "error": {
                      "type": "string",
                      "description": "Error message if an error occurred during streaming. When present, the ads array contains all successfully streamed ads before the error."
                    }
                  }
                }
              }
            }
          },
          "500": {
            "description": "Query failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "501": {
            "description": "Collector not configured",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/collector/ads/{adType}/{name}": {
      "get": {
        "summary": "Get specific collector ad by name",
        "description": "Retrieve a specific daemon advertisement from the collector by ad type and name",
        "operationId": "getCollectorAdByName",
        "parameters": [
          {
            "name": "adType",
            "in": "path",
            "required": true,
            "description": "Ad type (e.g., 'startd', 'schedd', 'master')",
            "schema": {
              "type": "string",
              "enum": ["startd", "schedd", "master", "submitter", "negotiator", "collector", "machines", "schedds", "masters", "submitters", "negotiators", "collectors"]
            }
          },
          {
            "name": "name",
            "in": "path",
            "required": true,
            "description": "Name of the daemon",
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "projection",
            "in": "query",
            "description": "Comma-separated list of attributes to return (default: all attributes)",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Daemon ClassAd",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "description": "ClassAd as a JSON object"
                }
              }
            }
          },
          "404": {
            "description": "Ad not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "Query failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "501": {
            "description": "Collector not configured",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    },
    "/collector/advertise": {
      "post": {
        "summary": "Advertise to collector",
        "description": "Send one or more ClassAd advertisements to the HTCondor collector. Supports single ad (JSON), text/plain (old ClassAd format), or multipart/form-data (multiple ads). The UPDATE command is determined from the ad's MyType attribute if not explicitly specified. Multiple ads use the multi-sending protocol with a 1MB buffer limit.",
        "operationId": "advertiseToCollector",
        "requestBody": {
          "description": "ClassAd(s) to advertise",
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/AdvertiseRequest"
              },
              "example": {
                "ad": {
                  "MyType": "Machine",
                  "Name": "slot1@hostname.example.com",
                  "State": "Unclaimed",
                  "Activity": "Idle",
                  "Memory": 8192,
                  "Cpus": 4
                },
                "with_ack": false
              }
            },
            "text/plain": {
              "schema": {
                "type": "string",
                "description": "ClassAd in old format"
              },
              "example": "MyType = \"Machine\"\nName = \"slot1@hostname\"\nState = \"Unclaimed\"\n"
            },
            "multipart/form-data": {
              "schema": {
                "type": "object",
                "properties": {
                  "ad1": {
                    "type": "string",
                    "format": "binary",
                    "description": "First ClassAd file"
                  },
                  "ad2": {
                    "type": "string",
                    "format": "binary",
                    "description": "Second ClassAd file (optional)"
                  },
                  "with_ack": {
                    "type": "string",
                    "description": "Request acknowledgment (true/false)",
                    "default": "false"
                  },
                  "command": {
                    "type": "string",
                    "description": "Optional UPDATE command override"
                  }
                }
              }
            }
          }
        },
        "parameters": [
          {
            "name": "with_ack",
            "in": "query",
            "description": "Request acknowledgment from collector (for text/plain)",
            "required": false,
            "schema": {
              "type": "boolean",
              "default": false
            }
          },
          {
            "name": "command",
            "in": "query",
            "description": "UPDATE command to use (for text/plain)",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "All advertisements succeeded",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/AdvertiseResponse"
                },
                "example": {
                  "success": true,
                  "message": "Advertisement successful",
                  "succeeded": 1,
                  "failed": 0
                }
              }
            }
          },
          "207": {
            "description": "Partial success (multi-status)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/AdvertiseResponse"
                },
                "example": {
                  "success": false,
                  "message": "2 of 5 ads failed to advertise",
                  "succeeded": 3,
                  "failed": 2,
                  "errors": ["ad 1: connection timeout", "ad 3: invalid MyType"]
                }
              }
            }
          },
          "400": {
            "description": "Bad request (invalid ad format, invalid command, etc.)",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "415": {
            "description": "Unsupported media type",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          },
          "500": {
            "description": "All advertisements failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/AdvertiseResponse"
                },
                "example": {
                  "success": false,
                  "message": "Failed to advertise",
                  "succeeded": 0,
                  "failed": 1,
                  "errors": ["failed to connect to collector"]
                }
              }
            }
          },
          "501": {
            "description": "Collector not configured",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Error"
                }
              }
            }
          }
        }
      }
    }
  }
}`

// handleOpenAPISchema serves the OpenAPI schema
func (s *Handler) handleOpenAPISchema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Parse and re-encode to ensure valid JSON and pretty printing
	var schema interface{}
	if err := json.Unmarshal([]byte(openAPISchema), &schema); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to parse OpenAPI schema")
		return
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(schema); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode OpenAPI schema", "error", err)
	}
}

// handleSwaggerUI serves the Swagger UI
func (s *Handler) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Override the global CSP for this route. The default policy set
	// in applySecurityHeaders is `default-src 'self'`, which blocks
	// the Swagger UI assets we pull from unpkg.com. Until we bundle
	// swagger-ui-dist into the binary (TODO: ship the assets via
	// go:embed so this route works air-gapped), allow unpkg + the
	// cross-origin font/style/script the bundle needs.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"style-src 'self' 'unsafe-inline' https://unpkg.com; "+
			"script-src 'self' 'unsafe-inline' https://unpkg.com; "+
			"img-src 'self' data: https://unpkg.com; "+
			"font-src 'self' data: https://unpkg.com; "+
			// connect-src must include unpkg so browser devtools can
			// fetch the .js.map sourcemaps the swagger-ui bundle
			// references. Not fetching them is harmless (Swagger UI
			// still runs) but produces noisy console errors.
			"connect-src 'self' https://unpkg.com; "+
			"frame-ancestors 'self'; "+
			"base-uri 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	html := `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta
      name="description"
      content="SwaggerUI"
    />
    <title>HTCondor API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  </head>
  <body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" crossorigin></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js" crossorigin></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        oauth2RedirectUrl: window.location.origin + '/docs/oauth2-redirect',
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "StandaloneLayout",
      });

      window.ui.initOAuth({
        clientId: "swagger-client",
        appName: "HTCondor API",
        usePkceWithAuthorizationCodeGrant: true
      });
    };
  </script>
  </body>
</html>`

	_, _ = w.Write([]byte(html))
}

// handleSwaggerOAuth2Redirect serves the OAuth2 redirect page for Swagger UI
func (s *Handler) handleSwaggerOAuth2Redirect(w http.ResponseWriter, _ *http.Request) {
	html := `<!doctype html>
<html lang="en-US">
<head>
    <title>Swagger UI: OAuth2 Redirect</title>
</head>
<body>
<script>
    'use strict';
    function run () {
        var oauth2 = window.opener.swaggerUIRedirectOauth2;
        var sentState = oauth2.state;
        var redirectUrl = oauth2.redirectUrl;
        var isValid, qp, arr;

        if (/code|token|error/.test(window.location.hash)) {
            qp = window.location.hash.substring(1).replace('?', '&');
        } else {
            qp = location.search.substring(1);
        }

        arr = qp.split("&");
        arr.forEach(function (v,i,_arr) { _arr[i] = '"' + v.replace('=', '":"') + '"';});
        qp = qp ? JSON.parse('{' + arr.join() + '}',
                function (key, value) {
                    return key === "" ? value : decodeURIComponent(value)
                }
        ) : {};

        isValid = qp.state === sentState;

        if ((
          oauth2.auth.schema.get("flow") === "accessCode" ||
          oauth2.auth.schema.get("flow") === "authorizationCode" ||
          oauth2.auth.schema.get("flow") === "authorization_code"
        ) && !oauth2.auth.code) {
            if (!isValid) {
                oauth2.errCb({
                    authId: oauth2.auth.name,
                    source: "auth",
                    level: "warning",
                    message: "Authorization may be unsafe, passed state was changed in server. The passed state wasn't returned from auth server."
                });
            }

            if (qp.code) {
                delete oauth2.state;
                oauth2.auth.code = qp.code;
                oauth2.callback({auth: oauth2.auth, redirectUrl: redirectUrl});
            } else {
                let oauthErrorMsg;
                if (qp.error) {
                    oauthErrorMsg = "["+qp.error+"]: " +
                        (qp.error_description ? qp.error_description+ ". " : "no accessCode received from the server. ") +
                        (qp.error_uri ? "More info: "+qp.error_uri : "");
                }

                oauth2.errCb({
                    authId: oauth2.auth.name,
                    source: "auth",
                    level: "error",
                    message: oauthErrorMsg || "[Authorization failed]: no accessCode received from the server."
                });
            }
        } else {
            oauth2.callback({auth: oauth2.auth, token: qp, isValid: isValid, redirectUrl: redirectUrl});
        }
        window.close();
    }

    if (document.readyState !== 'loading') {
        run();
    } else {
        document.addEventListener('DOMContentLoaded', function () {
            run();
        });
    }
</script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}
