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
      "name": "metrics",
      "description": "Time-series metrics from the htcondordb archive. Today the one table is job_metrics -- per-job resource-usage samples (memory/CPU/disk/GPU) captured as the schedd commits usage updates, one series per run attempt. Reads are owner-scoped and time-bucketed. When the sampler is not enabled the endpoint answers 200 with enabled=false so a UI can hide the feature."
    },
    {
      "name": "placement",
      "description": "condor_placementd: issue and audit access-point credentials for identities that authenticate elsewhere. The daemon registers its commands at ADMINISTRATOR and this server calls it as the access point's own identity, so the admin endpoints (/placement/status, users, tokens, authorizations, login, records and admin) require membership in the web UI admin group. The /placement/me endpoints serve any signed-in browser session, including one with no local account; they always act for the session's own placement identity and never take one from the request. GET /placement/me and POST /placement/me/token also accept a bearer access token holding the placement scope, which this server's own RFC 8628 device grant issues to the client placement_client; such a token reaches nothing else. The legacy device flow older placement-client versions use is served outside /api/v1, at /auth/device_authorization, /auth/code and /auth/cancel_device, with placement-webapp's exact responses. Absent a placementd, every endpoint but /placement/status returns 503. The /placement/admin endpoints manage the placementd's directory (identities, accounts, projects, authorizations) and need a placementd advertising PlacementdApiVersion >= 2; against an older one they return 501, and /placement/status reports api_version so a UI can hide them. Every directory write is recorded in the placementd's history against the signed-in admin, never against a name taken from the request, with an optional change_comment."
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
      "UtilDistribution": {
        "type": "object",
        "nullable": true,
        "description": "Exact nearest-rank percentiles and a histogram of 12-30 contiguous bins (lo inclusive).",
        "properties": {
          "n": {"type": "integer"},
          "min": {"type": "number"}, "p10": {"type": "number"}, "p25": {"type": "number"}, "p50": {"type": "number"},
          "p75": {"type": "number"}, "p90": {"type": "number"}, "p95": {"type": "number"}, "p99": {"type": "number"}, "max": {"type": "number"},
          "histogram": {"type": "array", "items": {"type": "object", "properties": {"lo": {"type": "number"}, "hi": {"type": "number"}, "count": {"type": "integer"}}}}
        }
      },
      "UtilRequest": {
        "type": "object",
        "nullable": true,
        "properties": {
          "typical": {"type": "number", "description": "The most common requested value."},
          "min": {"type": "number"}, "max": {"type": "number"},
          "distinct": {"type": "integer"},
          "adaptive": {"type": "boolean", "description": "Most jobs wrote the request as a formula over their own usage; typical/min/max are then its starting value."},
          "expression": {"type": "string", "description": "The most common formula, when adaptive (memory only)."}
        }
      },
      "UtilResourceSummary": {
        "type": "object",
        "description": "Time-weighted: request x wall hours reserved, usage x wall hours used. Units are core-hours, MiB-hours, KiB-hours or GPU-hours.",
        "properties": {
          "resource": {"type": "string", "enum": ["cpu", "memory", "disk", "gpu"]},
          "allocated_hours": {"type": "number"},
          "used_hours": {"type": "number", "nullable": true, "description": "Over jobs whose usage was measured; null when none was."},
          "allocated_hours_measured": {"type": "number", "description": "allocated_hours over only the measured jobs: the denominator for used_hours."},
          "jobs_measured": {"type": "integer"}
        }
      },
      "UtilAdvice": {
        "type": "object",
        "properties": {
          "id": {"type": "string", "enum": ["memory-lower", "memory-retry", "memory-raise", "memory-ok", "cpus-lower", "cpus-raise", "disk-lower", "disk-raise", "gpu-idle", "gpu-unused", "gpus-lower", "gpu-cpu-bound", "gpu-memory-small", "gpu-memory-require", "gpu-memory-raise", "short-jobs", "restarts"]},
          "resource": {"type": "string", "enum": ["cpu", "memory", "disk", "gpu", "runtime"]},
          "severity": {"type": "string", "enum": ["info", "suggest", "warn"]},
          "title": {"type": "string"},
          "detail": {"type": "string"},
          "submit": {"type": "array", "items": {"type": "string"}, "description": "Submit-file lines to paste."},
          "saves": {"type": "object", "nullable": true, "properties": {"unit": {"type": "string", "enum": ["core_hours", "gib_hours", "gpu_hours"]}, "amount": {"type": "number"}}},
          "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
          "applies": {"type": "boolean", "description": "POST /utilization/apply can apply this advice to waiting jobs."},
          "change": {"type": "object", "description": "The edit apply would make, present exactly when applies.", "properties": {
            "attribute": {"type": "string", "enum": ["RequestMemory", "RequestCpus", "RequestDisk", "RequestGPUs"]}, "value": {"type": "number"}}}
        }
      },
      "UtilShape": {
        "type": "object",
        "properties": {"cpus": {"type": "number"}, "memory_mib": {"type": "number"}, "disk_kib": {"type": "number"}, "gpus": {"type": "number"}}
      },
      "UtilThroughput": {
        "type": "object",
        "nullable": true,
        "description": "Up-to estimate of how many more of these jobs could run at once with the suggested requests, from the shapes of the pool's execute machines. Null when no advice changes the request, under 20 finished jobs, or without pool data (multi-AP, or the collector could not be read).",
        "properties": {
          "current": {"$ref": "#/components/schemas/UtilShape"},
          "suggested": {"$ref": "#/components/schemas/UtilShape"},
          "retry_memory_mib": {"type": "number", "nullable": true},
          "fit_current": {"type": "integer", "description": "Copies of the current shape the pool's machines hold at once."},
          "fit_suggested": {"type": "integer"},
          "gain": {"type": "number", "description": "Pool occupancy per unit of work, current over suggested, reruns included."},
          "limited_by": {"type": "string", "enum": ["cpu", "memory", "disk", "gpu"]},
          "wait_p50": {"type": "number", "description": "Median seconds from submission to first start."},
          "slots_limited": {"type": "boolean", "description": "wait_p50 >= 900"},
          "last_batch": {"type": "object", "nullable": true, "properties": {
            "id": {"type": "integer"}, "jobs": {"type": "integer"},
            "elapsed": {"type": "number", "description": "Seconds, first QDate to last CompletionDate."},
            "estimated": {"type": "number", "description": "Seconds: max(longest job wall, elapsed / gain)."}}}
        }
      },
      "UtilWorkflow": {
        "type": "object",
        "description": "Jobs grouped by (owner, batch name without a DAG +N suffix or else executable, executable, access point).",
        "properties": {
          "key": {"type": "string"},
          "name": {"type": "string"},
          "executable": {"type": "string"},
          "owner": {"type": "string", "description": "Set when the scope covers more than one owner."},
          "schedd": {"type": "string", "description": "Multi-AP mode."},
          "is_dag": {"type": "boolean"},
          "jobs": {"type": "integer"}, "succeeded": {"type": "integer"}, "failed": {"type": "integer"}, "removed": {"type": "integer"},
          "wall_hours": {"type": "number"},
          "wall": {"$ref": "#/components/schemas/UtilDistribution"},
          "short_jobs": {"type": "integer"},
          "restarts": {"type": "object", "properties": {"jobs": {"type": "integer"}, "lost_hours": {"type": "number"}}},
          "holds": {"type": "object", "properties": {"memory": {"type": "integer"}, "disk": {"type": "integer"}}},
          "resources": {"type": "array", "items": {"$ref": "#/components/schemas/UtilResourceSummary"}},
          "memory": {"type": "object", "properties": {"request": {"$ref": "#/components/schemas/UtilRequest"}, "peak_mib": {"$ref": "#/components/schemas/UtilDistribution"}}},
          "cpu": {"type": "object", "properties": {"request": {"$ref": "#/components/schemas/UtilRequest"}, "cores_used": {"$ref": "#/components/schemas/UtilDistribution"}, "efficiency": {"$ref": "#/components/schemas/UtilDistribution"}}},
          "disk": {"type": "object", "properties": {"request": {"$ref": "#/components/schemas/UtilRequest"}, "used_kib": {"$ref": "#/components/schemas/UtilDistribution"}}},
          "gpu": {"type": "object", "nullable": true, "description": "Null when no job requested a GPU. Utilization is often unmeasured: only execute points running HTCondor's GPU monitor record it.", "properties": {
            "request": {"$ref": "#/components/schemas/UtilRequest"},
            "jobs": {"type": "integer", "description": "Jobs that requested at least one GPU."},
            "measured": {"type": "integer", "description": "Of those, jobs with a utilization measurement."},
            "utilization": {"$ref": "#/components/schemas/UtilDistribution"},
            "memory_peak_mib": {"$ref": "#/components/schemas/UtilDistribution"},
            "device_memory_mib": {"type": "number", "nullable": true, "description": "Typical memory of the GPUs the jobs ran on, when the pool records MachineAttrGPUs_GlobalMemoryMb0."},
            "cores_used_while_gpu": {"$ref": "#/components/schemas/UtilDistribution"}}},
          "memory_curve": {"type": "array", "description": "Expected reserved MiB-hours at each candidate request_memory; empty under 20 finished jobs.", "items": {"type": "object", "properties": {
            "request_mib": {"type": "number"}, "retry_mib": {"type": "number", "nullable": true}, "reserved_mib_hours": {"type": "number"},
            "retry_fraction": {"type": "number"}, "is_current": {"type": "boolean"}, "is_recommended": {"type": "boolean"}}}},
          "advice": {"type": "array", "items": {"$ref": "#/components/schemas/UtilAdvice"}},
          "batches": {"type": "array", "items": {"type": "object", "properties": {
            "id": {"type": "integer"}, "submitted": {"type": "integer"}, "jobs": {"type": "integer"},
            "memory_request_mib": {"type": "number", "nullable": true}, "memory_p95_mib": {"type": "number", "nullable": true},
            "cpu_request": {"type": "number", "nullable": true}, "cpu_cores_p50": {"type": "number", "nullable": true}, "wall_p50": {"type": "number", "nullable": true},
            "gpu_request": {"type": "number", "nullable": true, "description": "Typical request_gpus of the batch's GPU jobs."},
            "gpu_util_p50": {"type": "number", "nullable": true, "description": "Median fraction of the GPUs each job had kept busy."}}}},
          "samples": {"type": "array", "items": {"type": "object", "properties": {
            "job": {"type": "string", "description": "cluster.proc, as in /utilization/jobs rows."},
            "memory_mib": {"type": "number", "nullable": true}, "wall": {"type": "number"}, "cores": {"type": "number", "nullable": true},
            "disk_kib": {"type": "number", "nullable": true}, "outcome": {"type": "string", "enum": ["ok", "failed", "removed", "memory_exceeded"]}}}},
          "throughput": {"$ref": "#/components/schemas/UtilThroughput"}
        }
      },
      "UtilWorkflowSummary": {
        "type": "object",
        "description": "One row of the workflow list. Fields that are usually empty are omitted: name when it equals executable, is_dag when false, failed/removed when 0, the GPU request and use when no job requested GPUs, an advice brief's saves when none.",
        "properties": {
          "key": {"type": "string"}, "name": {"type": "string"}, "executable": {"type": "string", "description": "The program the jobs run: the script or command an interpreter or wrapper starts, not necessarily basename(Cmd)."},
          "owner": {"type": "string"}, "schedd": {"type": "string"}, "is_dag": {"type": "boolean"},
          "jobs": {"type": "integer"}, "succeeded": {"type": "integer"}, "failed": {"type": "integer"}, "removed": {"type": "integer"},
          "wall_hours": {"type": "number"},
          "holds": {"type": "object", "properties": {"memory": {"type": "integer"}, "disk": {"type": "integer"}}},
          "request": {"type": "object", "properties": {"memory_mib": {"type": "number", "nullable": true}, "cpus": {"type": "number", "nullable": true},
            "disk_kib": {"type": "number", "nullable": true}, "gpus": {"type": "number"},
            "adaptive": {"type": "array", "items": {"type": "string", "enum": ["memory", "cpus", "disk", "gpus"]}}}},
          "used": {"type": "object", "description": "used_hours / allocated_hours_measured per resource.", "properties": {
            "cpu": {"type": "number", "nullable": true}, "memory": {"type": "number", "nullable": true}, "disk": {"type": "number", "nullable": true}, "gpu": {"type": "number", "nullable": true}}},
          "gpu_hours": {"type": "number"}, "gain": {"type": "number"}, "slots_limited": {"type": "boolean"},
          "advice": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "string"}, "severity": {"type": "string"},
            "saves": {"type": "object", "properties": {"unit": {"type": "string"}, "amount": {"type": "number"}}}}}}
        }
      },
      "UtilizationResponse": {
        "type": "object",
        "properties": {
          "since": {"type": "integer", "description": "Inclusive lower bound on EnteredHistoryTime, unix seconds."},
          "until": {"type": "integer"},
          "days": {"type": "integer"},
          "jobs_considered": {"type": "integer"},
          "truncated": {"type": "boolean", "description": "The limit was hit; the analysis covers the most recent jobs."},
          "limit": {"type": "integer", "description": "The limit applied."},
          "max_limit": {"type": "integer", "description": "The server's ceiling (HTTP_API_UTILIZATION_MAX_JOBS)."},
          "owners": {"type": "array", "description": "Owners in the analysed jobs, most wall clock first; only for a scope that sees other users.", "items": {"type": "object", "properties": {
            "owner": {"type": "string"}, "jobs": {"type": "integer"}, "wall_hours": {"type": "number"}}}},
          "overall": {"type": "object", "properties": {
            "jobs": {"type": "integer"}, "wall_hours": {"type": "number"}, "badput_hours": {"type": "number"},
            "resources": {"type": "array", "items": {"$ref": "#/components/schemas/UtilResourceSummary"}},
            "throughput_gain": {"type": "number", "nullable": true, "description": "All workflows: total occupancy at current requests over that at suggested ones; workflows left unchanged count on both sides."}}},
          "workflows": {"type": "array", "description": "Compact rows; one workflow's full detail is /utilization/workflow.", "items": {"$ref": "#/components/schemas/UtilWorkflowSummary"}},
          "suggestions": {"type": "array", "description": "Advice from every workflow, ranked (severity, GPU-hour savings first, larger savings), at most 500.", "items": {"type": "object", "properties": {
            "key": {"type": "string"}, "name": {"type": "string"}, "executable": {"type": "string"}, "owner": {"type": "string"},
            "id": {"type": "string"}, "resource": {"type": "string"}, "severity": {"type": "string"}, "title": {"type": "string"},
            "saves": {"type": "object", "nullable": true, "properties": {"unit": {"type": "string"}, "amount": {"type": "number"}}},
            "confidence": {"type": "string"}}}}
        }
      },
      "App": {
        "type": "object",
        "required": ["id", "type", "job_id", "state"],
        "properties": {
          "id":        {"type": "string", "description": "Opaque id; also carried in the job's JobBatchName"},
          "type":      {"type": "string", "description": "code-server"},
          "job_id":    {"type": "string", "description": "cluster.proc"},
          "owner":     {"type": "string"},
          "state":     {"type": "string", "enum": ["waiting", "starting", "running", "held", "ended"], "description": "A queued app and a dead one are identical through the proxy (both 502), so these distinguish them: 'waiting' has no slot yet, 'starting' is running but not yet listening, 'running' is reachable."},
          "detail":    {"type": "string", "description": "Why, for a state that would otherwise have to be guessed at: what it waits for, or the HoldReason"},
          "url":       {"type": "string", "description": "Where to open it. Present only when there is something to open. The trailing slash matters: the app is served by stripping this prefix and emits relative URLs."},
          "submitted": {"type": "integer", "description": "QDate, so a caller can say how long a wait has been going on"}
        }
      },
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
            "description": "Array of job IDs in cluster.proc format; in multi-AP mode, complete ids (cluster.proc@schedd)"
          },
          "schedd": {
            "type": "string",
            "description": "Multi-AP mode only: the access point the jobs were submitted to"
          },
          "jobs": {
            "type": "array",
            "description": "Multi-AP mode only: each job as schedd, cluster, proc and job_id",
            "items": {
              "type": "object",
              "properties": {
                "schedd": {"type": "string"},
                "cluster": {"type": "integer"},
                "proc": {"type": "integer"},
                "job_id": {"type": "string"}
              }
            }
          },
          "assignment": {
            "type": "object",
            "description": "Multi-AP mode only: the caller's access point assignment the submission followed",
            "properties": {
              "schedd": {"type": "string"},
              "alternates": {"type": "array", "items": {"type": "string"}},
              "source": {"type": "string"},
              "stale": {"type": "boolean"}
            }
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
          },
          "scan_limit_reached": {
            "type": "boolean",
            "description": "Present and true when the schedd stopped at its scan limit before finding as many records as requested: only the records_scanned most recent history records were examined, so older matches are not in the answer, even when it is empty. Raise scan_limit to search further back."
          },
          "records_scanned": {
            "type": "integer",
            "description": "How many history records the schedd examined; present with scan_limit_reached."
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
        "description": "A sign-in identity known to the placementd, merged with its newest live token.",
        "properties": {
          "username": {"type": "string", "description": "Sign-in identity, as it appears in the placementd map file."},
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
          "username": {"type": "string", "description": "Sign-in identity the token was issued for."},
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
          "username": {"type": "string", "description": "Sign-in identity to log in. Must appear in the placementd map file."},
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
          "reason": {"type": "string", "description": "Why the placementd is unavailable, when it is."},
          "api_version": {"type": "integer", "description": "The placementd's PlacementdApiVersion. 2 or more means the /placement/admin directory endpoints work."}
        }
      },
      "PlacementEntityMeta": {
        "type": "object",
        "properties": {
          "id": {"type": "string", "description": "Immutable uuid."},
          "source": {"type": "string", "enum": ["mapfile", "internal"], "description": "Owner of the row. mapfile rows are read-only here until adopted."},
          "version": {"type": "integer", "format": "int64", "description": "Changes on every change to the entity. Opaque: send it back as expected_version."},
          "modification_id": {"type": "integer", "format": "int64", "description": "The entity's latest history entry."},
          "created_at": {"type": "string", "format": "date-time"},
          "updated_at": {"type": "string", "format": "date-time"},
          "modified_by": {"type": "string"}
        }
      },
      "PlacementIdentity": {
        "allOf": [{"$ref": "#/components/schemas/PlacementEntityMeta"}, {"type": "object", "properties": {
          "identity": {"type": "string", "description": "The identity, this type's key."},
          "account_id": {"type": "string"},
          "account": {"type": "string"},
          "expires_at": {"type": "string", "format": "date-time", "description": "Absent means never."},
          "expired": {"type": "boolean"},
          "display_name": {"type": "string"},
          "comment": {"type": "string"},
          "authorizations": {"type": "array", "items": {"type": "string"}},
          "projects": {"type": "array", "items": {"type": "string"}},
          "default_project": {"type": "string"},
          "last_token_expiration": {"type": "string", "format": "date-time"}
        }}]
      },
      "PlacementAccount": {
        "allOf": [{"$ref": "#/components/schemas/PlacementEntityMeta"}, {"type": "object", "properties": {
          "name": {"type": "string"},
          "authorizations": {"type": "array", "items": {"type": "string"}},
          "projects": {"type": "array", "items": {"type": "string"}},
          "default_project": {"type": "string"},
          "identities": {"type": "array", "items": {"type": "string"}}
        }}]
      },
      "PlacementProject": {
        "allOf": [{"$ref": "#/components/schemas/PlacementEntityMeta"}, {"type": "object", "properties": {
          "name": {"type": "string"},
          "description": {"type": "string"},
          "accounts": {"type": "array", "items": {"type": "string"}}
        }}]
      },
      "PlacementAuthorizationRecord": {
        "allOf": [{"$ref": "#/components/schemas/PlacementEntityMeta"}, {"type": "object", "properties": {
          "name": {"type": "string"},
          "label": {"type": "string"},
          "color": {"type": "string"},
          "description": {"type": "string"},
          "requestable": {"type": "boolean"}
        }}]
      },
      "PlacementEntityInput": {
        "type": "object",
        "description": "Writable fields. Identity: identity, account (name or id), expires_at (RFC 3339 or Unix seconds), display_name, comment. Account: name, authorizations, projects, default_project (lists replace the whole set). Project: name, description. Authorization: name, label, color, description, requestable. On PATCH only the fields present change, null clears a field, and expected_version guards against concurrent edits.",
        "additionalProperties": true,
        "properties": {
          "expected_version": {"type": "integer", "format": "int64", "description": "PATCH only."},
          "change_comment": {"type": "string", "description": "Recorded in the history with this change."}
        }
      },
      "PlacementMapfileStatus": {
        "type": "object",
        "properties": {
          "load_time": {"type": "string", "format": "date-time"},
          "load_attempt_time": {"type": "string", "format": "date-time"},
          "ok": {"type": "boolean"},
          "quarantined": {"type": "integer"},
          "conflicts": {"type": "integer"},
          "user_mapfile": {"type": "string"},
          "authorizations_mapfile": {"type": "string"},
          "problems": {"type": "array", "items": {"type": "object", "properties": {
            "kind": {"type": "string"}, "file": {"type": "string"}, "line": {"type": "integer"},
            "key": {"type": "string"}, "message": {"type": "string"}
          }}}
        }
      },
      "PlacementEditResult": {
        "type": "object",
        "properties": {
          "index": {"type": "integer"},
          "id": {"type": "string"},
          "version": {"type": "integer", "format": "int64"},
          "warning": {"type": "string"},
          "error_code": {"type": "integer"},
          "error": {"type": "string"}
        }
      },
      "PlacementEditResponse": {
        "type": "object",
        "properties": {
          "committed": {"type": "boolean"},
          "dry_run": {"type": "boolean"},
          "results": {"type": "array", "items": {"$ref": "#/components/schemas/PlacementEditResult"}}
        }
      },
      "PlacementAdminError": {
        "type": "object",
        "properties": {
          "error": {"type": "string"},
          "message": {"type": "string"},
          "code": {"type": "integer"},
          "placement_code": {"type": "integer", "description": "The placementd's error code (13 not found, 14 version mismatch, 15 owned by the mapfile, 16 invalid argument, 17 still referenced, 18 duplicate, 19 unknown type)."},
          "placement_error": {"type": "string"},
          "owned_by": {"type": "string", "description": "Set to mapfile when the row must be adopted before it can change."},
          "cascade_required": {"type": "boolean", "description": "The delete succeeds with cascade=true."},
          "results": {"type": "array", "items": {"$ref": "#/components/schemas/PlacementEditResult"}}
        }
      },
      "PlacementModification": {
        "type": "object",
        "description": "One history entry: one entity changed by one batch or map file reload.",
        "properties": {
          "id": {"type": "integer", "format": "int64"},
          "changeset_id": {"type": "integer", "format": "int64", "description": "Groups the entries one batch or reload made."},
          "time": {"type": "string", "format": "date-time"},
          "channel": {"type": "string", "enum": ["cedar", "mapfile", "migration"]},
          "actor": {"type": "string", "description": "Who authenticated to the placementd."},
          "on_behalf_of": {"type": "string", "description": "The admin the change was made for."},
          "peer_address": {"type": "string"},
          "comment": {"type": "string"},
          "operation": {"type": "string", "enum": ["create", "update", "delete", "adopt", "reclaim", "handoff"]},
          "entity_type": {"type": "string", "enum": ["identity", "account", "project", "authorization"]},
          "entity_id": {"type": "string"},
          "changes": {"type": "object", "description": "Changed fields by name, each {old, new}; null is absent or cleared, and grants are lists.", "additionalProperties": {"type": "object", "properties": {"old": {}, "new": {}}}}
        }
      },
      "PlacementBatchRequest": {
        "type": "object",
        "required": ["operations"],
        "properties": {
          "dry_run": {"type": "boolean", "description": "Validate and report, then roll back."},
          "change_comment": {"type": "string", "description": "Recorded in the history with this change."},
          "operations": {"type": "array", "maxItems": 1000, "items": {"type": "object", "required": ["operation", "target_type"], "properties": {
            "operation": {"type": "string", "enum": ["Create", "Update", "Delete", "Adopt"]},
            "target_type": {"type": "string", "enum": ["Identity", "Account", "Project", "Authorization", "All"]},
            "id": {"type": "string"},
            "name": {"type": "string", "description": "Selector when id is absent, for an account, project or authorization."},
            "identity": {"type": "string", "description": "Selector when id is absent, for an identity."},
            "expected_version": {"type": "integer", "format": "int64"},
            "cascade": {"type": "boolean"},
            "fields": {"$ref": "#/components/schemas/PlacementEntityInput"}
          }}}
        }
      },
      "PlacementMe": {
        "type": "object",
        "description": "The signed-in session's placement identity, as the placementd sees it.",
        "properties": {
          "identity": {"type": "string", "description": "The identity sent to the placementd, derived at sign-in from HTTP_API_PLACEMENT_IDENTITY_CLAIMS. Empty when the provider supplied none."},
          "display_name": {"type": "string"},
          "authorized": {"type": "boolean", "description": "Whether the placementd will issue this identity a token."},
          "expired": {"type": "boolean", "description": "Whether the identity's mapping has expired."},
          "mapping_expiration": {"type": "string", "format": "date-time"},
          "account": {"type": "string", "description": "The AP account tokens are issued for."},
          "authorizations": {"type": "array", "items": {"$ref": "#/components/schemas/PlacementAuthorization"}, "description": "The authorizations this identity may request."},
          "projects": {"type": "array", "items": {"type": "object", "properties": {
            "name": {"type": "string"}, "default": {"type": "boolean"},
            "enabled": {"type": "boolean", "description": "False when the schedd's project record is disabled; no record counts as enabled."}}}},
          "account_enabled": {"type": "boolean", "description": "False when the schedd's user record for account is disabled."},
          "records_available": {"type": "boolean", "description": "False when the schedd could not be asked; the enabled flags then say nothing."}
        }
      },
      "PlacementTokenRequest": {
        "type": "object",
        "required": ["project", "authorizations"],
        "description": "A token request. It names no user; any field not listed here is refused.",
        "properties": {
          "project": {"type": "string"},
          "authorizations": {"type": "array", "items": {"type": "string"}, "description": "Each must be one PlacementMe offers."},
          "user_code": {"type": "string", "description": "Bind the token to this pending device request instead of returning it."}
        }
      },
      "PlacementMeRequest": {
        "type": "object",
        "properties": {
          "identity": {"type": "string"},
          "display_name": {"type": "string"},
          "email": {"type": "string"},
          "request": {"nullable": true, "type": "object", "properties": {
            "id": {"type": "integer"},
            "status": {"type": "string", "enum": ["pending", "approved", "denied", "withdrawn"]},
            "projects": {"type": "array", "items": {"type": "string"}},
            "note": {"type": "string"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
            "decided_at": {"type": "string", "format": "date-time"},
            "reason": {"type": "string", "description": "The administrator's reason, on a denial."},
            "account": {"type": "string", "description": "The account access was granted as, on an approval."}
          }}
        }
      },
      "PlacementAccessRequest": {
        "type": "object",
        "properties": {
          "id": {"type": "integer"},
          "identity": {"type": "string"},
          "idp_subject": {"type": "string"},
          "display_name": {"type": "string"},
          "email": {"type": "string"},
          "projects": {"type": "array", "items": {"type": "string"}},
          "note": {"type": "string"},
          "status": {"type": "string", "enum": ["pending", "approved", "denied", "withdrawn"]},
          "created_at": {"type": "string", "format": "date-time"},
          "updated_at": {"type": "string", "format": "date-time"},
          "decided_by": {"type": "string"},
          "decided_at": {"type": "string", "format": "date-time"},
          "decision_note": {"type": "string"},
          "account": {"type": "string"},
          "changeset_id": {"type": "integer", "description": "The directory change set an approval made, when known."},
          "suggested_account": {"type": "string", "description": "The identity's part before its last @, in UID_DOMAIN."}
        }
      },
      "PlacementIssued": {
        "type": "object",
        "properties": {
          "token": {"type": "string", "description": "The token. Absent when it was bound to a device request."},
          "ap_user_id": {"type": "string"},
          "issued_at": {"type": "string", "format": "date-time"},
          "expires_at": {"type": "string", "format": "date-time"},
          "project": {"type": "string"},
          "authorizations": {"type": "array", "items": {"type": "string"}},
          "user_config": {"type": "string", "description": "SCHEDD_HOST and COLLECTOR_HOST lines for ~/.condor/user_config."},
          "device": {"$ref": "#/components/schemas/PlacementDeviceRequest"}
        }
      },
      "PlacementDeviceRequest": {
        "type": "object",
        "properties": {
          "user_code": {"type": "string"},
          "client_id": {"type": "string"},
          "client_name": {"type": "string"},
          "state": {"type": "string", "enum": ["pending", "approved", "denied", "expired"]},
          "expires_at": {"type": "string", "format": "date-time"}
        }
      },
      "PlacementRecord": {
        "type": "object",
        "description": "The schedd's user or project record for a name the placementd hands out.",
        "properties": {
          "kind": {"type": "string", "enum": ["account", "project"]},
          "name": {"type": "string"},
          "found": {"type": "boolean", "description": "False when nothing has been submitted under the name yet."},
          "enabled": {"type": "boolean"},
          "disable_reason": {"type": "string"},
          "stats": {"type": "object", "additionalProperties": {"type": "integer"}, "description": "NumIdle, NumRunning, NumHeld, NumSuspended, NumScheduler*, TotalCompletedJobs, TotalRemovedJobs, when published."},
          "members": {"type": "array", "items": {"type": "string"}, "description": "Identities mapped to the account, or accounts in the project."}
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
    "/metrics/{table}": {
      "get": {
        "tags": ["metrics"],
        "summary": "Query time-series metrics",
        "description": "A read-only, owner-scoped, time-bucketed aggregate over an htcondordb archive time-series table. The only table today is job_metrics; an unknown table is 404. The job page uses this to plot per-run memory/CPU/disk/GPU: group_by=RunInstanceID, bucket=15m, agg=max:MemoryUsage,avg:CpuUtil,max:DiskUsage,avg:GpuUtil plus the max:Request* reference lines, constraint=ClusterId == N && ProcId == M. The same surface answers fleet questions by grouping on other columns (Owner, ProjectName, admin-configured extras). MemoryUsage/DiskUsage are high-water marks, not instantaneous (see the design notes). An aggregate over GpuUtil or GPUsAverageUsage counts only samples reporting no more GPUs busy than the job had. A non-admin caller is confined to its own Owner. When the sampler is disabled the response is 200 with enabled=false and no rows. In multi-AP mode the samples come from the federation hub, every caller (administrators too) is confined to its own User on the member access points, job_id selects one job, group_by gains ScheddName before ClusterId or ProcId, and the response carries job and sources; a hub that does not federate job_metrics answers enabled=false.",
        "operationId": "queryMetrics",
        "parameters": [
          {"name": "table", "in": "path", "required": true, "schema": {"type": "string", "enum": ["job_metrics"]}, "description": "The metrics table to read."},
          {"name": "constraint", "in": "query", "required": false, "schema": {"type": "string"}, "description": "ClassAd expression selecting rows (e.g. 'ClusterId == 12345 && ProcId == 0'). ANDed server-side with the caller's Owner unless they are an admin. Defaults to all the caller's rows."},
          {"name": "group_by", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Comma-separated grouping columns, in output order (e.g. 'RunInstanceID'). The time bucket, if any, is always the last group column."},
          {"name": "bucket", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Time bucket width on the table's time attribute (SampleTime for job_metrics): a duration like '15m' or a number of seconds. Omit for no time bucketing."},
          {"name": "agg", "in": "query", "required": true, "schema": {"type": "string"}, "description": "Comma-separated aggregates as func:Attr, e.g. 'max:MemoryUsage,avg:CpuUtil'. Functions: count (count:*), sum, avg, min, max."},
          {"name": "since", "in": "query", "required": false, "schema": {"type": "integer"}, "description": "Lower bound (inclusive) on the time attribute, unix seconds."},
          {"name": "until", "in": "query", "required": false, "schema": {"type": "integer"}, "description": "Upper bound (inclusive) on the time attribute, unix seconds."},
          {"name": "job_id", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Multi-AP mode: one job's samples, by its complete id (e.g. '123.0@ap1.example.org'). A bare cluster.proc is accepted when exactly one access point has that job of the caller's; on more it is a 409 listing candidates."},
          {"name": "schedd", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Multi-AP mode: one access point's samples."}
        ],
        "responses": {
          "200": {
            "description": "The aggregate result, or enabled=false when the sampler is off. Rows are arrays of string cell values aligned to columns; group cells come first (in group_by order, time bucket last), then one cell per agg. Numeric cells are decimal strings; a bucket cell is the bucket-start unix time.",
            "content": {"application/json": {"schema": {
              "type": "object",
              "properties": {
                "enabled": {"type": "boolean", "description": "False when this server has no such table (sampler disabled or too old); then no columns/rows."},
                "table": {"type": "string"},
                "time_attr": {"type": "string", "description": "The attribute buckets/since/until act on."},
                "bucket_seconds": {"type": "integer"},
                "columns": {"type": "array", "items": {"type": "object", "properties": {
                  "name": {"type": "string"},
                  "kind": {"type": "string", "enum": ["group", "metric"]},
                  "func": {"type": "string"},
                  "attr": {"type": "string"},
                  "bucket_seconds": {"type": "integer"}
                }}},
                "rows": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}},
                "truncated": {"type": "boolean", "description": "True if the row cap was hit; narrow the query."},
                "job": {"type": "object", "description": "Multi-AP mode, with job_id: the complete id read.", "properties": {
                  "schedd": {"type": "string"},
                  "cluster": {"type": "integer"},
                  "proc": {"type": "integer"},
                  "job_id": {"type": "string"}
                }},
                "sources": {"type": "object", "description": "Multi-AP mode: how current the hub's copy of each access point is, naming each whose job_metrics stream is down or not federated."}
              }
            }}}
          },
          "400": {"description": "Bad parameters (unknown agg function, invalid attribute, unparseable constraint)", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "Unknown metrics table", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The mirror could not be reached or the query failed", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/utilization": {
      "get": {
        "summary": "Resource utilization of finished jobs",
        "description": "How well the caller's finished jobs (completed or removed, EnteredHistoryTime within the window) used the CPU, memory, disk and GPUs they reserved, grouped into workflows, with submit-file advice for the next submission. Read from a synchronized htcondordb mirror when one is current, else the schedd's history; at most limit (default 50,000) most recent jobs. A non-admin caller is confined to its own jobs whatever owned_by_me says. Cached for five minutes per scope and window. Memory is MiB, disk KiB, time seconds unless a field name says hours.",
        "operationId": "getUtilization",
        "parameters": [
          {"name": "days", "in": "query", "required": false, "schema": {"type": "integer", "enum": [1, 7, 30], "default": 7}, "description": "Analysis window."},
          {"name": "owned_by_me", "in": "query", "required": false, "schema": {"type": "boolean", "default": true}, "description": "false asks for everyone's jobs; honored only for administrators (a project lead gets own plus projects')."},
          {"name": "schedd", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Multi-AP mode: restrict to one access point."},
          {"name": "constraint", "in": "query", "required": false, "schema": {"type": "string"}, "description": "ClassAd expression ANDed with the scope and the window. One that does not parse is a 400 carrying the parser's message."},
          {"name": "owners", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Comma-separated user names to narrow to. Implies owned_by_me=false unless that is given; intersected with what the caller may see, never widening it."},
          {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1, "default": 50000}, "description": "Most finished jobs to analyse, most recent first. Clamped to HTTP_API_UTILIZATION_MAX_JOBS (default 1,000,000); the response reports the value applied."}
        ],
        "responses": {
          "200": {"description": "The analysis; jobs_considered is 0 when there is nothing to analyse.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/UtilizationResponse"}}}},
          "400": {"description": "Bad parameters", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "Job history could not be read", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "The mirror is required and could not answer", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/utilization/workflow": {
      "get": {
        "summary": "One utilization workflow in full",
        "description": "One workflow's full detail -- distributions, samples, batches, memory curve, advice with text and submit lines, throughput -- from the cached analysis for the same days, owned_by_me, constraint, owners, limit and schedd, plus how many of the caller's jobs of it are idle in the queue now. Same scoping as /utilization; an unknown key is a 404.",
        "operationId": "getUtilizationWorkflow",
        "parameters": [
          {"name": "w", "in": "query", "required": true, "schema": {"type": "string"}},
          {"name": "days", "in": "query", "required": false, "schema": {"type": "integer", "enum": [1, 7, 30]}},
          {"name": "owned_by_me", "in": "query", "required": false, "schema": {"type": "boolean"}},
          {"name": "constraint", "in": "query", "required": false, "schema": {"type": "string"}},
          {"name": "owners", "in": "query", "required": false, "schema": {"type": "string"}},
          {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer"}},
          {"name": "schedd", "in": "query", "required": false, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "The workflow.", "content": {"application/json": {"schema": {"type": "object", "properties": {
            "since": {"type": "integer"}, "until": {"type": "integer"}, "days": {"type": "integer"}, "truncated": {"type": "boolean"}, "limit": {"type": "integer"},
            "workflow": {"$ref": "#/components/schemas/UtilWorkflow"},
            "waiting_jobs": {"type": "integer", "nullable": true, "description": "The caller's idle jobs of this workflow; null in multi-AP mode or when the queue could not be read."}}}}}},
          "400": {"description": "Bad parameters", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No workflow with that key in this analysis", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/utilization/apply": {
      "post": {
        "summary": "Apply a workflow's suggestions to its waiting jobs",
        "description": "Sets RequestMemory, RequestCpus, RequestDisk or RequestGPUs on the caller's idle jobs of the workflow, to the values in the server's own current advice (the body names advice ids, never values). Edits go through the job-edit path and its owner scope; an administrator's reach is the job-edit endpoints'. A request written as a formula over the job's usage is left as written and reported in skipped. memory-retry is declined: retry_request_memory is a submit-time on-evict transform that cannot be added to a queued job.",
        "operationId": "applyUtilization",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["w", "advice"], "properties": {
          "w": {"type": "string"}, "advice": {"type": "array", "items": {"type": "string"}},
          "days": {"type": "integer"}, "owned_by_me": {"type": "boolean"}, "constraint": {"type": "string"}, "owners": {"type": "string"},
          "limit": {"type": "integer"}, "schedd": {"type": "string"}}}}}},
        "responses": {
          "200": {"description": "What was done.", "content": {"application/json": {"schema": {"type": "object", "properties": {
            "edited": {"type": "integer"},
            "set": {"type": "object", "additionalProperties": {"type": "number"}},
            "declined": {"type": "array", "items": {"type": "object", "properties": {"advice": {"type": "string"}, "reason": {"type": "string"}}}},
            "skipped": {"type": "array", "items": {"type": "object", "properties": {"job": {"type": "string"}, "reason": {"type": "string"}}}},
            "failed": {"type": "array", "items": {"type": "object", "properties": {"job": {"type": "string"}, "reason": {"type": "string"}}}}}}}}},
          "400": {"description": "Bad body, or an advice id not in the workflow's current advice", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No workflow with that key in this analysis", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "Multi-AP mode", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/utilization/jobs": {
      "get": {
        "summary": "Jobs of one utilization workflow",
        "description": "The individual finished jobs of one workflow from /utilization, a page at a time. Pass the workflow key as w and the same days, owned_by_me, constraint, owners, limit and schedd the analysis used, so the jobs listed are the jobs analysed. Owner-scoped like /utilization: a key for someone else's workflow is a 404 for a caller who may not see it.",
        "operationId": "getUtilizationJobs",
        "parameters": [
          {"name": "w", "in": "query", "required": true, "schema": {"type": "string"}, "description": "Workflow key from /utilization."},
          {"name": "days", "in": "query", "required": false, "schema": {"type": "integer", "enum": [1, 7, 30], "default": 7}},
          {"name": "owned_by_me", "in": "query", "required": false, "schema": {"type": "boolean"}},
          {"name": "constraint", "in": "query", "required": false, "schema": {"type": "string"}},
          {"name": "owners", "in": "query", "required": false, "schema": {"type": "string"}},
          {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1}},
          {"name": "schedd", "in": "query", "required": false, "schema": {"type": "string"}},
          {"name": "sort", "in": "query", "required": false, "schema": {"type": "string", "enum": ["completed", "submitted", "wall", "memory", "cores", "efficiency", "disk", "gpu"], "default": "completed"}, "description": "Jobs without a value sort last in either order; ties go by cluster, proc."},
          {"name": "order", "in": "query", "required": false, "schema": {"type": "string", "enum": ["asc", "desc"], "default": "desc"}},
          {"name": "offset", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 0, "default": 0}},
          {"name": "page_size", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}}
        ],
        "responses": {
          "200": {"description": "One page of rows.", "content": {"application/json": {"schema": {"type": "object", "properties": {
            "key": {"type": "string"}, "total": {"type": "integer"}, "offset": {"type": "integer"},
            "next_offset": {"type": "integer", "nullable": true}, "sort": {"type": "string"}, "order": {"type": "string"},
            "truncated": {"type": "boolean"},
            "jobs": {"type": "array", "items": {"type": "object", "properties": {
              "id": {"type": "string"}, "cluster": {"type": "integer"}, "proc": {"type": "integer"}, "schedd": {"type": "string"},
              "owner": {"type": "string"}, "submitted": {"type": "integer", "nullable": true}, "started": {"type": "integer", "nullable": true},
              "completed": {"type": "integer", "nullable": true},
              "outcome": {"type": "string", "enum": ["ok", "failed", "removed", "memory_exceeded"]},
              "exit_code": {"type": "integer", "nullable": true}, "exit_by_signal": {"type": "boolean"}, "wall": {"type": "number"},
              "request": {"type": "object", "properties": {"memory_mib": {"type": "number", "nullable": true}, "cpus": {"type": "number", "nullable": true}, "disk_kib": {"type": "number", "nullable": true}, "gpus": {"type": "number", "nullable": true}}},
              "memory_peak_mib": {"type": "number", "nullable": true}, "cores_used": {"type": "number", "nullable": true},
              "cpu_efficiency": {"type": "number", "nullable": true}, "disk_used_kib": {"type": "number", "nullable": true},
              "gpu_utilization": {"type": "number", "nullable": true}, "gpu_memory_peak_mib": {"type": "number", "nullable": true},
              "restarts": {"type": "integer"}, "held_for_memory": {"type": "boolean"}, "held_for_disk": {"type": "boolean"}}}}
          }}}}},
          "400": {"description": "Bad parameters", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No workflow with that key in this analysis", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "Job history could not be read", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
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
          {"name": "username", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Restrict to one sign-in identity. An unknown identity yields an empty list, not an error."}
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
          {"name": "username", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Restrict to tokens issued for one sign-in identity."},
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
        "description": "Ask the placementd for an IDToken for a sign-in identity. Beyond returning the token this creates the AP user record -- and the project record, when a project is named -- in the schedd if they do not exist; a login against a DISABLED user or project fails rather than re-enabling it. The response is the only time the token is available. Requires membership in the web UI admin group.",
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
    "/placement/admin/{kind}": {
      "get": {
        "summary": "List directory entities",
        "description": "Identities, accounts, projects or authorizations, with each row's source and version. Requires membership in the web UI admin group.",
        "operationId": "listPlacementEntities",
        "tags": ["placement"],
        "parameters": [
          {"name": "kind", "in": "path", "required": true, "schema": {"type": "string", "enum": ["identities", "accounts", "projects", "authorizations"]}},
          {"name": "name", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Match one account, project or authorization by name. Not for identities."},
          {"name": "identity", "in": "query", "required": false, "schema": {"type": "string"}, "description": "Match one identity. Identities only."},
          {"name": "constraint", "in": "query", "required": false, "schema": {"type": "string"}, "description": "ClassAd expression evaluated against each entity ad."},
          {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer"}}
        ],
        "responses": {
          "200": {"description": "Entities, keyed by kind", "content": {"application/json": {"schema": {"type": "object", "additionalProperties": {"type": "array", "items": {"oneOf": [{"$ref": "#/components/schemas/PlacementIdentity"}, {"$ref": "#/components/schemas/PlacementAccount"}, {"$ref": "#/components/schemas/PlacementProject"}, {"$ref": "#/components/schemas/PlacementAuthorizationRecord"}]}}}}}},
          "400": {"description": "Invalid field, value or expression", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "post": {
        "summary": "Create a directory entity",
        "description": "Creates an internal row. References (an identity's account, an account's projects and authorizations) must already exist. Requires membership in the web UI admin group.",
        "operationId": "createPlacementEntity",
        "tags": ["placement"],
        "parameters": [{"name": "kind", "in": "path", "required": true, "schema": {"type": "string", "enum": ["identities", "accounts", "projects", "authorizations"]}}, {"name": "dry_run", "in": "query", "required": false, "schema": {"type": "boolean"}, "description": "Validate and report, then roll back."}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementEntityInput"}}}},
        "responses": {
          "201": {"description": "Created", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementEditResponse"}}}},
          "400": {"description": "Invalid field, value or expression", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "404": {"description": "No such entity, or a reference names none", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "409": {"description": "Version mismatch, a mapfile-owned row (owned_by), a delete that needs cascade (cascade_required), or a duplicate name", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/{kind}/{id}": {
      "get": {
        "summary": "Get a directory entity",
        "operationId": "getPlacementEntity",
        "tags": ["placement"],
        "parameters": [{"name": "kind", "in": "path", "required": true, "schema": {"type": "string", "enum": ["identities", "accounts", "projects", "authorizations"]}}, {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The entity uuid."}],
        "responses": {
          "200": {"description": "The entity", "content": {"application/json": {"schema": {"oneOf": [{"$ref": "#/components/schemas/PlacementIdentity"}, {"$ref": "#/components/schemas/PlacementAccount"}, {"$ref": "#/components/schemas/PlacementProject"}, {"$ref": "#/components/schemas/PlacementAuthorizationRecord"}]}}}},
          "404": {"description": "No such entity, or a reference names none", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "patch": {
        "summary": "Update a directory entity",
        "description": "Changes only the fields present; null clears one. Send expected_version: a 409 means the row changed since it was read. Mapfile rows return 409 with owned_by=mapfile until adopted.",
        "operationId": "updatePlacementEntity",
        "tags": ["placement"],
        "parameters": [{"name": "kind", "in": "path", "required": true, "schema": {"type": "string", "enum": ["identities", "accounts", "projects", "authorizations"]}}, {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The entity uuid."}, {"name": "dry_run", "in": "query", "required": false, "schema": {"type": "boolean"}, "description": "Validate and report, then roll back."}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementEntityInput"}}}},
        "responses": {
          "200": {"description": "Updated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementEditResponse"}}}},
          "400": {"description": "Invalid field, value or expression", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "404": {"description": "No such entity, or a reference names none", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "409": {"description": "Version mismatch, a mapfile-owned row (owned_by), a delete that needs cascade (cascade_required), or a duplicate name", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "Delete a directory entity",
        "description": "Refused with 409 and cascade_required=true while grants or identities reference the row, unless cascade=true.",
        "operationId": "deletePlacementEntity",
        "tags": ["placement"],
        "parameters": [
          {"name": "kind", "in": "path", "required": true, "schema": {"type": "string", "enum": ["identities", "accounts", "projects", "authorizations"]}}, {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The entity uuid."}, {"name": "dry_run", "in": "query", "required": false, "schema": {"type": "boolean"}, "description": "Validate and report, then roll back."},
          {"name": "cascade", "in": "query", "required": false, "schema": {"type": "boolean"}},
          {"name": "expected_version", "in": "query", "required": false, "schema": {"type": "integer", "format": "int64"}}
        ],
        "requestBody": {"required": false, "content": {"application/json": {"schema": {"type": "object", "properties": {"change_comment": {"type": "string", "description": "Recorded in the history with this change."}}}}}},
        "responses": {
          "200": {"description": "Deleted", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementEditResponse"}}}},
          "400": {"description": "Invalid field, value or expression", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "404": {"description": "No such entity, or a reference names none", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "409": {"description": "Version mismatch, a mapfile-owned row (owned_by), a delete that needs cascade (cascade_required), or a duplicate name", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/{kind}/{id}/adopt": {
      "post": {
        "summary": "Adopt a mapfile row",
        "description": "Transfers ownership from the mapfile to the directory, so the row becomes editable. Adopting an account adopts its identities. While the key is still in the mapfile the next reload takes it back; the result carries a warning then.",
        "operationId": "adoptPlacementEntity",
        "tags": ["placement"],
        "parameters": [{"name": "kind", "in": "path", "required": true, "schema": {"type": "string", "enum": ["identities", "accounts", "projects", "authorizations"]}}, {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The entity uuid."}, {"name": "dry_run", "in": "query", "required": false, "schema": {"type": "boolean"}, "description": "Validate and report, then roll back."}],
        "requestBody": {"required": false, "content": {"application/json": {"schema": {"type": "object", "properties": {"expected_version": {"type": "integer", "format": "int64"}, "change_comment": {"type": "string", "description": "Recorded in the history with this change."}}}}}},
        "responses": {
          "200": {"description": "Adopted", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementEditResponse"}}}},
          "404": {"description": "No such entity, or a reference names none", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "409": {"description": "Version mismatch, a mapfile-owned row (owned_by), a delete that needs cascade (cascade_required), or a duplicate name", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/adopt-all": {
      "post": {
        "summary": "Adopt every mapfile row",
        "operationId": "adoptAllPlacementEntities",
        "tags": ["placement"],
        "parameters": [{"name": "dry_run", "in": "query", "required": false, "schema": {"type": "boolean"}, "description": "Validate and report, then roll back."}],
        "requestBody": {"required": false, "content": {"application/json": {"schema": {"type": "object", "properties": {"change_comment": {"type": "string", "description": "Recorded in the history with this change."}}}}}},
        "responses": {
          "200": {"description": "Adopted", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementEditResponse"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/batch": {
      "post": {
        "summary": "Apply a batch of directory edits",
        "description": "One atomic PLACEMENT_EDIT: every operation applies or none does. A failed batch answers with the first failure's status and every operation's result.",
        "operationId": "placementBatch",
        "tags": ["placement"],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementBatchRequest"}}}},
        "responses": {
          "200": {"description": "Applied, or validated on a dry run", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementEditResponse"}}}},
          "400": {"description": "Invalid field, value or expression", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "404": {"description": "No such entity, or a reference names none", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "409": {"description": "Version mismatch, a mapfile-owned row (owned_by), a delete that needs cascade (cascade_required), or a duplicate name", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/history": {
      "get": {
        "summary": "Directory history",
        "description": "Changes to the directory, newest first: who made each, through which channel, and each field's old and new value. Entries outlive deleted entities.",
        "operationId": "placementHistory",
        "tags": ["placement"],
        "parameters": [
          {"name": "entity_id", "in": "query", "required": false, "schema": {"type": "string"}, "description": "One entity's uuid."},
          {"name": "constraint", "in": "query", "required": false, "schema": {"type": "string"}, "description": "ClassAd expression evaluated against each entry."},
          {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}}
        ],
        "responses": {
          "200": {"description": "History, newest first", "content": {"application/json": {"schema": {"type": "object", "properties": {"history": {"type": "array", "items": {"$ref": "#/components/schemas/PlacementModification"}}}}}}},
          "400": {"description": "Invalid limit or expression", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/{kind}/{id}/history": {
      "get": {
        "summary": "One entity's history",
        "operationId": "placementEntityHistory",
        "tags": ["placement"],
        "parameters": [
          {"name": "kind", "in": "path", "required": true, "schema": {"type": "string", "enum": ["identities", "accounts", "projects", "authorizations"]}},
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The entity uuid."},
          {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}}
        ],
        "responses": {
          "200": {"description": "History, newest first", "content": {"application/json": {"schema": {"type": "object", "properties": {"history": {"type": "array", "items": {"$ref": "#/components/schemas/PlacementModification"}}}}}}},
          "400": {"description": "Invalid limit or expression", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/requests": {
      "get": {
        "summary": "List access requests",
        "description": "Requests from people whose identity the placementd does not map, newest first (at most 500). Requires membership in the web UI admin group. Display names, emails and notes are what the requester's provider and the requester gave.",
        "operationId": "listPlacementAccessRequests",
        "tags": ["placement"],
        "parameters": [
          {"name": "status", "in": "query", "required": false, "schema": {"type": "string", "enum": ["pending", "approved", "denied", "withdrawn", "all"], "default": "pending"}}
        ],
        "responses": {
          "200": {"description": "Requests", "content": {"application/json": {"schema": {"type": "object", "properties": {"requests": {"type": "array", "items": {"$ref": "#/components/schemas/PlacementAccessRequest"}}, "pending": {"type": "integer", "description": "Every pending request, whatever the filter."}, "can_approve": {"type": "boolean", "description": "Whether the placementd serves the directory edits an approval needs."}}}}}},
          "400": {"description": "Unknown status", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/requests/count": {
      "get": {
        "summary": "Count pending access requests",
        "operationId": "countPlacementAccessRequests",
        "tags": ["placement"],
        "responses": {
          "200": {"description": "Count", "content": {"application/json": {"schema": {"type": "object", "properties": {"pending": {"type": "integer"}}}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/requests/{id}": {
      "get": {
        "summary": "One access request",
        "operationId": "getPlacementAccessRequest",
        "tags": ["placement"],
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
        "responses": {
          "200": {"description": "Request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAccessRequest"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/requests/{id}/approve": {
      "post": {
        "summary": "Approve an access request",
        "description": "One PLACEMENT_EDIT batch, made on behalf of the signed-in administrator with the change comment \"access request #<id>\" plus the comment given: the account is created if it does not exist (or its grants updated when they differ), then the request's identity is created and mapped to it. The request is marked approved only once the batch committed. dry_run (body or query) validates without changing anything.",
        "operationId": "approvePlacementAccessRequest",
        "tags": ["placement"],
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["account"], "properties": {
          "account": {"type": "string"},
          "authorizations": {"type": "array", "items": {"type": "string"}},
          "projects": {"type": "array", "items": {"type": "string"}},
          "default_project": {"type": "string"},
          "expires_at": {"type": "string", "format": "date-time", "nullable": true, "description": "When the identity's mapping stops being honored; absent or null for never."},
          "display_name": {"type": "string"},
          "comment": {"type": "string", "maxLength": 2048},
          "dry_run": {"type": "boolean"}
        }}}}},
        "responses": {
          "200": {"description": "Approved, or validated on a dry run", "content": {"application/json": {"schema": {"allOf": [{"$ref": "#/components/schemas/PlacementEditResponse"}, {"type": "object", "properties": {"request": {"$ref": "#/components/schemas/PlacementAccessRequest"}}}]}}}},
          "400": {"description": "Invalid body, or the placementd refused a field", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAdminError"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "409": {"description": "The request is not pending; the identity is already in the directory (identity_exists); or the account comes from the map file and the grants differ", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/requests/{id}/deny": {
      "post": {
        "summary": "Deny an access request",
        "description": "The reason is shown to the requester.",
        "operationId": "denyPlacementAccessRequest",
        "tags": ["placement"],
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["reason"], "properties": {"reason": {"type": "string", "maxLength": 2048}}}}}},
        "responses": {
          "200": {"description": "Denied", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAccessRequest"}}}},
          "400": {"description": "No reason, or an invalid body", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "409": {"description": "The request is not pending", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/requests/{id}/resolve": {
      "post": {
        "summary": "Mark an access request resolved",
        "description": "Marks the request approved without changing the directory, for an identity given access some other way. Refused unless the placementd maps the identity now.",
        "operationId": "resolvePlacementAccessRequest",
        "tags": ["placement"],
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
        "requestBody": {"required": false, "content": {"application/json": {"schema": {"type": "object", "properties": {"comment": {"type": "string", "maxLength": 2048}}}}}},
        "responses": {
          "200": {"description": "Resolved", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementAccessRequest"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "409": {"description": "The request is not pending, or the identity does not have access", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/admin/mapfile-status": {
      "get": {
        "summary": "Mapfile reload status",
        "description": "The outcome of the placementd's last mapfile reload: when it loaded, how many keys were quarantined or reclaimed, and the problems found.",
        "operationId": "placementMapfileStatus",
        "tags": ["placement"],
        "responses": {
          "200": {"description": "Status", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementMapfileStatus"}}}},
          "401": {"description": "Not authenticated", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not an administrator", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "501": {"description": "The placementd does not support directory management", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The placementd could not be reached or returned an unexpected error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "No placementd is available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/me": {
      "get": {
        "summary": "Your placement identity",
        "description": "What the placementd says about the signed-in session's own identity, with the projects and authorizations it may request and the schedd's enabled flags. Any browser session.",
        "operationId": "placementMe",
        "tags": ["placement"],
        "responses": {
          "200": {"description": "Identity", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementMe"}}}},
          "401": {"description": "Not signed in", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "Placement tokens are not available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/me/token": {
      "post": {
        "summary": "Request a placement token for yourself",
        "description": "Mints a token for the session's own identity (UserName and Requester are both the session's). Requires the X-Requested-With header. With user_code the token goes to that device request and is not returned.",
        "operationId": "placementMeToken",
        "tags": ["placement"],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementTokenRequest"}}}},
        "responses": {
          "201": {"description": "Token issued", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementIssued"}}}},
          "400": {"description": "Malformed request, unknown field, or an authorization not offered", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "Not authorized, or the X-Requested-With header is missing", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "Unknown device code", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "409": {"description": "The device request was already answered or has expired", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "503": {"description": "Placement tokens are not available", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/me/request": {
      "get": {
        "summary": "Your access request",
        "description": "Your latest access request, or null, with the identity, name and email a new request would record. For a session whose placement identity the placementd does not map.",
        "operationId": "placementMeRequest",
        "tags": ["placement"],
        "responses": {
          "200": {"description": "Request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementMeRequest"}}}},
          "403": {"description": "The session has no placement identity", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "post": {
        "summary": "Request access",
        "description": "Files a request for the session's own identity; the body names none, and any field not listed is refused. Only for an identity the placementd does not map, one pending request at a time, and rate-limited per identity and per address. Requires the X-Requested-With header.",
        "operationId": "placementMeRequestCreate",
        "tags": ["placement"],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {
          "projects": {"type": "array", "maxItems": 10, "items": {"type": "string", "maxLength": 64}},
          "note": {"type": "string", "description": "At most 2048 bytes."}
        }}}}},
        "responses": {
          "201": {"description": "Filed", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementMeRequest"}}}},
          "400": {"description": "Invalid body, or over a limit", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "403": {"description": "No placement identity, or the X-Requested-With header is missing", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "409": {"description": "A request is already pending, or the identity already has access", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "429": {"description": "Too many requests", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "Withdraw your pending access request",
        "operationId": "placementMeRequestWithdraw",
        "tags": ["placement"],
        "responses": {
          "200": {"description": "Withdrawn", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementMeRequest"}}}},
          "404": {"description": "No pending request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/me/project": {
      "post": {
        "summary": "Select your project",
        "description": "For a session signed in through the placementd identity mapping: the project its tokens name. Requires the X-Requested-With header.",
        "operationId": "placementMeProject",
        "tags": ["placement"],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["project"], "properties": {"project": {"type": "string"}}}}}},
        "responses": {
          "200": {"description": "Selected"},
          "400": {"description": "Not one of the account's projects", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "409": {"description": "The session has no placementd account", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/me/device/{user_code}": {
      "get": {
        "summary": "A pending device request",
        "operationId": "placementDeviceRequest",
        "tags": ["placement"],
        "parameters": [{"name": "user_code", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^[A-Za-z]{4}-[A-Za-z]{4}$"}}],
        "responses": {
          "200": {"description": "Request", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementDeviceRequest"}}}},
          "404": {"description": "Unknown code", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/me/device/{user_code}/deny": {
      "post": {
        "summary": "Deny a pending device request",
        "description": "The client's next poll gets access_denied. A request already answered or expired is left as it is. Same as POST /auth/cancel_device. Requires the X-Requested-With header.",
        "operationId": "placementDeviceDeny",
        "tags": ["placement"],
        "parameters": [{"name": "user_code", "in": "path", "required": true, "schema": {"type": "string"}}],
        "responses": {
          "200": {"description": "Canceled"},
          "404": {"description": "Unknown code", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/records/projects": {
      "get": {
        "summary": "List placement projects",
        "description": "Every project on a placementd map file line, with its schedd record's state. Requires membership in the web UI admin group.",
        "operationId": "listPlacementProjects",
        "tags": ["placement"],
        "responses": {
          "200": {"description": "Projects"}
        }
      }
    },
    "/placement/records/{kind}/{name}": {
      "get": {
        "summary": "A placement account's or project's schedd record",
        "description": "The record, its job counters and who it belongs to. Only names the placementd hands out. Requires membership in the web UI admin group.",
        "operationId": "getPlacementRecord",
        "tags": ["placement"],
        "parameters": [
          {"name": "kind", "in": "path", "required": true, "schema": {"type": "string", "enum": ["accounts", "projects"]}},
          {"name": "name", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "responses": {
          "200": {"description": "Record", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementRecord"}}}},
          "404": {"description": "Not a name the placementd hands out", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/placement/records/{kind}/{name}/{action}": {
      "post": {
        "summary": "Suspend or unsuspend a placement account or project",
        "description": "DISABLE_USERREC or ENABLE_USERREC on the schedd. A suspension's reason is \"suspended by <admin> via web UI\". Requires membership in the web UI admin group.",
        "operationId": "setPlacementRecordSuspended",
        "tags": ["placement"],
        "parameters": [
          {"name": "kind", "in": "path", "required": true, "schema": {"type": "string", "enum": ["accounts", "projects"]}},
          {"name": "name", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "action", "in": "path", "required": true, "schema": {"type": "string", "enum": ["suspend", "unsuspend"]}}
        ],
        "responses": {
          "200": {"description": "The record after the change", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlacementRecord"}}}},
          "404": {"description": "Not a placement name, or the schedd has no record for it", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "The schedd refused or could not be reached", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
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
            "description": "Filter jobs to only those owned by the authenticated user. Default: true. Set to false to see all jobs; honoured only for an administrator, and every other caller, bearer token or browser session, gets its own jobs.",
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
        "parameters": [
          {
            "name": "schedd",
            "in": "query",
            "required": false,
            "schema": {"type": "string"},
            "description": "Multi-AP mode only: submit to this access point, which must be your home access point or one of its alternates (default: your home access point)"
          }
        ],
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
        "description": "Retrieve the ClassAd for a specific job. Attributes stored as expressions arrive as the string \"/Expr(...)/\". Alongside them, the member \"evaluated\" holds the number each of RequestCpus, RequestMemory, RequestDisk and RequestGPUs evaluates to in the job's own ad, so a request written as an expression (e.g. over MemoryUsage) can be read without a ClassAd evaluator; a request that does not evaluate to a number is left out.",
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
    "/jobs/{jobId}/runtime-estimate": {
      "get": {
        "summary": "Estimate how long a job will run",
        "description": "How long the job is likely to run in total, with a likely range, estimated from the runtimes of the same owner's similar jobs that have already completed (the same cluster, command line, batch name, submit directory or program, or the owner's jobs as a whole, chosen by which has predicted that owner's jobs best), always of the same universe and, for a DAG node, from DAG nodes only. Other users' jobs never answer: an owner with no comparable finished job gets no estimate. For a running job, also how long it has run and how long it likely has left. memory says what the same group's runs peaked at, and how the job's own peak compares. A job that has left the queue is answered from its history record, as it would have been estimated when submitted, from groups holding runs other than its own; exceeded_history and memory.above_usual then say whether its run was unusual. Built from the htcondordb mirror's job history, refreshed every few minutes; it never reveals another job's command, id or owner. Always 200 for a job the caller can see: when no estimate can be made, available is false and reason says why (disabled, model_warming_up, insufficient_history, not_estimated).",
        "operationId": "getJobRuntimeEstimate",
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
            "description": "The estimate, or why there is none",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "required": ["job_id", "available", "exceeded_history", "model"],
                  "properties": {
                    "job_id": {"type": "string"},
                    "available": {"type": "boolean"},
                    "reason": {"type": "string", "enum": ["disabled", "model_warming_up", "insufficient_history", "not_estimated"], "description": "Why there is no estimate; absent when available. insufficient_history: the owner has no recently finished job of the same kind. not_estimated: the job is a scheduler- or local-universe job, such as a DAG's workflow manager (DAGMan), which is never estimated."},
                    "estimate_seconds": {"type": "number", "description": "Expected total runtime. For a running job that has outlived the typical run, re-estimated from the comparable runs that lasted at least as long."},
                    "p10_seconds": {"type": "number", "description": "Lower end of the likely range: about 10% of comparable jobs finish sooner."},
                    "p90_seconds": {"type": "number", "description": "Upper end of the likely range: about 90% of comparable jobs finish by then. Drawn from past estimation errors made at the same point in a job's life (waiting or running)."},
                    "basis": {
                      "type": "object",
                      "properties": {
                        "level": {"type": "string", "enum": ["cluster", "exact", "template", "batch", "iwd", "cmd", "owner"], "description": "Which group of the owner's completed jobs answered: the job's own cluster, the same command line, the same command line with numbers masked, the same batch name, the same submit directory, the same program, or all the owner's jobs. Every group holds only jobs of the same universe that are, like this one, DAG nodes or not."},
                        "sample_count": {"type": "integer", "description": "How many recent runtimes that group holds."},
                        "new_command": {"type": "boolean", "description": "None of the owner's recently completed jobs ran the same program. Absent when false."}
                      }
                    },
                    "rough": {"type": "boolean", "description": "The estimate came from a broad group (level cmd or owner), which is right far less often than the specific ones; present it as a rough guess."},
                    "elapsed_seconds": {"type": "number", "description": "How long the current execution has run. Present only while the job is running."},
                    "remaining_seconds": {"type": "number", "description": "estimate_seconds less elapsed_seconds. Absent when the job is not running or has exceeded its history."},
                    "exceeded_history": {"type": "boolean", "description": "The job has run longer than nearly every comparable job, so no remaining time is given; the estimate and range are what history said before it started. For a finished job: its runtime was longer than the comparable runs' median and fewer than 3 of them lasted at least as long (its own run left out)."},
                    "memory": {
                      "type": "object",
                      "description": "What the runs of the group that answered peaked at, in MiB, over those with a known peak. Absent when none has one.",
                      "properties": {
                        "sample_count": {"type": "integer", "description": "How many of the group's runs have a known peak."},
                        "p10_mib": {"type": "number"}, "p25_mib": {"type": "number"}, "p50_mib": {"type": "number"}, "p75_mib": {"type": "number"}, "p90_mib": {"type": "number"},
                        "peak_mib": {"type": "number", "description": "The job's own peak so far (MemoryUsage, unrounded when the schedd keeps ResidentSetSize_RAW); for a finished job, its peak. Absent when none is recorded."},
                        "requested_mib": {"type": "number", "description": "The job's RequestMemory, evaluated. Absent when it does not evaluate to a positive number."},
                        "above_requested": {"type": "integer", "description": "How many of the group's runs peaked above requested_mib."},
                        "rough": {"type": "boolean", "description": "The same as the estimate's rough: the group is a broad one."},
                        "above_usual": {"type": "boolean", "description": "The job is running or finished, the group is a specific one (not rough) with at least 5 known peaks, and the job's peak (so far) is at least 1.25 times the group's p90 and at least 256 MiB above it. A finished job's own run is left out of the group it is compared with."}
                      }
                    },
                    "model": {
                      "type": "object",
                      "properties": {
                        "trained_through": {"type": "string", "format": "date-time", "description": "Completion time of the newest job the estimator has read."},
                        "jobs_ingested": {"type": "integer"}
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            "description": "Invalid job ID",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "401": {
            "description": "Not authenticated",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "404": {
            "description": "Job not found, or not the caller's",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "500": {
            "description": "Failed to query the job",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          }
        }
      }
    },
    "/jobs/{jobId}/similar": {
      "get": {
        "summary": "The finished jobs behind a runtime estimate",
        "description": "The job's group at one level of the runtime estimator -- by default the level that answered its estimate -- as the estimator files it: the owner's finished jobs that completed normally within the estimator's recency window, grouped by its own features and keys, newest first and at most its per-group sample bound. runtimes summarizes what the estimator holds for the group right now, which is what an estimate uses, and memory the same runs' peak memory in MiB (those with a known peak; null when none has one). The job is read with the same scope as GET /jobs/{jobId}: someone else's job is a 404, and the list holds only jobs the caller may read. Not available in multi-AP mode.",
        "operationId": "getJobSimilar",
        "parameters": [
          {"name": "jobId", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "level", "in": "query", "required": false, "schema": {"type": "string", "enum": ["cluster", "exact", "template", "batch", "iwd", "cmd", "owner"]}, "description": "A level that does not apply to the job is a 400."},
          {"name": "offset", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 0, "default": 0}},
          {"name": "page_size", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50}}
        ],
        "responses": {
          "200": {"description": "The group.", "content": {"application/json": {"schema": {"type": "object", "properties": {
            "job_id": {"type": "string"}, "level": {"type": "string"}, "description": {"type": "string"},
            "estimate_level": {"type": "string", "nullable": true},
            "levels": {"type": "array", "items": {"type": "object", "properties": {"level": {"type": "string"}, "description": {"type": "string"}, "applies": {"type": "boolean"}, "count": {"type": "integer", "nullable": true}}}},
            "window": {"type": "object", "properties": {"days": {"type": "number"}, "max_jobs": {"type": "integer"}}},
            "runtimes": {"type": "object", "nullable": true, "properties": {"count": {"type": "integer"}, "p10": {"type": "number"}, "p25": {"type": "number"}, "p50": {"type": "number"}, "p75": {"type": "number"}, "p90": {"type": "number"}}},
            "memory": {"type": "object", "nullable": true, "properties": {"count": {"type": "integer"}, "p10": {"type": "number"}, "p25": {"type": "number"}, "p50": {"type": "number"}, "p75": {"type": "number"}, "p90": {"type": "number"}}},
            "total": {"type": "integer"}, "offset": {"type": "integer"}, "next_offset": {"type": "integer", "nullable": true},
            "jobs": {"type": "array", "items": {"type": "object", "properties": {
              "id": {"type": "string"}, "cluster": {"type": "integer"}, "proc": {"type": "integer"}, "submitted": {"type": "integer", "nullable": true},
              "completed": {"type": "integer"}, "runtime": {"type": "number"}, "exit_code": {"type": "integer"},
              "peak_memory_mib": {"type": "number", "nullable": true}}}}}}}}},
          "400": {"description": "Bad parameters", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "Job not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/batches/{batchId}": {
      "get": {
        "summary": "A batch: one row of the jobs page, over its whole life",
        "description": "A DAG (every job sharing its JobBatchName, id the root DAGMan cluster), a named batch (one owner's jobs under one JobBatchName across clusters, id the smallest cluster) or a cluster, found by any of its cluster ids in the queue or in history. Identity and the constraint selecting its jobs; progress; jobs in the queue by status; finished-job outcomes, runtimes, wall/badput/core hours and memory from up to 100,000 history records, newest first; hold reasons grouped as on the Issues page; a DAG's DAG_* attributes; the Utilization workflows its jobs fall in. Same scope as GET /jobs/{jobId}: another user's batch is 404. Reused for 15 seconds. Not available in multi-AP mode.",
        "operationId": "getBatch",
        "parameters": [{"name": "batchId", "in": "path", "required": true, "schema": {"type": "integer", "minimum": 0}, "description": "Any cluster id of the batch; the answer's id is the batch's own."}],
        "responses": {
          "200": {"description": "The batch.", "content": {"application/json": {"schema": {"type": "object", "properties": {
            "kind": {"type": "string", "enum": ["dag", "named", "cluster"]}, "id": {"type": "integer"}, "name": {"type": "string"},
            "owner": {"type": "string"}, "constraint": {"type": "string"}, "remove_constraint": {"type": "string"},
            "clusters": {"type": "array", "items": {"type": "integer"}}, "dagman_job_id": {"type": "string"},
            "submitted": {"type": "integer"}, "first_start": {"type": "integer"}, "last_completion": {"type": "integer"},
            "progress": {"type": "object"}, "live": {"type": "object", "additionalProperties": {"type": "integer"}},
            "live_jobs": {"type": "integer"}, "live_truncated": {"type": "boolean"}, "finished": {"type": "object"},
            "hold_reasons": {"type": "array", "items": {"type": "object"}}, "dag": {"type": "object"},
            "workflows": {"type": "array", "items": {"type": "object"}}, "has_history": {"type": "boolean"}, "fetched_at": {"type": "integer"}}}}}},
          "400": {"description": "Bad batch id", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "Batch not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/batches/{batchId}/jobs": {
      "get": {
        "summary": "A batch's jobs, queued and finished",
        "description": "The batch's jobs in the queue and its history records in one list. Default order: the queue first by id, then the finished, latest first. Rows without the sort key sort last.",
        "operationId": "getBatchJobs",
        "parameters": [
          {"name": "batchId", "in": "path", "required": true, "schema": {"type": "integer", "minimum": 0}},
          {"name": "status", "in": "query", "schema": {"type": "string"}, "description": "Comma-separated: running, idle, uploading, transferring, held, suspended, completed, removed, unknown, live (every queued job), finished (every history record)."},
          {"name": "sort", "in": "query", "schema": {"type": "string", "enum": ["default", "id", "status", "submitted", "started", "finished", "runtime", "exit", "peak_memory"]}},
          {"name": "order", "in": "query", "schema": {"type": "string", "enum": ["asc", "desc"]}},
          {"name": "offset", "in": "query", "schema": {"type": "integer", "minimum": 0}},
          {"name": "page_size", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}}
        ],
        "responses": {
          "200": {"description": "One page of jobs.", "content": {"application/json": {"schema": {"type": "object", "properties": {
            "id": {"type": "integer"}, "total": {"type": "integer"}, "offset": {"type": "integer"}, "next_offset": {"type": "integer", "nullable": true},
            "live_truncated": {"type": "boolean"}, "history_truncated": {"type": "boolean"},
            "jobs": {"type": "array", "items": {"type": "object"}}}}}}},
          "400": {"description": "Bad batch id or query", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "Batch not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/utilization/for-job/{jobId}": {
      "get": {
        "summary": "The Utilization workflow of a job",
        "description": "The Utilization workflow a job -- waiting, running or finished -- belongs to, by the analysis's own identity and key, and whether that workflow has finished jobs in the last 30 days. Same scope as GET /jobs/{jobId}. Not available in multi-AP mode.",
        "operationId": "getUtilizationForJob",
        "parameters": [{"name": "jobId", "in": "path", "required": true, "schema": {"type": "string"}}],
        "responses": {
          "200": {"description": "The workflow.", "content": {"application/json": {"schema": {"type": "object", "properties": {
            "job_id": {"type": "string"}, "key": {"type": "string"}, "name": {"type": "string"}, "executable": {"type": "string"},
            "owner": {"type": "string"}, "has_history": {"type": "boolean", "nullable": true}}}}}},
          "400": {"description": "Bad job id", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "Job not found", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/jobs/runtime-estimates": {
      "post": {
        "summary": "Estimate how long many jobs will run",
        "description": "The runtime estimates of up to 5000 jobs in one request, for a listing: each shaped like GET /jobs/{jobId}/runtime-estimate without job_id and model, keyed by job id. Only jobs the caller may read that are waiting or running are answered; any other id (another user's job, a missing one, a held one) is absent. A read, authorized as one despite the POST. When the server has no estimator, or has not read its history yet, the answer is available false with reason disabled or model_warming_up and nothing is looked up.",
        "operationId": "getJobsRuntimeEstimates",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["jobs"],
                "properties": {
                  "jobs": {"type": "array", "maxItems": 5000, "items": {"type": "string"}, "description": "Job ids in cluster.proc format."}
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "The estimates, or why there are none",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "required": ["available"],
                  "properties": {
                    "available": {"type": "boolean"},
                    "reason": {"type": "string", "enum": ["disabled", "model_warming_up"]},
                    "estimates": {"type": "object", "additionalProperties": {"type": "object", "description": "The single-job estimate's fields: available, reason, estimate_seconds, p10_seconds, p90_seconds, basis, rough, elapsed_seconds, remaining_seconds, exceeded_history. A DAGMan job (or any scheduler- or local-universe job) is answered with available false and reason not_estimated."}},
                    "model": {
                      "type": "object",
                      "properties": {
                        "trained_through": {"type": "string", "format": "date-time"},
                        "jobs_ingested": {"type": "integer"}
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            "description": "Invalid body or job ID",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "401": {
            "description": "Not authenticated",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "413": {
            "description": "More than 5000 job ids",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "500": {
            "description": "Failed to query the jobs",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
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
        "description": "Query archived (completed) job records. Served from the schedd's history file, or from a synchronized htcondordb mirror when one is current and the schedd has identified the caller \u2014 the response's source field names which answered. With projection=* each record also carries the member \"evaluated\", as GET /jobs/{jobId} describes; a projected record does not, since an expression evaluated without the attributes it reads gives a wrong number.",
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
            "description": "Restrict the query to the authenticated user's own records. Default: false; always applied to a caller that is not an administrator, bearer token or browser session alike. It does not affect whether an htcondordb mirror may answer \u2014 that turns on the schedd having identified the caller, and a mirror read is confined exactly as the request was.",
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
    "/apps": {
      "get": {
        "summary": "List the caller's apps",
        "description": "Apps are long-lived servers running inside a job and reached through the job proxy. There is no registry: an app is a job marked by its JobBatchName, so this is a queue query. Deliberately does NOT probe whether each app is listening yet -- that costs a connection into the job -- so an app reported as 'running' may not be reachable for a few more seconds. Use GET /apps/{id} for that.",
        "operationId": "listApps",
        "responses": {
          "200": {"description": "The caller's apps", "content": {"application/json": {"schema": {
            "type": "object",
            "required": ["apps"],
            "properties": {"apps": {"type": "array", "items": {"$ref": "#/components/schemas/App"}}}
          }}}},
          "401": {"description": "Authentication required", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "Schedd query failed", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "post": {
        "summary": "Launch an app in the pool",
        "description": "Submits a container-universe job running a VS Code server on a Unix socket in its sandbox. Returns immediately, before the job has a slot: the app is 'waiting' until one is matched, then 'starting' until the server binds its socket. Poll GET /apps/{id}, which is the call that probes.",
        "operationId": "createApp",
        "requestBody": {
          "required": false,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "type":         {"type": "string", "description": "App type. Only \"code-server\" is implemented, and it is the default."},
                  "cpus":         {"type": "integer", "description": "CPU cores requested. Default 1", "minimum": 1, "maximum": 64},
                  "memory_mb":    {"type": "integer", "description": "Memory in MiB. Default 4096", "minimum": 256},
                  "disk_mb":      {"type": "integer", "description": "Scratch disk in MiB. Default 10240", "minimum": 256},
                  "image":        {"type": "string", "description": "Container image. Ignored when the operator has set HTTP_API_VSCODE_IMAGE, which wins outright."},
                  "workdir":      {"type": "string", "description": "Folder the editor opens. Defaults to the job's scratch directory."},
                  "submit_lines": {"type": "string", "description": "Extra submit commands. The ones that would redefine what the job is are refused."}
                }
              }
            }
          }
        },
        "responses": {
          "201": {"description": "Job submitted; no slot yet", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/App"}}}},
          "400": {"description": "Invalid request body, unknown app type, or a container universe with no image", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "401": {"description": "Authentication required", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "502": {"description": "Schedd refused the submit, or spooling the launcher failed", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      }
    },
    "/apps/{id}": {
      "get": {
        "summary": "Get one app, probing whether it is reachable",
        "description": "Unlike the list, this opens a connection into the job to see whether the server is listening, and reports 'starting' until it is. A running job is not the same as a reachable one.",
        "operationId": "getApp",
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
        "responses": {
          "200": {"description": "The app", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/App"}}}},
          "401": {"description": "Authentication required", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such app for this caller", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        }
      },
      "delete": {
        "summary": "End an app",
        "description": "Removes the app's job from the queue.",
        "operationId": "deleteApp",
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
        "responses": {
          "200": {"description": "Removed", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/App"}}}},
          "401": {"description": "Authentication required", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
          "404": {"description": "No such app for this caller", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
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
    "/pool/drain-estimates": {
      "get": {
        "summary": "When each execute node would be empty if drained now",
        "description": "For every execute node with running jobs (or that is draining): how long a drain started now would take to empty it. A drain lets each job run until it finishes or its retirement limit runs out, whichever is first. Retirement limits come from every claimed slot; expected finishing times exist only for jobs submitted from this access point, estimated from their owners' finished jobs. So a node whose jobs all have an estimate gets likely_empty_seconds; one with jobs from other access points gets at_least_seconds (the estimated part) and unknown_up_to_seconds (the latest retirement limit among the rest). The answer covers every user's jobs, is computed once for all callers, and is up to a minute old; seconds are counted from generated_at. Without ?machine the per-job slots are omitted. Not available in multi-AP mode.",
        "operationId": "getPoolDrainEstimates",
        "parameters": [
          {
            "name": "machine",
            "in": "query",
            "required": false,
            "description": "Answer for this one machine (its Machine attribute, case-insensitive), with a row per running job.",
            "schema": {"type": "string"}
          }
        ],
        "responses": {
          "200": {
            "description": "The estimates. When the latest refresh failed, the last good answer with stale true and error set.",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "required": ["generated_at", "age_seconds", "stale", "estimates_available", "summary", "machines"],
                  "properties": {
                    "generated_at": {"type": "string", "format": "date-time"},
                    "age_seconds": {"type": "number"},
                    "stale": {"type": "boolean", "description": "The latest refresh failed; this is the last answer that worked."},
                    "error": {"type": "string", "description": "Why the answer is stale, or why it has no runtime estimates."},
                    "estimates_available": {"type": "boolean", "description": "False when this access point does not estimate runtimes; the retirement bounds are still given."},
                    "access_point": {"type": "string", "description": "This access point's schedd name, as it appears in GlobalJobId."},
                    "summary": {
                      "type": "object",
                      "properties": {
                        "machines": {"type": "integer"},
                        "jobs_running": {"type": "integer"},
                        "jobs_estimated": {"type": "integer"},
                        "jobs_from_this_ap": {"type": "integer"},
                        "cores_freeing_next_hour": {"type": "number", "description": "Cores held by estimated jobs expected to finish on their own within the hour. Jobs from this access point only."},
                        "draining_nodes": {"type": "integer"},
                        "draining_likely_empty_within_2h": {"type": "integer", "description": "Draining nodes all of whose jobs are expected to be gone within two hours."}
                      }
                    },
                    "machines": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "machine": {"type": "string"},
                          "draining": {"type": "boolean"},
                          "jobs_total": {"type": "integer"},
                          "jobs_estimated": {"type": "integer"},
                          "jobs_from_this_ap": {"type": "integer"},
                          "jobs_unknown_end": {"type": "integer", "description": "Jobs with no estimate whose retirement limit is more than a minute away."},
                          "jobs_unknown_from_other_aps": {"type": "integer"},
                          "likely_empty_seconds": {"type": "number", "description": "When the jobs with a known end are expected to be gone; 0 for a node with nothing running; absent when no job has a known end."},
                          "likely_empty_at": {"type": "string", "format": "date-time"},
                          "at_least_seconds": {"type": "number", "description": "Present when some jobs have an unknown end: likely_empty_seconds is then only a lower bound."},
                          "at_most_seconds": {"type": "number", "description": "The latest a drain could take: the startd's ExpectedMachineGracefulDrainingCompletion, else the latest retirement deadline."},
                          "at_most_at": {"type": "string", "format": "date-time"},
                          "unknown_up_to_seconds": {"type": "number", "description": "The latest retirement deadline among the jobs with an unknown end."},
                          "evicted_on_drain": {"type": "integer", "description": "Jobs a drain now would evict: their retirement limit ends before they would, or within a minute."},
                          "exceeded": {"type": "integer", "description": "Jobs running longer than comparable jobs have."},
                          "expected_ends": {
                            "type": "array",
                            "items": {"type": "object", "properties": {"seconds": {"type": "number"}, "usually_by_seconds": {"type": "number"}, "cpus": {"type": "number"}}}
                          },
                          "slots": {
                            "type": "array",
                            "description": "Only with ?machine.",
                            "items": {
                              "type": "object",
                              "properties": {
                                "name": {"type": "string"},
                                "owner": {"type": "string", "description": "RemoteOwner"},
                                "cpus": {"type": "number"},
                                "backfill": {"type": "boolean"},
                                "submitted_from": {"type": "string", "description": "The schedd in the job's GlobalJobId."},
                                "from_this_ap": {"type": "boolean"},
                                "running_seconds": {"type": "number"},
                                "expected_end": {"type": "string", "format": "date-time"},
                                "usually_by": {"type": "string", "format": "date-time", "description": "When about 90% of comparable jobs have finished."},
                                "exceeded": {"type": "boolean"},
                                "retirement_deadline": {"type": "string", "format": "date-time"},
                                "evicted_on_drain": {"type": "boolean"}
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          "401": {
            "description": "Not authenticated",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "501": {
            "description": "No collector configured, or multi-AP mode",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          },
          "502": {
            "description": "The collector could not be read and there is no earlier answer",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
          }
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
	var schema map[string]any
	if err := json.Unmarshal([]byte(openAPISchema), &schema); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to parse OpenAPI schema")
		return
	}
	s.setOpenAPIOAuth2URLs(schema)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(schema); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode OpenAPI schema", "error", err)
	}
}

// setOpenAPIOAuth2URLs points the schema's OAuth2 security scheme at the
// endpoints this server advertises. The literal in openAPISchema names
// the /mcp/ spelling, which a server without MCP does not route.
func (s *Handler) setOpenAPIOAuth2URLs(schema map[string]any) {
	flow, ok := nestedMap(schema, "components", "securitySchemes", "oauth2", "flows", "authorizationCode")
	if !ok {
		return
	}
	flow["authorizationUrl"] = s.oauth2EndpointPath("authorize")
	flow["tokenUrl"] = s.oauth2EndpointPath("token")
}

// nestedMap walks m through the named keys, each of which must hold an
// object.
func nestedMap(m map[string]any, keys ...string) (map[string]any, bool) {
	for _, k := range keys {
		next, ok := m[k].(map[string]any)
		if !ok {
			return nil, false
		}
		m = next
	}
	return m, true
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
