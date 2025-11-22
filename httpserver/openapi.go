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
    }
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "TOKEN",
        "description": "HTCondor TOKEN authentication. The bearer token is used to authenticate with the schedd on behalf of the user."
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
            "description": "HTCondor submit file content"
          }
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
      }
    }
  },
  "paths": {
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
        "description": "Submit a new job to the schedd using SubmitRemote. Jobs are submitted with input file spooling enabled and start in HELD status until input files are uploaded.",
        "operationId": "submitJob",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/JobSubmitRequest"
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
        "description": "Query the HTCondor schedd for archived job records. Returns completed jobs from the history file.",
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
    }
  }
}`

// handleOpenAPISchema serves the OpenAPI schema
func (s *Server) handleOpenAPISchema(w http.ResponseWriter, r *http.Request) {
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
