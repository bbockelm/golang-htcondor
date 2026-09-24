package mcpserver

// Structured tool output (MCP spec revision 2026-07-28).
//
// The spec recommends a tool return `structuredContent` -- machine-readable
// data conforming to a published `outputSchema` -- alongside the curated
// human-readable text, so a client can drive logic off the result without
// re-parsing prose. This file adds both: withStructured attaches the data to
// a result, and outputSchemas publishes the schema, stamped onto the
// catalogue in toolsFor next to the annotations.
//
// The curated text block is never removed: downstream LLM clients rely on
// it, and the spec is explicit that structuredContent is *in addition to*,
// not a replacement for, the text. Because this server hand-builds every
// result (rather than deriving the text from a typed return value the way
// the SDK's high-level helper does), there is no auto-render trap -- the two
// fields are populated independently and cannot clobber each other.
//
// Schemas are intentionally permissive (additionalProperties allowed, few
// required fields): a job/history record is a ClassAd with an open attribute
// set, and a client validating structuredContent against these must not
// reject a result for carrying an attribute the schema did not enumerate.

// withStructured attaches structuredContent to a tool result map, leaving
// the existing content/metadata untouched. Returns the same map for chaining.
func withStructured(result map[string]interface{}, structured interface{}) map[string]interface{} {
	result["structuredContent"] = structured
	return result
}

// structuredTextResult builds a result carrying both the curated text and the
// structured data, for the many handlers that previously returned text only.
func structuredTextResult(text string, structured interface{}) interface{} {
	return map[string]interface{}{
		"content":           []map[string]interface{}{{"type": "text", "text": text}},
		"structuredContent": structured,
	}
}

// --- JSON Schema construction helpers -----------------------------------

func obj(props map[string]interface{}, required ...string) map[string]interface{} {
	s := map[string]interface{}{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": true,
	}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func arr(items map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"type": "array", "items": items}
}

var (
	strSchema  = map[string]interface{}{"type": "string"}
	intSchema  = map[string]interface{}{"type": "integer"}
	boolSchema = map[string]interface{}{"type": "boolean"}
	// adSchema is a single ClassAd: an object with an open attribute set.
	adSchema = map[string]interface{}{"type": "object", "additionalProperties": true}
	// anySchema is used where the payload is a nested structure this file
	// does not enumerate (e.g. the match-analysis Result).
	anySchema = map[string]interface{}{}
)

// dagSchema is the workflow progress get_job files under "dag" when the
// job is a DAGMan manager. Nothing is required: DAGMan publishes these
// only once it has parsed the DAG, so the first call after a submit
// legitimately carries only the manager job's own status.
var dagSchema = obj(map[string]interface{}{
	"job_status":        intSchema,
	"hold_reason_code":  intSchema,
	"dag_status":        intSchema,
	"dag_nodestotal":    intSchema,
	"dag_nodesdone":     intSchema,
	"dag_nodesready":    intSchema,
	"dag_nodesqueued":   intSchema,
	"dag_nodesfailed":   intSchema,
	"dag_nodesunready":  intSchema,
	"dag_nodesfutile":   intSchema,
	"dag_jobsidle":      intSchema,
	"dag_jobsrunning":   intSchema,
	"dag_jobsheld":      intSchema,
	"dag_jobscompleted": intSchema,
	"dag_file":          strSchema,
})

// jobListSchema is the shape shared by every tool that returns a set of job
// or history ads: the ads plus provenance and a truncation flag.
func jobListSchema(itemsKey string) map[string]interface{} {
	return obj(map[string]interface{}{
		itemsKey:     arr(adSchema),
		"count":      intSchema,
		"constraint": strSchema,
		"source":     strSchema,
		"has_more":   boolSchema,
	}, "count")
}

// outputSchemas publishes an output schema for each tool. A tool absent from
// this map is served without an outputSchema, which is valid -- structured
// output is recommended, not required. toolsFor stamps these onto the
// catalogue.
var outputSchemas = map[string]map[string]interface{}{
	// --- job-query family: sets of ads -------------------------------
	"query_jobs":             jobListSchema("jobs"),
	"query_history_db":       jobListSchema("records"),
	"query_jobs_as_of":       jobListSchema("records"),
	"query_job_archive":      jobListSchema("records"),
	"query_job_epochs":       jobListSchema("records"),
	"query_transfer_history": jobListSchema("records"),
	"get_job": obj(map[string]interface{}{
		"job":    adSchema,
		"job_id": strSchema,
		// Present only on a DAGMan manager job, which is why it is not
		// required. Open for the same reason the ad itself is: DAGMan
		// publishes a set of progress attributes that grows between
		// releases, and a client that rejected a result carrying a new
		// one would break on a pool upgrade.
		"dag": dagSchema,
	}, "job_id"),

	// --- aggregate ----------------------------------------------------
	"aggregate_jobs": obj(map[string]interface{}{
		"groups": arr(obj(map[string]interface{}{
			"key":   arr(strSchema),
			"count": strSchema,
		})),
		"group_by":  arr(strSchema),
		"table":     strSchema,
		"source":    strSchema,
		"truncated": boolSchema,
	}),

	// analyze_issues answers in clusters, and the shape is what makes it
	// usable without re-reading the prose: an agent deciding whether to
	// tell one user or raise a ticket wants count and users, not the
	// sentence they were rendered into.
	"analyze_issues": obj(map[string]interface{}{
		"window_seconds": intSchema,
		"granularity":    anySchema,
		"include_ended":  boolSchema,
		"source":         strSchema,
		"truncated":      boolSchema,
		"notes":          arr(strSchema),
		"sections": arr(obj(map[string]interface{}{
			"kind":  strSchema,
			"title": strSchema,
			"total": intSchema,
			"users": intSchema,
			"clusters": arr(obj(map[string]interface{}{
				"kind":     strSchema,
				"template": strSchema,
				"count":    intSchema,
				"users":    intSchema,
				"top_users": arr(obj(map[string]interface{}{
					"owner": strSchema,
					"count": intSchema,
				})),
				"codes": arr(obj(map[string]interface{}{
					"code":    intSchema,
					"subcode": intSchema,
					"label":   strSchema,
					"count":   intSchema,
				})),
				"facets": arr(obj(map[string]interface{}{
					"name":     strSchema,
					"distinct": intSchema,
					"top": arr(obj(map[string]interface{}{
						"value": strSchema,
						"count": intSchema,
					})),
				})),
				"first_seen": intSchema,
				"last_seen":  intSchema,
				"examples": arr(obj(map[string]interface{}{
					"cluster_id": intSchema,
					"proc_id":    intSchema,
					"owner":      strSchema,
					"batch":      strSchema,
					"at":         intSchema,
					"message":    strSchema,
				})),
				"variants": arr(obj(map[string]interface{}{
					"template": strSchema,
					"count":    intSchema,
				})),
			})),
		})),
	}),

	// --- match analysis ----------------------------------------------
	"analyze_job_match": obj(map[string]interface{}{
		"job_id":       strSchema,
		"requirements": strSchema,
		"result":       anySchema,
		"slot_cache":   anySchema,
	}, "job_id"),

	// --- submit / mutate ---------------------------------------------
	// submit_dag reports what it staged and what the caller still owes,
	// so an agent can act on the outstanding work without re-reading prose.
	"submit_dag": obj(map[string]interface{}{
		"cluster_id":  intSchema,
		"job_id":      strSchema,
		"dag_name":    strSchema,
		"input_files": arr(strSchema),
		"notes":       arr(strSchema),
		"deferred":    arr(strSchema),
		// The constraint that matches the workflow's node jobs. They are
		// not in the manager's cluster, so nothing else in this payload
		// finds them.
		"node_constraint": strSchema,
		"dry_run":         boolSchema,
		"submit_file":     strSchema,
		// A dry run reports a workflow that cannot start rather than
		// refusing it, so it needs somewhere to say so.
		"fatal":  boolSchema,
		"errors": arr(strSchema),
	}),
	"submit_job": obj(map[string]interface{}{
		"cluster_id":   intSchema,
		"job_ids":      arr(strSchema),
		"proc_count":   intSchema,
		"needs_upload": boolSchema,
		"warnings":     arr(strSchema),
	}, "cluster_id"),
	// build_container returns the submitted job plus the resolved
	// destination and resources, so a caller can see what the site
	// defaults and caps turned its request into.
	"build_container": obj(map[string]interface{}{
		"cluster_id":  intSchema,
		"job_id":      strSchema,
		"name":        strSchema,
		"destination": strSchema,
		"verify":      strSchema,
		"cpus":        intSchema,
		"memory_mb":   intSchema,
		"disk_mb":     intSchema,
	}, "cluster_id", "job_id", "destination"),
	"remove_job":  jobActionSchema(),
	"hold_job":    jobActionSchema(),
	"release_job": jobActionSchema(),
	"remove_jobs": obj(map[string]interface{}{
		"action":            strSchema,
		"constraint":        strSchema,
		"total":             intSchema,
		"success":           intSchema,
		"permission_denied": intSchema,
		"not_found":         intSchema,
	}, "action"),
	"edit_job": obj(map[string]interface{}{
		"job_id":     strSchema,
		"attributes": adSchema,
		"notes":      arr(strSchema),
	}, "job_id"),
	"advertise_to_collector": obj(map[string]interface{}{
		"advertised": boolSchema,
		"ad_name":    strSchema,
		"ad_type":    strSchema,
		"with_ack":   boolSchema,
	}, "advertised"),

	// --- sandbox in/out ----------------------------------------------
	"get_job_stdout": jobOutputStreamSchema(),
	"get_job_stderr": jobOutputStreamSchema(),
	"get_job_output": obj(map[string]interface{}{
		"job_id":     strSchema,
		"file_count": intSchema,
		"files": arr(obj(map[string]interface{}{
			"filename":     strSchema,
			"size":         intSchema,
			"is_base64":    boolSchema,
			"is_truncated": boolSchema,
			"url":          strSchema,
			"data":         strSchema,
		})),
	}, "job_id", "file_count"),
	// Two shapes share this tool: a single-proc upload (job_id/...) and a
	// cluster-wide fan-out (cluster_id/procs_*). The schema is the union,
	// with nothing required.
	"upload_job_input": obj(map[string]interface{}{
		"job_id":          strSchema,
		"files":           arr(strSchema),
		"file_count":      intSchema,
		"total_size":      intSchema,
		"released":        boolSchema,
		"cluster_id":      intSchema,
		"procs_spooled":   intSchema,
		"procs_remaining": intSchema,
		"procs_failed":    intSchema,
	}),

	"create_watch_url": obj(map[string]interface{}{
		"url":                  strSchema,
		"watch_id":             strSchema,
		"owner":                strSchema,
		"event":                strSchema,
		"label":                strSchema,
		"expires_at":           strSchema,
		"ttl_seconds":          intSchema,
		"max_wait_seconds":     intSchema,
		"default_wait_seconds": intSchema,
	}, "url", "watch_id"),

	"create_input_upload_url": obj(map[string]interface{}{
		"cluster_id":  intSchema,
		"owner":       strSchema,
		"expires_at":  strSchema,
		"ttl_seconds": intSchema,
		"count":       intSchema,
		// One entry per proc: HTCondor spools per proc, and the allow-set
		// is per proc too.
		"uploads": arr(obj(map[string]interface{}{
			"job_id":         strSchema,
			"url":            strSchema,
			"expected_files": arr(strSchema),
		})),
		"procs_remaining": intSchema,
		"note":            strSchema,
	}, "cluster_id", "count", "uploads"),

	// --- credentials --------------------------------------------------
	"list_service_credentials": obj(map[string]interface{}{
		"credentials": arr(obj(map[string]interface{}{
			"service":    strSchema,
			"handle":     strSchema,
			"exists":     boolSchema,
			"updated_at": strSchema,
		})),
		"count": intSchema,
	}, "count"),
	"get_credential_status": obj(map[string]interface{}{
		"service":    strSchema,
		"handle":     strSchema,
		"exists":     boolSchema,
		"updated_at": strSchema,
	}, "service", "exists"),
	"store_service_credential": obj(map[string]interface{}{
		"service": strSchema,
		"handle":  strSchema,
		"stored":  boolSchema,
	}, "service", "stored"),
	"delete_service_credential": obj(map[string]interface{}{
		"service": strSchema,
		"handle":  strSchema,
		"deleted": boolSchema,
	}, "service", "deleted"),

	// --- documentation & skills --------------------------------------
	// Every condor_doc_* tool funnels through toolCondorDocSearch and
	// returns the same snippet-search shape.
	"condor_doc_search":             docSearchSchema(),
	"condor_doc_job_attributes":     docSearchSchema(),
	"condor_doc_machine_attributes": docSearchSchema(),
	"condor_doc_submit_syntax":      docSearchSchema(),
	"condor_doc_config_variables":   docSearchSchema(),
	"skills_list": obj(map[string]interface{}{
		"skills": arr(obj(map[string]interface{}{
			"name":        strSchema,
			"description": strSchema,
		})),
		"count": intSchema,
	}, "count"),
	"skills_get": obj(map[string]interface{}{
		"name":        strSchema,
		"description": strSchema,
		"content":     strSchema,
	}, "name"),

	// --- watches ------------------------------------------------------
	"watch_jobs": obj(map[string]interface{}{
		"watch_id":   strSchema,
		"event":      strSchema,
		"constraint": strSchema,
		"fired":      boolSchema,
		// How long this call blocked, and how long the watch has existed
		// (they differ once a watch outlives the call that made it).
		"blocked_seconds":   intSchema,
		"watch_age_seconds": intSchema,
		// Fired because the state can no longer occur rather than
		// because it happened -- "it never ran", not "it ran".
		"unsatisfiable": boolSchema,
	}, "watch_id"),
	"check_watches": obj(map[string]interface{}{
		"watches": arr(adSchema),
		"count":   intSchema,
		// How long this CALL blocked, as against each watch's own
		// waited_seconds, which is how long that watch has been open.
		"blocked_seconds": intSchema,
		"new_count":       intSchema,
		"waiting_count":   intSchema,
	}, "count"),
	"cancel_watch": obj(map[string]interface{}{
		"watch_id":  strSchema,
		"cancelled": boolSchema,
	}, "cancelled"),

	// --- interactive sessions & live-job reach -----------------------
	"interactive_session_start": obj(map[string]interface{}{
		"session":    strSchema,
		"job_id":     strSchema,
		"job_status": intSchema,
		"status":     strSchema,
	}, "session"),
	"interactive_session_exec": obj(map[string]interface{}{
		"job_id":    strSchema,
		"stdout":    strSchema,
		"stderr":    strSchema,
		"exit_code": intSchema,
	}, "job_id"),
	"interactive_session_list": obj(map[string]interface{}{
		"sessions": arr(adSchema),
		"count":    intSchema,
	}, "count"),
	"interactive_session_stop": obj(map[string]interface{}{
		"session": strSchema,
		"job_id":  strSchema,
		"stopped": boolSchema,
	}, "stopped"),
	"exec_in_job": obj(map[string]interface{}{
		"job_id":    strSchema,
		"stdout":    strSchema,
		"stderr":    strSchema,
		"exit_code": intSchema,
	}, "job_id"),
	"tail_job_output": obj(map[string]interface{}{
		"job_id":        strSchema,
		"stdout":        strSchema,
		"stderr":        strSchema,
		"stdout_offset": intSchema,
		"stderr_offset": intSchema,
	}, "job_id"),

	// --- version ------------------------------------------------------
	// structuredContent is the version.Build struct verbatim; its field set
	// is owned by that package, so the schema stays open.
	"get_version": obj(map[string]interface{}{
		"Module":   strSchema,
		"Revision": strSchema,
		"Dirty":    boolSchema,
	}),

	// Mirrors whoamiReport field for field. oauth_scopes is the list of
	// scope strings the token carries, not an object: the schema said
	// object, which no caller could have discovered while the tool was
	// returning no structured content at all.
	"whoami": obj(map[string]interface{}{
		"authenticated_user": strSchema,
		"admin":              boolSchema,
		"superuser":          boolSchema,
		"admin_via":          strSchema,
		"superuser_via":      strSchema,
		"job_visibility":     strSchema,
		"confined_to_owner":  strSchema,
		"access_point":       strSchema,
		"oauth_scopes":       arr(strSchema),
	}),
}

// jobActionSchema is the result shape for the single-job control tools
// (remove_job / hold_job / release_job).
func jobActionSchema() map[string]interface{} {
	return obj(map[string]interface{}{
		"job_id":  strSchema,
		"action":  strSchema,
		"success": boolSchema,
	}, "job_id", "action", "success")
}

// jobOutputStreamSchema is the result shape for get_job_stdout/get_job_stderr.
func jobOutputStreamSchema() map[string]interface{} {
	return obj(map[string]interface{}{
		"job_id":      strSchema,
		"output_type": strSchema,
		"filename":    strSchema,
		"size":        intSchema,
		"empty":       boolSchema,
		"content":     strSchema,
	}, "job_id", "output_type")
}

// docSearchSchema is the result shape shared by every condor_doc_* tool:
// a set of snippet hits, each carrying page/source/line provenance.
func docSearchSchema() map[string]interface{} {
	return obj(map[string]interface{}{
		"query": strSchema,
		"results": arr(obj(map[string]interface{}{
			"page":         strSchema,
			"source":       strSchema,
			"line":         intSchema,
			"matched_line": intSchema,
			"snippet":      strSchema,
		})),
		"count": intSchema,
	}, "count")
}

// outputSchemaFor returns the published output schema for a tool, or nil.
func outputSchemaFor(name string) map[string]interface{} {
	return outputSchemas[name]
}
