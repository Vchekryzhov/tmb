// PROTOTYPE CODE - throwaway PoC, not production.
package main

// Field types of the journal schema, as docs/audit-schema.md names them.
const (
	tString   = "string"
	tInt      = "integer"
	tBool     = "boolean"
	tStrings  = "array of string"
	tInts     = "array of integer"
	tStrMap   = "object of string"
	tAnyValue = "any"
)

// auditCommonFields are written into every event by the Logger.
var auditCommonFields = map[string]string{
	"schema": tInt,
	"ts":     tString,
	"event":  tString,
}

// requesterFields are RequesterID.LogFields: requester_uid and
// requester_pid on the unix path, requester_fp on the TLS path.
var requesterFields = map[string]string{
	"requester_uid": tInt,
	"requester_pid": tInt,
	"requester_fp":  tString,
}

// approverFields are approverLogFields: the approver socket peer, never
// written as requester_* (CONTEXT.md keeps the two roles apart).
var approverFields = map[string]string{
	"approver_uid": tInt,
	"approver_pid": tInt,
}

// withApprover adds the approver fields to an event's own fields.
func withApprover(own map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range approverFields {
		out[k] = v
	}
	for k, v := range own {
		out[k] = v
	}
	return out
}

// withRequester adds the requester fields to an event's own fields.
func withRequester(own map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range requesterFields {
		out[k] = v
	}
	for k, v := range own {
		out[k] = v
	}
	return out
}

// auditEvents is the register of journal events: every event the broker
// writes and its fields (beyond auditCommonFields) with their types.
// docs/audit-schema.md documents exactly this set; TestAuditSchemaDoc and
// TestAuditSchemaCode hold the document, this register and the code
// together. Changing the fields of an existing event raises
// auditSchemaVersion (TestAuditSchemaVersion holds the frozen sets).
var auditEvents = map[string]map[string]string{
	"broker_start": {
		"pid": tInt, "socket": tString, "mode": tString, "ttl_seconds": tInt,
		"allowed_requester_uids": tInts, "allowed_requester_keys": tStrings, "tls_addr": tString,
		"host_id": tString, "host_key": tString,
	},
	"broker_stop":          {"pid": tInt},
	"tls_listen":           {"addr": tString},
	"claim_gc":             {"removed": tInt, "skipped": tInt, "error": tString},
	"claim_gc_skipped":     {"file": tString, "error": tString},
	"peercred_error":       {"error": tString, "socket": tString},
	"tls_handshake_failed": {"remote": tString, "error": tString},
	"tls_no_client_cert":   {"remote": tString},
	"requester_denied":     withRequester(map[string]string{"reason": tString}),
	"bad_frame":            withRequester(withApprover(map[string]string{"error": tString})),
	"bad_request":          withRequester(map[string]string{"error": tString}),
	"request": withRequester(map[string]string{
		"transport": tString, "type": tString, "executable": tString, "argv": tStrings,
		"cwd": tString, "uid": tInt, "env": tStrMap, "nonce": tString, "hash": tString, "claim_token": tString,
	}),
	"deny": withRequester(map[string]string{
		"executable": tString, "argv": tStrings, "nonce": tString, "hash": tString, "reason": tString, "detail": tString,
	}),
	"queued": withRequester(map[string]string{
		"item": tString, "hash": tString, "executable": tString, "argv": tStrings, "cwd": tString, "nonce": tString,
		"short_code": tString,
	}),
	"approval_timeout":  withRequester(map[string]string{"item": tString, "wait_seconds": tInt}),
	"request_abandoned": withRequester(map[string]string{"item": tString, "wait_seconds": tInt}),
	"approver_denied":   withApprover(map[string]string{"reason": tString}),
	"decision_rejected": withApprover(map[string]string{"item": tString, "reason": tString, "approver_key": tString}),
	"queue_list_failed": withApprover(map[string]string{"error": tString}),
	"approval": withRequester(map[string]string{
		"mode": tString, "approver": tString, "decision": tString, "result": tString, "reason": tString,
		"executable": tString, "argv": tStrings, "nonce": tString, "hash": tString,
		"short_code": tString, "payload": tString, "signed": tBool, "approver_keys": tStrings,
		"approver_key_classes": tStrings, "approver_key_names": tStrings, "signatures": tStrings,
	}),
	"claim": withRequester(map[string]string{
		"token": tString, "hash": tString, "nonce": tString, "executable": tString, "result": tString,
	}),
	"exec_start": withRequester(map[string]string{
		"token": tString, "executable": tString, "argv": tStrings, "cwd": tString, "uid": tInt,
		"env_count": tInt, "exe_via_fd": tBool, "exe_dev": tInt, "exe_ino": tInt,
		"cwd_verified": tBool, "cwd_via_fd": tBool,
	}),
	"exec_fail": {"token": tString, "error": tString},
	"exec_exit": withRequester(map[string]string{
		"token": tString, "executable": tString, "exit_status": tInt, "duration_ms": tInt,
		"client_gone": tBool,
	}),
	"reload":               {"pid": tInt, "changed": tStrings, "ignored": tStrings},
	"reload_failed":        {"pid": tInt, "error": tString},
	"reload_ignored_field": {"field": tString, "running": tAnyValue, "config": tAnyValue},
	"audit_unavailable":    {"pid": tInt, "path": tString, "error": tString},
}
