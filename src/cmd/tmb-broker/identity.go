package main

import "fmt"

// RequesterKind enumerates how a listener authenticated the requester.
type RequesterKind string

const (
	// KindUID: unix-socket listener, kernel SO_PEERCRED credentials.
	KindUID RequesterKind = "uid"
	// KindKeyFP: TLS listener, SHA-256 fingerprint of the client
	// certificate's public key (DER SubjectPublicKeyInfo, lowercase hex, no
	// colons): it survives reissuing the certificate on the same key.
	KindKeyFP RequesterKind = "keyfp"
)

// RequesterID is the opaque identity of a requester, selected per-listener
// (uid via SO_PEERCRED on the unix path, public key fingerprint on the TLS
// path). The approval, token, claim-store and log mechanics receive only
// this value - they never see *syscall.Ucred, a raw uid, or the transport.
type RequesterID struct {
	Kind RequesterKind
	UID  uint32 // Kind == KindUID: SO_PEERCRED uid
	PID  uint32 // Kind == KindUID: SO_PEERCRED pid; display-only, not part of identity
	FP   string // Kind == KindKeyFP: hex SHA-256 of the client key SPKI
}

// UIDRequester builds the identity of a unix-socket peer.
func UIDRequester(uid, pid uint32) RequesterID {
	return RequesterID{Kind: KindUID, UID: uid, PID: pid}
}

// KeyRequester builds the identity of a TLS peer from the lowercase hex
// SHA-256 fingerprint of its public key.
func KeyRequester(fp string) RequesterID {
	return RequesterID{Kind: KindKeyFP, FP: fp}
}

// Equal reports whether two identities denote the same requester. The
// SO_PEERCRED pid is display metadata only (approve and claim routinely come
// from different processes of the same uid), so it is excluded.
func (id RequesterID) Equal(other RequesterID) bool {
	if id.Kind != other.Kind {
		return false
	}
	switch id.Kind {
	case KindUID:
		return id.UID == other.UID
	case KindKeyFP:
		return id.FP == other.FP
	}
	return false
}

// Key is the stable string form of the identity used in claim-store metadata.
func (id RequesterID) Key() string {
	switch id.Kind {
	case KindUID:
		return fmt.Sprintf("uid:%d", id.UID)
	case KindKeyFP:
		return "keyfp:" + id.FP
	}
	return fmt.Sprintf("unknown:%s", id.Kind)
}

// LogFields returns the JSONL identity fields for this requester. Field
// names are stable API: requester_uid/requester_pid on the unix path,
// requester_fp (key fingerprint) on the TLS path.
func (id RequesterID) LogFields() map[string]any {
	switch id.Kind {
	case KindUID:
		return map[string]any{"requester_uid": id.UID, "requester_pid": id.PID}
	case KindKeyFP:
		return map[string]any{"requester_fp": id.FP}
	}
	return map[string]any{}
}

// ConsoleLine renders the requester for the manual approval console. The
// uid rendering is byte-stable (the N-series scenario registry checks it);
// the key rendering shows the first 16 hex chars of the fingerprint.
func (id RequesterID) ConsoleLine() string {
	switch id.Kind {
	case KindUID:
		return fmt.Sprintf("uid=%d pid=%d (kernel SO_PEERCRED)", id.UID, id.PID)
	case KindKeyFP:
		fp := id.FP
		if len(fp) > 16 {
			fp = fp[:16]
		}
		return fmt.Sprintf("key fp=%s", fp)
	}
	return "unknown"
}

// NotAllowedDetail is the deny detail shown when the identity misses the
// broker allowlist. The uid wording is byte-stable.
func (id RequesterID) NotAllowedDetail() string {
	switch id.Kind {
	case KindUID:
		return fmt.Sprintf("uid %d is not in the broker allowlist", id.UID)
	case KindKeyFP:
		return fmt.Sprintf("key fp %s is not in the broker allowlist", id.FP)
	}
	return "requester not in the broker allowlist"
}
