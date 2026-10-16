// PROTOTYPE CODE - throwaway PoC, not production.
//
// tmb-broker: privileged side of the TMB PoC. Listens on a unix socket,
// authenticates the requester via SO_PEERCRED, gets human (or mocked)
// approval for the EXACT request tuple, and executes exactly one confirmed
// command per approval with no shell in the exec path.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"tmb-poc/internal/proto"
)

// Approval modes.
const (
	ModeManual      = "manual"
	ModeMockApprove = "mock-approve"
	ModeMockDeny    = "mock-deny"
	ModeMockTimeout = "mock-timeout"
)

// pendingApproval is an approval bound to one exact request hash AND to the
// requester identity that asked for it.
type pendingApproval struct {
	Hash      string
	Expiry    time.Time
	ExePath   string // realpath at approval time
	ExeDev    uint64
	ExeIno    uint64
	ExeFile   *os.File // read-only fd pinned to ExeDev/ExeIno at approval (linux); nil once closed
	CwdReal   string
	CwdDev    uint64 // cwd directory identity pinned at approval (linux)
	CwdIno    uint64
	CwdFile   *os.File // O_DIRECTORY fd held on CwdDev/CwdIno until exec (linux); nil once closed
	CwdPinned bool
	Requester RequesterID
}

// closePins releases the pinned exe and cwd fds (idempotent). Every path
// that drops or finishes a pending approval calls this, so pins never leak.
func (p *pendingApproval) closePins() {
	if p.ExeFile != nil {
		p.ExeFile.Close()
		p.ExeFile = nil
	}
	if p.CwdFile != nil {
		p.CwdFile.Close()
		p.CwdFile = nil
	}
}

type Broker struct {
	cfg    *Config
	mode   string
	ttl    time.Duration
	log    *Logger
	claims *ClaimStore

	mu      sync.Mutex // guards pending + manual prompt serialization
	pending map[string]*pendingApproval

	stdin   *bufio.Reader // broker console stdin (manual approval)
	console io.Writer     // broker console output (manual approval)

	queue *approvalQueue // queue mode: requests waiting for an approver
}

func NewBroker(cfg *Config, log *Logger, claims *ClaimStore, mode string, ttl time.Duration) *Broker {
	return &Broker{
		cfg:     cfg,
		mode:    mode,
		ttl:     ttl,
		log:     log,
		claims:  claims,
		pending: map[string]*pendingApproval{},
		stdin:   bufio.NewReader(os.Stdin),
		console: os.Stdout,
		queue:   newApprovalQueue(),
	}
}

// allowedRequester checks the identity against the broker allowlist. The
// allowlist entries are per-kind: uids for SO_PEERCRED identities,
// certificate fingerprints for TLS identities.
func (b *Broker) allowedRequester(id RequesterID) bool {
	switch id.Kind {
	case KindUID:
		for _, u := range b.cfg.AllowedRequesterUIDs {
			if u == id.UID {
				return true
			}
		}
	case KindCertFP:
		for _, fp := range b.cfg.AllowedRequesterFPs {
			if fp == id.FP {
				return true
			}
		}
	}
	return false
}

func (b *Broker) envKeyAllowed(k string) bool {
	for _, a := range b.cfg.AllowedEnvKeys {
		if a == k {
			return true
		}
	}
	return false
}

// maxEnvValue bounds one requested env value, so the approval display and
// the audit log never carry an oversized value.
const maxEnvValue = 4096

// checkEnv applies the env policy to the requested keys in sorted order (a
// stable verdict for a multi-key request). Per key: syntax, PATH, then
// fixed_env (a fixed key is never editable, even if it is also
// allowlisted), then the allowlist; then the value: single line, no NUL, at most maxEnvValue bytes.
func (b *Broker) checkEnv(env map[string]string) (deny, detail string) {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := env[k]
		switch {
		case k == "" || strings.ContainsAny(k, "=\x00"):
			return "env_key_invalid", fmt.Sprintf("%q", k)
		case k == "PATH": // never requestable, whatever fixed_env says
			return "env_key_not_allowed", k
		case b.envKeyFixed(k):
			return "env_fixed_key", k
		case !b.envKeyAllowed(k):
			return "env_key_not_allowed", k
		case strings.ContainsAny(v, "\x00\n"):
			return "env_value_invalid", k + ": value contains NUL or a newline"
		case len(v) > maxEnvValue:
			return "env_value_too_long", fmt.Sprintf("%s: %d bytes, limit %d", k, len(v), maxEnvValue)
		}
	}
	return "", ""
}

func (b *Broker) envKeyFixed(k string) bool {
	_, fixed := b.cfg.FixedEnv[k]
	return fixed
}

// cwdAllowed reports whether a realpath'd cwd equals one of the configured
// roots or lies below one. Roots are realpaths already (normalizeCwdRoots);
// an empty list allows nothing.
func (b *Broker) cwdAllowed(cwdReal string) bool {
	for _, root := range b.cfg.AllowedCwdRoots {
		if cwdReal == root || strings.HasPrefix(cwdReal, strings.TrimSuffix(root, "/")+"/") {
			return true
		}
	}
	return false
}

// shellDenied checks both the raw path and the realpath against the deny
// list (entries themselves resolved, so /bin/sh -> /usr/bin/dash matches).
func (b *Broker) shellDenied(rawPath, realPath string) bool {
	set := map[string]bool{}
	for _, e := range b.cfg.ShellDenyList {
		set[e] = true
		if rp, err := filepath.EvalSymlinks(e); err == nil {
			set[rp] = true
		}
	}
	return set[rawPath] || set[realPath]
}

// Serve runs the accept loop.
func (b *Broker) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go b.handleConn(conn.(*net.UnixConn))
	}
}

func (b *Broker) handleConn(conn *net.UnixConn) {
	defer conn.Close()

	// SO_PEERCRED on EVERY connection, before reading anything.
	id, err := peerCred(conn)
	if err != nil {
		b.log.Event("peercred_error", map[string]any{"error": err.Error()})
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "peercred_failed", Detail: err.Error()})
		return
	}
	if !b.allowedRequester(id) {
		b.denyRequesterNotAllowed(conn, id)
		return
	}
	b.serveRequest(conn, id, "unix")
}

func (b *Broker) serveRequest(conn net.Conn, id RequesterID, transport string) {
	raw, err := proto.ReadRawFrame(conn)
	if err != nil {
		ev := id.LogFields()
		ev["error"] = err.Error()
		b.log.Event("bad_frame", ev)
		return
	}
	req, err := proto.DecodeRequest(raw)
	if err != nil {
		ev := id.LogFields()
		ev["error"] = err.Error()
		b.log.Event("bad_request", ev)
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "bad_request", Detail: err.Error()})
		return
	}
	req.Nonce = strings.TrimSpace(req.Nonce)

	ev := id.LogFields()
	ev["transport"] = transport
	ev["type"] = req.Type
	ev["executable"] = req.Executable
	ev["argv"] = req.Argv
	ev["cwd"] = req.Cwd
	ev["uid"] = req.UID
	ev["env"] = req.Env
	ev["nonce"] = short(req.Nonce, 12)
	ev["claim_token"] = req.ClaimToken
	b.log.Event("request", ev)

	switch req.Type {
	case "approve":
		b.doApprove(req, id, conn)
	case "claim":
		b.doClaim(req, id, conn)
	case "exec":
		// approve + claim + exec from the SAME in-memory request object
		if !b.approveStage(req, id, conn) {
			return
		}
		hash := req.Hash()
		proto.WriteFrame(conn, &proto.Frame{Type: "approved",
			Token:  proto.TokenID(hash),
			Detail: fmt.Sprintf("one-shot token, ttl=%s", b.ttl)})
		req.ClaimToken = proto.TokenID(hash) // broker-side binding
		b.claimStage(req, id, conn)
	default:
		b.deny(req, id, "unknown_request_type", req.Type, conn)
	}
}

func (b *Broker) deny(req *proto.Request, id RequesterID, reason, detail string, conn net.Conn) {
	ev := id.LogFields()
	ev["executable"] = req.Executable
	ev["argv"] = req.Argv
	ev["nonce"] = short(req.Nonce, 12)
	ev["reason"] = reason
	ev["detail"] = detail
	b.log.Event("deny", ev)
	proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: reason, Detail: detail})
}

// denyDrainTimeout bounds how long a denied connection may take to deliver
// its request frame before the denial is sent anyway.
const denyDrainTimeout = 500 * time.Millisecond

// denyRequesterNotAllowed rejects a connection whose identity failed the
// allowlist check: requester_denied JSONL event, then the denied frame with
// the identity's detail. Shared by the unix and TLS listeners (which is why
// it takes net.Conn); the caller's defer closes the connection.
func (b *Broker) denyRequesterNotAllowed(conn net.Conn, id RequesterID) {
	ev := id.LogFields()
	ev["reason"] = "requester_not_allowed"
	b.log.Event("requester_denied", ev)
	// Consume (never parse) the request the client is sending: answering and
	// closing first races its write, and a fast client then sees EPIPE or a
	// reset instead of this denial. Bounded by MaxFrame and a short deadline.
	_ = conn.SetReadDeadline(time.Now().Add(denyDrainTimeout))
	_, _ = proto.ReadRawFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "requester_not_allowed",
		Detail: id.NotAllowedDetail()})
}

// --- validation -----------------------------------------------------------

// validateRequest performs all request-shape and policy checks and returns
// the resolved real paths + stat identity. Deny codes are stable strings.
func (b *Broker) validateRequest(req *proto.Request) (exeReal, cwdReal string, dev, ino uint64, deny string, detail string) {
	if !filepath.IsAbs(req.Executable) {
		return "", "", 0, 0, "executable_not_absolute", req.Executable
	}
	if len(req.Argv) == 0 {
		return "", "", 0, 0, "argv_empty", ""
	}
	if len(req.Argv) > 128 {
		return "", "", 0, 0, "argv_too_long", fmt.Sprintf("%d elements", len(req.Argv))
	}
	for _, a := range req.Argv {
		if len(a) > 8192 {
			return "", "", 0, 0, "argv_too_long", "element exceeds 8192 bytes"
		}
	}
	if req.UID != 0 {
		return "", "", 0, 0, "uid_not_supported", fmt.Sprintf("uid %d requested; PoC supports only uid 0", req.UID)
	}
	if deny, detail := b.checkEnv(req.Env); deny != "" {
		return "", "", 0, 0, deny, detail
	}
	if len(req.Env) > 32 {
		return "", "", 0, 0, "env_too_many", ""
	}
	if req.Nonce == "" || len(req.Nonce) > 128 {
		return "", "", 0, 0, "nonce_invalid", short(req.Nonce, 16)
	}
	if req.Cwd == "" {
		req.Cwd = "/tmp"
	}
	if !filepath.IsAbs(req.Cwd) {
		return "", "", 0, 0, "cwd_not_absolute", req.Cwd
	}

	exeReal, err := filepath.EvalSymlinks(req.Executable)
	if err != nil {
		return "", "", 0, 0, "executable_not_found", req.Executable
	}
	st, err := os.Stat(exeReal)
	if err != nil || !st.Mode().IsRegular() {
		return "", "", 0, 0, "executable_not_regular", exeReal
	}
	sti, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", "", 0, 0, "executable_stat_failed", exeReal
	}
	dev, ino = uint64(sti.Dev), uint64(sti.Ino)
	if b.shellDenied(req.Executable, exeReal) {
		return "", "", 0, 0, "shell_policy", exeReal
	}
	cwdReal, err = filepath.EvalSymlinks(req.Cwd)
	if err != nil {
		return "", "", 0, 0, "cwd_invalid", req.Cwd
	}
	if st2, err := os.Stat(cwdReal); err != nil || !st2.IsDir() {
		return "", "", 0, 0, "cwd_invalid", cwdReal
	}
	if !b.cwdAllowed(cwdReal) {
		return "", "", 0, 0, "cwd_not_allowed", cwdReal
	}
	return exeReal, cwdReal, dev, ino, "", ""
}

// --- approval -------------------------------------------------------------

func (b *Broker) doApprove(req *proto.Request, id RequesterID, conn net.Conn) {
	if !b.approveStage(req, id, conn) {
		return
	}
	proto.WriteFrame(conn, &proto.Frame{Type: "approved",
		Token:  proto.TokenID(req.Hash()),
		Detail: fmt.Sprintf("one-shot token, ttl=%s", b.ttl)})
}

// approveStage validates, runs the approval interaction, and on grant stores
// a pending approval bound to the requester identity. Returns false when a
// deny frame has been sent.
func (b *Broker) approveStage(req *proto.Request, id RequesterID, conn net.Conn) bool {
	exeReal, cwdReal, dev, ino, deny, detail := b.validateRequest(req)
	if deny != "" {
		b.deny(req, id, deny, detail, conn)
		return false
	}

	granted, reason, approver := b.runApprovalInteraction(req, id, exeReal, cwdReal, dev, ino)
	aev := id.LogFields()
	aev["mode"] = b.mode
	// the approver's identity in queue mode, mode:<mode> for bench modes
	aev["approver"] = approver
	aev["decision"] = decision(granted)
	aev["result"] = boolRes(granted)
	aev["reason"] = reason
	aev["executable"] = req.Executable
	aev["argv"] = req.Argv
	aev["nonce"] = short(req.Nonce, 12)
	b.log.Event("approval", aev)
	if !granted {
		b.deny(req, id, reason, "nothing was executed", conn)
		return false
	}

	hash := req.Hash()
	pend := &pendingApproval{
		Hash: hash, Expiry: time.Now().Add(b.ttl),
		ExePath: exeReal, ExeDev: dev, ExeIno: ino, CwdReal: cwdReal,
		Requester: id,
	}
	// pin the approved identities for exec time: an open fd on the exe
	// inode (exec runs /proc/self/fd/N, never the mutable path) and the
	// cwd directory dev/ino (re-verified at exec). Fail closed if either
	// target changed between stat and pin.
	if code, detail := pinApproval(pend, exeReal, cwdReal, dev, ino); code != "" {
		b.deny(req, id, code, detail, conn)
		return false
	}
	b.mu.Lock()
	if old, exists := b.pending[hash]; exists {
		old.closePins() // re-approve replaces the pending: drop the old pin
	}
	b.pending[hash] = pend
	b.mu.Unlock()
	return true
}

// runApprovalInteraction performs the mode-specific approval. manual prints
// the exact request to the broker console and reads y/n from stdin; mock
// modes are deterministic stand-ins for tests.
func (b *Broker) runApprovalInteraction(req *proto.Request, id RequesterID, exeReal, cwdReal string, dev, ino uint64) (bool, string, string) {
	if b.mode == ModeQueue {
		return b.queueApproval(req, id, exeReal, cwdReal)
	}
	granted, reason := b.benchApproval(req, id, exeReal, dev, ino)
	return granted, reason, "mode:" + b.mode
}

// benchApproval is the approval of the bench modes: the broker decides on
// its own (mock-*) or asks its console (manual).
func (b *Broker) benchApproval(req *proto.Request, id RequesterID, exeReal string, dev, ino uint64) (bool, string) {
	switch b.mode {
	case ModeMockApprove:
		return true, ""
	case ModeMockDeny:
		return false, "approval_denied_by_mode"
	case ModeMockTimeout:
		// no approval ever arrives; wait out the TTL, then deny
		time.Sleep(b.ttl + 500*time.Millisecond)
		return false, "approval_timeout"
	case ModeManual:
		b.mu.Lock() // serialize prompts so they never interleave
		defer b.mu.Unlock()
		fmt.Fprintf(b.console, "=== TMB APPROVAL REQUIRED ===\n")
		fmt.Fprintf(b.console, "  requester : %s\n", id.ConsoleLine())
		fmt.Fprintf(b.console, "  executable: %s (realpath %s, dev=%d ino=%d)\n", req.Executable, exeReal, dev, ino)
		argvJ, _ := json.Marshal(req.Argv)
		fmt.Fprintf(b.console, "  argv      : %s\n", argvJ)
		fmt.Fprintf(b.console, "  cwd       : %s\n", req.Cwd)
		fmt.Fprintf(b.console, "  run as uid: %d\n", req.UID)
		// the environment the process will actually get, not the request's
		envJ, _ := json.Marshal(b.buildEnv(req))
		fmt.Fprintf(b.console, "  env       : %s\n", envJ)
		fmt.Fprintf(b.console, "  nonce     : %s\n", req.Nonce)
		fmt.Fprintf(b.console, "Approve exactly this command? [y/N]: ")
		line, err := b.stdin.ReadString('\n')
		if err != nil && line == "" {
			// stdin closed (detached broker) -> fail closed
			fmt.Fprintf(b.console, "CLOSED (no human input) -> DENIED\n")
			return false, "approval_input_closed"
		}
		ans := strings.ToLower(strings.TrimSpace(line))
		fmt.Fprintf(b.console, "HUMAN ANSWER: %q -> %s\n", ans, map[bool]string{true: "APPROVED", false: "DENIED"}[ans == "y" || ans == "yes"])
		if ans == "y" || ans == "yes" {
			return true, ""
		}
		return false, "approval_denied_by_human"
	default:
		return false, "approval_mode_unknown"
	}
}

// --- claim / execution ----------------------------------------------------

func (b *Broker) doClaim(req *proto.Request, id RequesterID, conn net.Conn) {
	b.claimStage(req, id, conn)
}

// peekPending returns the live pending approval for a hash (dropping it if
// expired) WITHOUT consuming it.
func (b *Broker) peekPending(hash string) (*pendingApproval, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, has := b.pending[hash]
	if has && time.Now().After(p.Expiry) {
		delete(b.pending, hash)
		p.closePins()
		has = false
	}
	return p, has
}

// takePending atomically removes and returns the live pending approval.
func (b *Broker) takePending(hash string) (*pendingApproval, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, has := b.pending[hash]
	if has && time.Now().After(p.Expiry) {
		delete(b.pending, hash)
		p.closePins()
		has = false
	}
	if has {
		delete(b.pending, hash) // approval is one-shot
	}
	return p, has
}

// claimStage re-validates, checks token binding + requester binding + replay
// state, consumes token+nonce on disk, and executes. Sends deny/exit frames
// itself.
func (b *Broker) claimStage(req *proto.Request, id RequesterID, conn net.Conn) {
	exeReal, cwdReal, dev, ino, deny, detail := b.validateRequest(req)
	if deny != "" {
		b.deny(req, id, deny, detail, conn)
		return
	}

	hash := req.Hash()
	tokenID := proto.TokenID(hash)
	rkey := id.Key()

	// 1. token must bind to THIS exact request (mutation after approval)
	if req.ClaimToken != tokenID {
		b.deny(req, id, "token_binding_mismatch",
			fmt.Sprintf("presented token %q does not bind to hash of this request (%s)", req.ClaimToken, tokenID), conn)
		return
	}

	// 2. the approval belongs to the requester it was granted to: a claim
	// from a DIFFERENT identity is refused BEFORE any token/nonce
	// consumption, so the original requester can still redeem it.
	if p, has := b.peekPending(hash); has && !p.Requester.Equal(id) {
		b.deny(req, id, "requester_mismatch",
			fmt.Sprintf("approval was granted to requester %s, token not consumed", p.Requester.Key()), conn)
		return
	}

	// 3. exactly-once on disk (survives broker restart)
	ok, err := b.claims.ClaimToken(hash, tokenID, rkey)
	if err != nil {
		b.deny(req, id, "claim_store_error", err.Error(), conn)
		return
	}
	if !ok {
		b.deny(req, id, "token_consumed_replay", "token already redeemed exactly once before", conn)
		return
	}
	ok, err = b.claims.ClaimNonce(req.Nonce, rkey)
	if err != nil {
		b.deny(req, id, "claim_store_error", err.Error(), conn)
		return
	}
	if !ok {
		b.deny(req, id, "nonce_consumed_replay", "nonce already redeemed exactly once before", conn)
		return
	}

	// 4. pending approval must exist, be unexpired, and pin the same inode
	p, has := b.takePending(hash)
	if !has {
		b.deny(req, id, "no_pending_approval", "no live approval for this exact request (expired, consumed, or broker restarted)", conn)
		return
	}
	if p.ExePath != exeReal || p.ExeDev != dev || p.ExeIno != ino {
		p.closePins() // pending consumed by takePending: drop the pin
		b.deny(req, id, "executable_changed",
			fmt.Sprintf("approved %s (dev=%d ino=%d), now %s (dev=%d ino=%d)", p.ExePath, p.ExeDev, p.ExeIno, exeReal, dev, ino), conn)
		return
	}

	ev := id.LogFields()
	ev["token"] = tokenID
	ev["hash"] = hash
	ev["nonce"] = short(req.Nonce, 12)
	ev["executable"] = exeReal
	ev["result"] = "ok"
	b.log.Event("claim", ev)

	// 5. execute EXACTLY the approved in-memory request tuple
	b.execute(req, p, tokenID, id, conn, cwdReal)
}

func boolRes(b bool) string {
	if b {
		return "granted"
	}
	return "denied"
}

// decision is the approval event's verdict, in the words of the approver
// protocol (approve or deny).
func decision(granted bool) string {
	if granted {
		return "approve"
	}
	return "deny"
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
