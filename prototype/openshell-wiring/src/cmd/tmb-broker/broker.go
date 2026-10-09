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
	"net"
	"os"
	"path/filepath"
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

// pendingApproval is an approval bound to one exact request hash.
type pendingApproval struct {
	Hash    string
	Expiry  time.Time
	ExePath string // realpath at approval time
	ExeDev  uint64
	ExeIno  uint64
	CwdReal string
}

type Broker struct {
	cfg    *Config
	mode   string
	ttl    time.Duration
	log    *Logger
	claims *ClaimStore

	mu      sync.Mutex // guards pending + manual prompt serialization
	pending map[string]*pendingApproval

	stdin *bufio.Reader // broker console stdin (manual approval)
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
	}
}

func (b *Broker) allowedRequester(uid uint32) bool {
	for _, u := range b.cfg.AllowedRequesterUIDs {
		if u == uid {
			return true
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

// ServeTCP runs the TCP accept loop (variant B). SO_PEERCRED does not exist
// for TCP: the requester uid is synthesized (cfg.TCPRequesterUID) and every
// such request is logged with transport=tcp so the downgrade is auditable.
func (b *Broker) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			uc := &syscall.Ucred{Uid: b.cfg.TCPRequesterUID(), Pid: 0}
			b.log.Event("tcp_connect", map[string]any{
				"remote": c.RemoteAddr().String(), "synth_uid": uc.Uid,
			})
			if !b.allowedRequester(uc.Uid) {
				b.log.Event("requester_denied", map[string]any{
					"requester_uid": uc.Uid, "transport": "tcp",
					"reason": "requester_not_allowed",
				})
				proto.WriteFrame(c, &proto.Frame{Type: "denied", Reason: "requester_not_allowed",
					Detail: fmt.Sprintf("synthesized uid %d not in allowlist", uc.Uid)})
				return
			}
			b.serveRequest(c, uc, "tcp")
		}(conn)
	}
}

func (b *Broker) handleConn(conn *net.UnixConn) {
	defer conn.Close()

	// SO_PEERCRED on EVERY connection, before reading anything.
	uc, err := peerCred(conn)
	if err != nil {
		b.log.Event("peercred_error", map[string]any{"error": err.Error()})
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "peercred_failed", Detail: err.Error()})
		return
	}
	if !b.allowedRequester(uc.Uid) {
		b.log.Event("requester_denied", map[string]any{
			"requester_uid": uc.Uid, "requester_pid": uc.Pid,
			"reason": "requester_not_allowed",
		})
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "requester_not_allowed",
			Detail: fmt.Sprintf("uid %d is not in the broker allowlist", uc.Uid)})
		return
	}
	b.serveRequest(conn, uc, "unix")
}

func (b *Broker) serveRequest(conn net.Conn, uc *syscall.Ucred, transport string) {
	raw, err := proto.ReadRawFrame(conn)
	if err != nil {
		b.log.Event("bad_frame", map[string]any{"requester_uid": uc.Uid, "error": err.Error()})
		return
	}
	var req proto.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		b.log.Event("bad_request", map[string]any{"requester_uid": uc.Uid, "error": err.Error()})
		proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: "bad_request", Detail: err.Error()})
		return
	}
	req.Nonce = strings.TrimSpace(req.Nonce)

	b.log.Event("request", map[string]any{
		"requester_uid": uc.Uid, "requester_pid": uc.Pid, "transport": transport,
		"type": req.Type, "executable": req.Executable, "argv": req.Argv,
		"cwd": req.Cwd, "uid": req.UID, "env": req.Env,
		"nonce": short(req.Nonce, 12), "claim_token": req.ClaimToken,
	})

	switch req.Type {
	case "approve":
		b.doApprove(&req, uc, conn)
	case "claim":
		b.doClaim(&req, uc, conn)
	case "exec":
		// approve + claim + exec from the SAME in-memory request object
		if !b.approveStage(&req, uc, conn) {
			return
		}
		hash := req.Hash()
		proto.WriteFrame(conn, &proto.Frame{Type: "approved",
			Token:  proto.TokenID(hash),
			Detail: fmt.Sprintf("one-shot token, ttl=%s", b.ttl)})
		req.ClaimToken = proto.TokenID(hash) // broker-side binding
		b.claimStage(&req, uc, conn)
	default:
		b.deny(&req, "unknown_request_type", req.Type, conn)
	}
}

func (b *Broker) deny(req *proto.Request, reason, detail string, conn net.Conn) {
	b.log.Event("deny", map[string]any{
		"executable": req.Executable, "argv": req.Argv,
		"nonce": short(req.Nonce, 12), "reason": reason, "detail": detail,
	})
	proto.WriteFrame(conn, &proto.Frame{Type: "denied", Reason: reason, Detail: detail})
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
	for k := range req.Env {
		if !b.envKeyAllowed(k) {
			return "", "", 0, 0, "env_key_not_allowed", k
		}
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
	return exeReal, cwdReal, dev, ino, "", ""
}

// --- approval -------------------------------------------------------------

func (b *Broker) doApprove(req *proto.Request, uc *syscall.Ucred, conn net.Conn) {
	if !b.approveStage(req, uc, conn) {
		return
	}
	proto.WriteFrame(conn, &proto.Frame{Type: "approved",
		Token:  proto.TokenID(req.Hash()),
		Detail: fmt.Sprintf("one-shot token, ttl=%s", b.ttl)})
}

// approveStage validates, runs the approval interaction, and on grant stores
// a pending approval. Returns false when a deny frame has been sent.
func (b *Broker) approveStage(req *proto.Request, uc *syscall.Ucred, conn net.Conn) bool {
	exeReal, cwdReal, dev, ino, deny, detail := b.validateRequest(req)
	if deny != "" {
		b.deny(req, deny, detail, conn)
		return false
	}

	granted, reason := b.runApprovalInteraction(req, uc, exeReal, dev, ino)
	b.log.Event("approval", map[string]any{
		"mode": b.mode, "result": boolRes(granted), "reason": reason,
		"executable": req.Executable, "argv": req.Argv, "nonce": short(req.Nonce, 12),
	})
	if !granted {
		b.deny(req, reason, "nothing was executed", conn)
		return false
	}

	hash := req.Hash()
	b.mu.Lock()
	b.pending[hash] = &pendingApproval{
		Hash: hash, Expiry: time.Now().Add(b.ttl),
		ExePath: exeReal, ExeDev: dev, ExeIno: ino, CwdReal: cwdReal,
	}
	b.mu.Unlock()
	return true
}

// runApprovalInteraction performs the mode-specific approval. manual prints
// the exact request to the broker console and reads y/n from stdin; mock
// modes are deterministic stand-ins for tests.
func (b *Broker) runApprovalInteraction(req *proto.Request, uc *syscall.Ucred, exeReal string, dev, ino uint64) (bool, string) {
	envJ, _ := json.Marshal(req.Env)
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
		fmt.Printf("=== TMB APPROVAL REQUIRED ===\n")
		fmt.Printf("  requester : uid=%d pid=%d (kernel SO_PEERCRED)\n", uc.Uid, uc.Pid)
		fmt.Printf("  executable: %s (realpath %s, dev=%d ino=%d)\n", req.Executable, exeReal, dev, ino)
		argvJ, _ := json.Marshal(req.Argv)
		fmt.Printf("  argv      : %s\n", argvJ)
		fmt.Printf("  cwd       : %s\n", req.Cwd)
		fmt.Printf("  run as uid: %d\n", req.UID)
		fmt.Printf("  env       : %s\n", envJ)
		fmt.Printf("  nonce     : %s\n", req.Nonce)
		fmt.Printf("Approve exactly this command? [y/N]: ")
		line, err := b.stdin.ReadString('\n')
		if err != nil && line == "" {
			// stdin closed (detached broker) -> fail closed
			fmt.Printf("CLOSED (no human input) -> DENIED\n")
			return false, "approval_input_closed"
		}
		ans := strings.ToLower(strings.TrimSpace(line))
		fmt.Printf("HUMAN ANSWER: %q -> %s\n", ans, map[bool]string{true: "APPROVED", false: "DENIED"}[ans == "y" || ans == "yes"])
		if ans == "y" || ans == "yes" {
			return true, ""
		}
		return false, "approval_denied_by_human"
	default:
		return false, "approval_mode_unknown"
	}
}

// --- claim / execution ----------------------------------------------------

func (b *Broker) doClaim(req *proto.Request, uc *syscall.Ucred, conn net.Conn) {
	b.claimStage(req, uc, conn)
}

// claimStage re-validates, checks token binding + replay state, consumes
// token+nonce on disk, and executes. Sends deny/exit frames itself.
func (b *Broker) claimStage(req *proto.Request, uc *syscall.Ucred, conn net.Conn) {
	exeReal, cwdReal, dev, ino, deny, detail := b.validateRequest(req)
	if deny != "" {
		b.deny(req, deny, detail, conn)
		return
	}

	hash := req.Hash()
	tokenID := proto.TokenID(hash)
	ruid := fmt.Sprintf("%d", uc.Uid)

	// 1. token must bind to THIS exact request (mutation after approval)
	if req.ClaimToken != tokenID {
		b.deny(req, "token_binding_mismatch",
			fmt.Sprintf("presented token %q does not bind to hash of this request (%s)", req.ClaimToken, tokenID), conn)
		return
	}

	// 2. exactly-once on disk (survives broker restart)
	ok, err := b.claims.ClaimToken(hash, tokenID, ruid)
	if err != nil {
		b.deny(req, "claim_store_error", err.Error(), conn)
		return
	}
	if !ok {
		b.deny(req, "token_consumed_replay", "token already redeemed exactly once before", conn)
		return
	}
	ok, err = b.claims.ClaimNonce(req.Nonce, ruid)
	if err != nil {
		b.deny(req, "claim_store_error", err.Error(), conn)
		return
	}
	if !ok {
		b.deny(req, "nonce_consumed_replay", "nonce already redeemed exactly once before", conn)
		return
	}

	// 3. pending approval must exist, be unexpired, and pin the same inode
	b.mu.Lock()
	p, has := b.pending[hash]
	if has && time.Now().After(p.Expiry) {
		delete(b.pending, hash)
		has = false
	}
	if has {
		delete(b.pending, hash) // approval is one-shot
	}
	b.mu.Unlock()
	if !has {
		b.deny(req, "no_pending_approval", "no live approval for this exact request (expired, consumed, or broker restarted)", conn)
		return
	}
	if p.ExePath != exeReal || p.ExeDev != dev || p.ExeIno != ino {
		b.deny(req, "executable_changed",
			fmt.Sprintf("approved %s (dev=%d ino=%d), now %s (dev=%d ino=%d)", p.ExePath, p.ExeDev, p.ExeIno, exeReal, dev, ino), conn)
		return
	}

	b.log.Event("claim", map[string]any{
		"token": tokenID, "hash": hash, "nonce": short(req.Nonce, 12),
		"executable": exeReal, "requester_uid": uc.Uid, "result": "ok",
	})

	// 4. execute EXACTLY the approved in-memory request tuple
	b.execute(req, p, tokenID, uc, conn, cwdReal)
}

func boolRes(b bool) string {
	if b {
		return "granted"
	}
	return "denied"
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// peerCred fetches the kernel-provided credentials of the socket peer.
func peerCred(conn *net.UnixConn) (*syscall.Ucred, error) {
	var cred *syscall.Ucred
	var serr error
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	err = raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	return cred, nil
}
