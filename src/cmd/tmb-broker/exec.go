// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"sync"
	"syscall"
	"time"

	"tmb-poc/internal/proto"
)

// execute runs the approved executable with the EXACT argv from the request.
//
// Hygiene rules enforced here:
//   - direct execve via os/exec (fork+exec): NO sh -c, NO PATH lookup
//     (on linux the exec target is /proc/self/fd/N pinned to the inode
//     approved by the human; off-linux it is the absolute realpath)
//   - argv is the request's argv verbatim
//   - env is rebuilt by the broker from the fixed env + allowlisted keys;
//     the child NEVER inherits the broker env or the request env wholesale
//   - stdin is /dev/null; only fds 0,1,2 exist in the child (Go opens all
//     fds O_CLOEXEC / SOCK_CLOEXEC and ExtraFiles is nil, so the client
//     socket cannot leak into the child; the pinned exe fd is O_CLOEXEC
//     too and execve resolves it before the close)
//   - cwd is the realpath'd request cwd, re-verified by directory identity
//     (dev/ino) at exec time: a replaced cwd denies with cwd_changed; on
//     linux the child then chdirs through the held fd (/proc/self/fd/N),
//     so a swap after that check cannot move it to another directory
func (b *Broker) execute(req *proto.Request, p *pendingApproval, tokenID string, id RequesterID, conn net.Conn, cwdReal string) {
	// the pending was consumed by the claim: whatever happens below, its
	// pin goes away with this execution attempt
	defer p.closePins()

	if p.CwdPinned && !cwdStillPinned(cwdReal, p.CwdDev, p.CwdIno) {
		b.deny(req, id, "cwd_changed",
			fmt.Sprintf("approved cwd %s (dev=%d ino=%d) was replaced before exec", cwdReal, p.CwdDev, p.CwdIno), conn)
		return
	}
	afterCwdCheck()
	exeTarget, viaFd := p.execTarget()
	cwdTarget, cwdViaFd := p.cwdTarget(cwdReal)

	env := b.buildEnv(req)

	devNull, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		b.deny(req, id, "exec_error", "open /dev/null: "+err.Error(), conn)
		return
	}
	defer devNull.Close()

	start := time.Now()
	cmd := &exec.Cmd{
		Path:   exeTarget, // linux: /proc/self/fd/N = the approved inode; else the absolute realpath
		Args:   req.Argv,  // EXACT argv, verbatim from the approved request
		Dir:    cwdTarget, // linux: /proc/self/fd/N = the approved directory; else the realpath
		Env:    env,
		Stdin:  devNull,
		Stdout: nil, // pipes below
		Stderr: nil,
		// ExtraFiles deliberately nil -> child sees ONLY fd 0,1,2
		SysProcAttr: &syscall.SysProcAttr{},
	}
	// output goes to the client as chunk frames; os/exec copies the
	// pipes itself, so WaitDelay can bound a descendant that keeps them open
	out := &clientStream{conn: conn}
	cmd.Stdout = out.writer("stdout")
	cmd.Stderr = out.writer("stderr")
	cmd.WaitDelay = execWaitDelay

	if err := closeOnExecInherited(); err != nil {
		b.deny(req, id, "exec_error", err.Error(), conn)
		return
	}

	evStart := id.LogFields()
	evStart["token"] = tokenID
	evStart["executable"] = p.ExePath
	evStart["argv"] = req.Argv
	evStart["cwd"] = cwdReal
	evStart["uid"] = req.UID
	evStart["env_count"] = len(env)
	evStart["exe_via_fd"] = viaFd
	evStart["exe_dev"] = p.ExeDev
	evStart["exe_ino"] = p.ExeIno
	evStart["cwd_verified"] = p.CwdPinned
	evStart["cwd_via_fd"] = cwdViaFd
	// no execution without its record: exec_start must reach the disk
	if b.log.Event("exec_start", evStart) != nil {
		b.deny(req, id, "audit_unavailable", auditUnavailableDetail, conn)
		return
	}

	if err := cmd.Start(); err != nil {
		b.log.Event("exec_fail", map[string]any{"token": tokenID, "error": err.Error()})
		b.deny(req, id, "exec_start_failed", err.Error(), conn)
		return
	}

	waitErr := cmd.Wait()
	if errors.Is(waitErr, exec.ErrWaitDelay) {
		// the command exited; a descendant held its output open past
		// execWaitDelay and was cut off. The exit status is the command's.
		waitErr = nil
		if !cmd.ProcessState.Success() {
			waitErr = &exec.ExitError{ProcessState: cmd.ProcessState}
		}
	}
	code := 0
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
			// ExitCode is -1 for a signal death; report it the shell way
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
		} else {
			code = 255
		}
	}
	evExit := id.LogFields()
	evExit["token"] = tokenID
	evExit["executable"] = p.ExePath
	evExit["exit_status"] = code
	evExit["duration_ms"] = time.Since(start).Milliseconds()
	evExit["client_gone"] = out.gone()
	b.log.Event("exec_exit", evExit)
	out.write(&proto.Frame{Type: "exit", Code: &code})
}

// execWaitDelay bounds how long the broker waits, after the command exits,
// for a descendant that still holds its stdout or stderr open.
var execWaitDelay = 5 * time.Second

// clientWriteTimeout bounds one frame write to the client. A client that
// stops reading is treated as gone: its output is discarded, so the
// command is never blocked on a full pipe.
var clientWriteTimeout = 30 * time.Second

// clientStream serializes frame writes to the client and remembers when the
// client stopped taking them.
type clientStream struct {
	conn   net.Conn
	mu     sync.Mutex
	failed bool
}

func (s *clientStream) write(f *proto.Frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(clientWriteTimeout))
	if err := proto.WriteFrame(s.conn, f); err != nil {
		s.failed = true
	}
	_ = s.conn.SetWriteDeadline(time.Time{})
}

func (s *clientStream) gone() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

// writer returns an io.Writer that sends each write as one chunk frame of
// kind. It never fails: once the client is gone the bytes are dropped and
// the command keeps running to its end.
func (s *clientStream) writer(kind string) io.Writer {
	return chunkWriter{s: s, kind: kind}
}

type chunkWriter struct {
	s    *clientStream
	kind string
}

// maxChunk keeps one chunk frame well under proto.MaxFrame after base64.
const maxChunk = 32 * 1024

func (w chunkWriter) Write(p []byte) (int, error) {
	for off := 0; off < len(p); off += maxChunk {
		end := min(off+maxChunk, len(p))
		w.s.write(proto.Chunk(w.kind, p[off:end]))
	}
	return len(p), nil
}

// afterCwdCheck is a test seam: it runs between the last cwd identity check
// and the fork, the window the held cwd fd closes.
var afterCwdCheck = func() {}

// buildEnv constructs the child environment: fixed env from broker config
// plus request values for allowlisted keys that are not fixed. A fixed key
// always keeps its configured value; PATH can only be fixed (loadConfig
// rejects it in allowed_env_keys).
func (b *Broker) buildEnv(req *proto.Request) []string {
	vals := map[string]string{}
	for k, v := range req.Env {
		if b.envKeyAllowed(k) && !b.envKeyFixed(k) {
			vals[k] = v
		}
	}
	for k, v := range b.conf().FixedEnv {
		vals[k] = v
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, k := range keys {
		env = append(env, k+"="+vals[k])
	}
	return env
}
