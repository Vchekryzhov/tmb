// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
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
//     (dev/ino) at exec time: a replaced cwd denies with cwd_changed
func (b *Broker) execute(req *proto.Request, p *pendingApproval, tokenID string, id RequesterID, conn net.Conn, cwdReal string) {
	// the pending was consumed by the claim: whatever happens below, its
	// pin goes away with this execution attempt
	defer p.closePins()

	if p.CwdPinned && !cwdStillPinned(cwdReal, p.CwdDev, p.CwdIno) {
		b.deny(req, id, "cwd_changed",
			fmt.Sprintf("approved cwd %s (dev=%d ino=%d) was replaced before exec", cwdReal, p.CwdDev, p.CwdIno), conn)
		return
	}
	exeTarget, viaFd := p.execTarget()

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
		Dir:    cwdReal,
		Env:    env,
		Stdin:  devNull,
		Stdout: nil, // pipes below
		Stderr: nil,
		// ExtraFiles deliberately nil -> child sees ONLY fd 0,1,2
		SysProcAttr: &syscall.SysProcAttr{},
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.deny(req, id, "exec_error", err.Error(), conn)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
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
	b.log.Event("exec_start", evStart)

	if err := cmd.Start(); err != nil {
		b.log.Event("exec_fail", map[string]any{"token": tokenID, "error": err.Error()})
		b.deny(req, id, "exec_start_failed", err.Error(), conn)
		return
	}

	var wmu sync.Mutex // serialize frame writes to the client
	writeFrame := func(f *proto.Frame) {
		wmu.Lock()
		defer wmu.Unlock()
		proto.WriteFrame(conn, f)
	}
	pump := func(r io.Reader, kind string) func() {
		return func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					writeFrame(proto.Chunk(kind, buf[:n]))
				}
				if err != nil {
					return
				}
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pump(stdout, "stdout")() }()
	go func() { defer wg.Done(); pump(stderr, "stderr")() }()
	wg.Wait() // drain both pipes BEFORE Wait closes them

	waitErr := cmd.Wait()
	code := 0
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
			if code < 0 { // killed by signal
				code = 128 + (-code)
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
	b.log.Event("exec_exit", evExit)
	writeFrame(&proto.Frame{Type: "exit", Code: &code})
}

// buildEnv constructs the child environment: fixed env from broker config
// plus request values for allowlisted keys only. PATH is always the fixed
// safe value and is never requestable.
func (b *Broker) buildEnv(req *proto.Request) []string {
	vals := map[string]string{}
	for k, v := range b.cfg.FixedEnv {
		vals[k] = v
	}
	for k, v := range req.Env {
		if b.envKeyAllowed(k) {
			vals[k] = v
		}
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
