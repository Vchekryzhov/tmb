// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
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
//     (Path is the realpath pinned at approval, absolute)
//   - argv is the request's argv verbatim
//   - env is rebuilt by the broker from the fixed env + allowlisted keys;
//     the child NEVER inherits the broker env or the request env wholesale
//   - stdin is /dev/null; only fds 0,1,2 exist in the child (Go opens all
//     fds O_CLOEXEC / SOCK_CLOEXEC and ExtraFiles is nil, so the client
//     socket cannot leak into the child)
//   - cwd is the realpath'd request cwd
func (b *Broker) execute(req *proto.Request, p *pendingApproval, tokenID string, uc *syscall.Ucred, conn net.Conn, cwdReal string) {
	env := b.buildEnv(req)

	devNull, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		b.deny(req, "exec_error", "open /dev/null: "+err.Error(), conn)
		return
	}
	defer devNull.Close()

	start := time.Now()
	cmd := &exec.Cmd{
		Path:   p.ExePath, // absolute realpath, pinned dev+ino at approval
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
		b.deny(req, "exec_error", err.Error(), conn)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		b.deny(req, "exec_error", err.Error(), conn)
		return
	}

	b.log.Event("exec_start", map[string]any{
		"token": tokenID, "executable": p.ExePath, "argv": req.Argv,
		"cwd": cwdReal, "uid": req.UID, "env_count": len(env), "requester_uid": uc.Uid,
	})

	if err := cmd.Start(); err != nil {
		b.log.Event("exec_fail", map[string]any{"token": tokenID, "error": err.Error()})
		b.deny(req, "exec_start_failed", err.Error(), conn)
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
	b.log.Event("exec_exit", map[string]any{
		"token": tokenID, "executable": p.ExePath,
		"exit_status": code, "duration_ms": time.Since(start).Milliseconds(),
	})
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
