// PROTOTYPE CODE - throwaway PoC, not production.
//
// tmb: unprivileged client CLI. It NEVER executes the requested command
// itself - it resolves the executable to an absolute path, builds a
// structured request, sends it to the broker socket, and streams back
// stdout/stderr + exit code.
//
// Exit codes: remote exit code on success; 125 when the broker denied the
// request; 3 on transport errors (broker down -> FAIL CLOSED).
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tmb-poc/internal/proto"
)

const defaultSocket = "/run/tmb/tmb.sock"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "exec":
		err = cmdExec(os.Args[2:])
	case "approve": // debug: phase 1 only (get a token, do not execute)
		err = cmdApprove(os.Args[2:])
	case "claim": // debug: phase 2 only (present token, execute if accepted)
		err = cmdClaim(os.Args[2:])
	case "raw": // debug: send an arbitrary JSON request verbatim
		err = cmdRaw(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tmb: %v\n", err)
		os.Exit(exitCodeFor(err))
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `tmb (PROTOTYPE client)
usage:
  tmb exec [--root] [--cwd DIR] [--env K=V]... -- /abs/executable [args...]   full flow
  tmb approve --json FILE|-                                                  debug: approval phase only
  tmb claim --token TOKEN --json FILE|-                                      debug: claim phase only
  tmb raw --json FILE|-                                                      debug: raw request verbatim
flags (all): --socket PATH (default %s, env TMB_SOCK)
`, defaultSocket)
}

// --- shared plumbing ------------------------------------------------------

type transportErr struct{ error }

func exitCodeFor(err error) int {
	var te *transportErr
	if errors.As(err, &te) {
		return 3 // broker unreachable -> fail closed
	}
	var de *deniedErr
	if errors.As(err, &de) {
		return 125
	}
	return 2
}

type deniedErr struct{ reason, detail string }

func (e *deniedErr) Error() string {
	if e.detail != "" {
		return fmt.Sprintf("DENIED: %s (%s)", e.reason, e.detail)
	}
	return "DENIED: " + e.reason
}

func dial(path string) (net.Conn, error) {
	// wiring PoC (variant B): "tcp://host:port" in TMB_SOCK/--socket dials the
	// broker TCP listener instead of the unix socket. No SO_PEERCRED on this
	// path - the broker synthesizes the requester uid.
	network, addr := "unix", path
	if strings.HasPrefix(path, "tcp://") {
		network, addr = "tcp", strings.TrimPrefix(path, "tcp://")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.Dial(network, addr)
		if err == nil {
			return conn, nil
		}
		if !isRetryable(err) || time.Now().After(deadline) {
			return nil, &transportErr{fmt.Errorf(
				"broker unreachable at %s (is tmb-broker running?): %w - FAIL CLOSED, nothing executed", path, err)}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func isRetryable(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func sendRequest(conn net.Conn, req *proto.Request) error {
	return proto.WriteFrame(conn, req)
}

// streamFrames reads frames until a terminal one; returns (exitCode, deny, err).
func streamFrames(conn net.Conn, quiet bool) (int, error) {
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			return -1, &transportErr{fmt.Errorf("connection to broker lost: %w", err)}
		}
		switch f.Type {
		case "approved":
			fmt.Fprintf(os.Stderr, "TOK: %s (%s)\n", f.Token, f.Detail)
		case "stdout", "stderr":
			data, err := base64.StdEncoding.DecodeString(f.Data)
			if err != nil {
				return -1, fmt.Errorf("bad chunk frame: %w", err)
			}
			if f.Type == "stdout" {
				os.Stdout.Write(data)
			} else {
				os.Stderr.Write(data)
			}
		case "exit":
			fmt.Fprintf(os.Stderr, "EXIT: %d\n", *f.Code)
			return *f.Code, nil
		case "denied":
			return -1, &deniedErr{f.Reason, f.Detail}
		case "error":
			return -1, fmt.Errorf("broker error: %s %s", f.Reason, f.Detail)
		default:
			if !quiet {
				b, _ := json.Marshal(f)
				fmt.Fprintf(os.Stderr, "FRAME: %s\n", b)
			}
		}
	}
}

func readJSONFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// resolveExecutable resolves the requested executable to an ABSOLUTE path
// client-side. If it contains a slash it must already be absolute; otherwise
// it is resolved through PATH like a shell would. The broker independently
// rejects anything non-absolute.
func resolveExecutable(arg0 string) (string, error) {
	if strings.ContainsRune(arg0, '/') {
		if !filepath.IsAbs(arg0) {
			return "", fmt.Errorf("executable %q contains '/' but is not absolute", arg0)
		}
		return arg0, nil
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		if !filepath.IsAbs(dir) {
			continue
		}
		cand := filepath.Join(dir, arg0)
		if st, err := os.Stat(cand); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("executable %q not found on PATH (client resolves to absolute; broker rejects non-absolute)", arg0)
}

// --- exec -----------------------------------------------------------------

func cmdExec(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	root := fs.Bool("root", false, "request uid 0 (only uid supported in PoC)")
	cwd := fs.String("cwd", "/tmp", "working directory for the command")
	socketRef := ""
	fs.StringVar(&socketRef, "socket", "", "broker socket path")
	var envFlags multiFlag
	fs.Var(&envFlags, "env", "request env K=V (must be in broker allowlist); repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("exec: expected '--' followed by the command, e.g. tmb exec --root -- /usr/bin/id -u")
	}
	argvRest := rest
	if !*root {
		return errors.New("exec: PoC supports only --root (uid 0)")
	}
	exe, err := resolveExecutable(argvRest[0])
	if err != nil {
		return err
	}
	argv := append([]string{exe}, argvRest[1:]...) // argv[0] = resolved absolute path

	env := map[string]string{"LANG": "C.UTF-8"}
	for _, kv := range envFlags {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("--env expects K=V, got %q", kv)
		}
		env[parts[0]] = parts[1]
	}

	req := &proto.Request{
		Type:       "exec",
		Executable: exe,
		Argv:       argv,
		Cwd:        *cwd,
		UID:        0,
		Env:        env,
		Nonce:      proto.NewNonce(),
	}
	sock := socketRef
	if sock == "" {
		sock = envSock()
	}
	fmt.Fprintf(os.Stderr, "REQ: %s\n", req.Canonical())
	conn, err := dial(sock)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := sendRequest(conn, req); err != nil {
		return &transportErr{err}
	}
	code, err := streamFrames(conn, false)
	if err != nil {
		return err
	}
	// exit with the REMOTE exit code
	os.Exit(code)
	return nil
}

func envSock() string {
	if s := os.Getenv("TMB_SOCK"); s != "" {
		return s
	}
	return defaultSocket
}

// --- debug subcommands ------------------------------------------------------

func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	jsonPath := fs.String("json", "-", "request JSON file ('-' = stdin)")
	socketRef := ""
	fs.StringVar(&socketRef, "socket", "", "broker socket path")
	fs.Parse(args)
	raw, err := readJSONFile(*jsonPath)
	if err != nil {
		return err
	}
	var req proto.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("bad request JSON: %w", err)
	}
	req.Type = "approve"
	fmt.Fprintf(os.Stderr, "REQ: %s\n", req.Canonical())
	return roundtrip(socketRef, &req)
}

func cmdClaim(args []string) error {
	fs := flag.NewFlagSet("claim", flag.ExitOnError)
	jsonPath := fs.String("json", "-", "request JSON file ('-' = stdin)")
	token := fs.String("token", "", "token to present")
	socketRef := ""
	fs.StringVar(&socketRef, "socket", "", "broker socket path")
	fs.Parse(args)
	if *token == "" {
		return errors.New("claim: --token is required")
	}
	raw, err := readJSONFile(*jsonPath)
	if err != nil {
		return err
	}
	var req proto.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("bad request JSON: %w", err)
	}
	req.Type = "claim"
	req.ClaimToken = *token
	fmt.Fprintf(os.Stderr, "REQ: %s\n", req.Canonical())
	code, err := roundtripCode(socketRef, &req)
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}

func cmdRaw(args []string) error {
	fs := flag.NewFlagSet("raw", flag.ExitOnError)
	jsonPath := fs.String("json", "-", "request JSON file ('-' = stdin)")
	socketRef := ""
	fs.StringVar(&socketRef, "socket", "", "broker socket path")
	fs.Parse(args)
	raw, err := readJSONFile(*jsonPath)
	if err != nil {
		return err
	}
	var req proto.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("bad request JSON: %w", err)
	}
	fmt.Fprintf(os.Stderr, "REQ-RAW: %s\n", raw)
	return roundtrip(socketRef, &req)
}

// roundtrip sends the request and prints every frame as JSON (no stream
// decoding) - used by debug subcommands.
func roundtrip(socketRef string, req *proto.Request) error {
	_, err := roundtripCode(socketRef, req)
	return err
}

func roundtripCode(socketRef string, req *proto.Request) (int, error) {
	sock := socketRef
	if sock == "" {
		sock = envSock()
	}
	conn, err := dial(sock)
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	if err := sendRequest(conn, req); err != nil {
		return -1, &transportErr{err}
	}
	sawApproved := false
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			// Clean EOF AFTER an "approved" frame = broker ended a standalone
			// approve phase; EOF before any frame = transport loss (fail closed).
			if errors.Is(err, io.EOF) && sawApproved {
				return 0, nil
			}
			return -1, &transportErr{fmt.Errorf("connection to broker lost: %w", err)}
		}
		switch f.Type {
		case "approved":
			sawApproved = true
			b, _ := json.Marshal(f)
			fmt.Fprintf(os.Stderr, "FRAME: %s\n", b)
		case "stdout", "stderr":
			data, _ := base64.StdEncoding.DecodeString(f.Data)
			if f.Type == "stdout" {
				os.Stdout.Write(data)
			} else {
				os.Stderr.Write(data)
			}
		case "exit":
			fmt.Fprintf(os.Stderr, "EXIT: %d\n", *f.Code)
			return *f.Code, nil
		case "denied":
			b, _ := json.Marshal(f)
			fmt.Fprintf(os.Stderr, "FRAME: %s\n", b)
			return -1, &deniedErr{f.Reason, f.Detail}
		default:
			b, _ := json.Marshal(f)
			fmt.Fprintf(os.Stderr, "FRAME: %s\n", b)
		}
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
