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
	"crypto/tls"
	"crypto/x509"
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

	"tmb-poc/internal/buildinfo"
	"tmb-poc/internal/proto"
)

const defaultSocket = "/run/tmb/tmb.sock"

func main() {
	if buildinfo.HandleVersion("tmb", os.Args[1:], os.Stdout) {
		return
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// cli carries the standard streams of one invocation.
type cli struct {
	stdin          io.Reader
	stdout, stderr io.Writer
}

// run executes one tmb invocation and returns its exit code: the remote
// exit code on success, 125 on denial, 3 on transport errors, 2 on usage
// errors.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	c := &cli{stdin: stdin, stdout: stdout, stderr: stderr}
	if len(args) < 1 {
		c.usage()
		return 2
	}
	var code int
	var err error
	switch args[0] {
	case "exec":
		code, err = c.cmdExec(args[1:])
	case "debug":
		code, err = c.cmdDebug(args[1:])
	case "approve": // approver role: decide queued requests
		return cmdApprover(args[1:], c.stdin, c.stdout, c.stderr)
	case "keygen":
		return cmdKeygen(args[1:], c.stdout, c.stderr)
	case "fingerprint":
		return cmdFingerprint(args[1:], c.stdout, c.stderr)
	default:
		c.usage()
		return 2
	}
	var fe *flagErr
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &fe):
		return 2 // the flag package has already printed the error and usage
	case err != nil:
		fmt.Fprintf(c.stderr, "tmb: %v\n", err)
		return exitCodeFor(err)
	}
	return code
}

// flagErr is a flag parse error the flag package has already reported.
type flagErr struct{ error }

// parseFlags parses args into fs, which reports to the invocation's stderr.
func (c *cli) parseFlags(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(c.stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &flagErr{err}
	}
	return nil
}

func (c *cli) usage() {
	fmt.Fprintf(c.stderr, `tmb (PROTOTYPE client)
usage:
  tmb exec [--root] [--cwd DIR] [--env K=V]... -- /abs/executable [args...]   full flow
  tmb approve [--list | --yes ID | --no ID] [--socket PATH]                   approver: decide queued requests
  tmb approve --list --json | --decide [--socket PATH]                        approver, machine mode: queue as JSON; decision JSON on stdin
                        (socket env TMB_APPROVE_SOCK, default %[2]s)
  tmb keygen --out FILE                                                      sandbox key (P-256, 0600); prints public key + fingerprint
  tmb version                                                                print the release version (also -version)
  tmb fingerprint FILE                                                       key fingerprint of a PEM key, certificate or CSR
  tmb debug approve --json FILE|-                                            debug: approval phase only
  tmb debug claim --token TOKEN --json FILE|-                                debug: claim phase only
  tmb debug raw --json FILE|-                                                debug: raw request verbatim
  TMB_DEBUG=1 (any exec or debug over TLS): print the broker certificate serial to stderr
endpoint selection (exec and debug):
  unix socket (default): --socket PATH (default %[1]s, env TMB_SOCK)
  TLS (mTLS endpoint):   --addr HOST:PORT (env TMB_ADDR) plus --ca/--cert/--key
                        (env TMB_CA/TMB_CERT/TMB_KEY); TMB_ADDR set without the
                        client cert material is a usage error (exit 2)
`, defaultSocket, defaultApproveSocket)
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

// dial connects to a unix-socket broker with the PoC retry loop.
func dial(path string) (net.Conn, error) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.Dial("unix", path)
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

// endpoint collects the broker endpoint selection for one subcommand. Empty
// fields fall back to env (TMB_SOCK / TMB_ADDR / TMB_CA / TMB_CERT /
// TMB_KEY); a set addr selects the TLS path, otherwise the unix path.
type endpoint struct {
	socket, addr, ca, cert, key string
}

func (e *endpoint) addFlags(fs *flag.FlagSet) {
	fs.StringVar(&e.socket, "socket", "", "broker socket path (env TMB_SOCK)")
	fs.StringVar(&e.addr, "addr", "", "broker TLS address host:port (env TMB_ADDR)")
	fs.StringVar(&e.ca, "ca", "", "CA certificate verifying the broker (env TMB_CA)")
	fs.StringVar(&e.cert, "cert", "", "client certificate (env TMB_CERT)")
	fs.StringVar(&e.key, "key", "", "client key (env TMB_KEY)")
}

func orEnv(v, env string) string {
	if v != "" {
		return v
	}
	return os.Getenv(env)
}

// dialEndpoint connects to the broker: TLS when a TMB_ADDR endpoint is set
// (flag or env), the unix socket exactly as before otherwise.
func dialEndpoint(e endpoint) (net.Conn, error) {
	addr := orEnv(e.addr, "TMB_ADDR")
	if addr == "" {
		sock := orEnv(e.socket, "TMB_SOCK")
		if sock == "" {
			sock = defaultSocket
		}
		return dial(sock)
	}
	ca := orEnv(e.ca, "TMB_CA")
	cert := orEnv(e.cert, "TMB_CERT")
	key := orEnv(e.key, "TMB_KEY")
	if ca == "" || cert == "" || key == "" {
		return nil, fmt.Errorf(
			"tls endpoint %s: TMB_CA, TMB_CERT and TMB_KEY (or --ca/--cert/--key) are required when TMB_ADDR is set - no connection attempted", addr)
	}
	return dialTLS(addr, ca, cert, key)
}

// tlsClientConfig builds the client-side TLS config: the broker chain is
// verified against the TMB_CA root pool with ServerName taken from the host
// part of the address. InsecureSkipVerify is forbidden by design and never
// set.
func tlsClientConfig(addr, caPath, certPath, keyPath string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("bad address %q (want host:port): %v", addr, err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read --ca/TMB_CA %s: %v", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("--ca/TMB_CA %s: no certificates parsed", caPath)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load --cert/--key (TMB_CERT/TMB_KEY): %v", err)
	}
	return &tls.Config{
		ServerName:   host,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// dialTLS dials the TLS endpoint and completes the handshake. Config errors
// are plain errors (exit 2); connection and verification failures are
// transport errors (exit 3, FAIL CLOSED).
func dialTLS(addr, caPath, certPath, keyPath string) (net.Conn, error) {
	cfg, err := tlsClientConfig(addr, caPath, certPath, keyPath)
	if err != nil {
		return nil, err
	}
	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, &transportErr{fmt.Errorf(
			"broker unreachable at %s: %v - FAIL CLOSED, nothing executed", addr, err)}
	}
	tc := tls.Client(raw, cfg)
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, &transportErr{fmt.Errorf(
			"TLS handshake with %s failed: %v - FAIL CLOSED, nothing executed", addr, err)}
	}
	_ = raw.SetDeadline(time.Time{})
	if os.Getenv("TMB_DEBUG") != "" {
		debugBrokerCert(os.Stderr, tc.ConnectionState())
	}
	return tc, nil
}

// debugBrokerCert prints the serial number of the broker certificate this
// connection was handshaken with (TMB_DEBUG set): an operator, or the
// harness, sees which certificate a reloaded broker served.
func debugBrokerCert(w io.Writer, st tls.ConnectionState) {
	if len(st.PeerCertificates) == 0 {
		return
	}
	c := st.PeerCertificates[0]
	fmt.Fprintf(w, "tmb: debug: broker certificate serial=%X subject=%s\n", c.SerialNumber, c.Subject.CommonName)
}

func isRetryable(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func sendRequest(conn net.Conn, req *proto.Request) error {
	return proto.WriteFrame(conn, req)
}

// streamFrames reads frames until a terminal one; returns (exitCode, err).
func (c *cli) streamFrames(conn net.Conn, quiet bool) (int, error) {
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			return -1, &transportErr{fmt.Errorf("connection to broker lost: %w", err)}
		}
		switch f.Type {
		case "approved":
			fmt.Fprintf(c.stderr, "TOK: %s (%s)\n", f.Token, f.Detail)
		case "waiting":
			fmt.Fprintf(c.stderr, "tmb: waiting for approval (item %s, %s)\n", f.Token, f.Detail)
		case "stdout", "stderr":
			data, err := base64.StdEncoding.DecodeString(f.Data)
			if err != nil {
				return -1, fmt.Errorf("bad chunk frame: %w", err)
			}
			if f.Type == "stdout" {
				c.stdout.Write(data)
			} else {
				c.stderr.Write(data)
			}
		case "exit":
			fmt.Fprintf(c.stderr, "EXIT: %d\n", *f.Code)
			return *f.Code, nil
		case "denied":
			return -1, &deniedErr{f.Reason, f.Detail}
		case "error":
			return -1, fmt.Errorf("broker error: %s %s", f.Reason, f.Detail)
		default:
			if !quiet {
				b, _ := json.Marshal(f)
				fmt.Fprintf(c.stderr, "FRAME: %s\n", b)
			}
		}
	}
}

func (c *cli) readJSONFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(c.stdin)
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

func (c *cli) cmdExec(args []string) (int, error) {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	root := fs.Bool("root", false, "request uid 0 (only uid supported in PoC)")
	cwd := fs.String("cwd", "/tmp", "working directory for the command")
	var ep endpoint
	ep.addFlags(fs)
	var envFlags multiFlag
	fs.Var(&envFlags, "env", "request env K=V (must be in broker allowlist); repeatable")
	if err := c.parseFlags(fs, args); err != nil {
		return 0, err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return 0, errors.New("exec: expected '--' followed by the command, e.g. tmb exec --root -- /usr/bin/id -u")
	}
	argvRest := rest
	if !*root {
		return 0, errors.New("exec: PoC supports only --root (uid 0)")
	}
	exe, err := resolveExecutable(argvRest[0])
	if err != nil {
		return 0, err
	}
	argv := append([]string{exe}, argvRest[1:]...) // argv[0] = resolved absolute path

	env := map[string]string{}
	for _, kv := range envFlags {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return 0, fmt.Errorf("--env expects K=V, got %q", kv)
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
	fmt.Fprintf(c.stderr, "REQ: %s\n", req.Canonical())
	conn, err := dialEndpoint(ep)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := sendRequest(conn, req); err != nil {
		return 0, &transportErr{err}
	}
	// exit with the REMOTE exit code
	return c.streamFrames(conn, false)
}

// --- debug subcommands ------------------------------------------------------

// cmdDebug dispatches the requester protocol steps that exist for the
// harness only: approve (phase 1), claim (phase 2) and raw (verbatim JSON).
func (c *cli) cmdDebug(args []string) (int, error) {
	if len(args) == 0 {
		return 0, errors.New("debug: expected approve, claim or raw")
	}
	switch args[0] {
	case "approve": // phase 1 only (get a token, do not execute)
		return 0, c.cmdApprove(args[1:])
	case "claim": // phase 2 only (present token, execute if accepted)
		return c.cmdClaim(args[1:])
	case "raw": // send an arbitrary JSON request verbatim
		return 0, c.cmdRaw(args[1:])
	}
	return 0, fmt.Errorf("debug: unknown step %q, expected approve, claim or raw", args[0])
}

func (c *cli) cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	jsonPath := fs.String("json", "-", "request JSON file ('-' = stdin)")
	var ep endpoint
	ep.addFlags(fs)
	if err := c.parseFlags(fs, args); err != nil {
		return err
	}
	raw, err := c.readJSONFile(*jsonPath)
	if err != nil {
		return err
	}
	var req proto.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("bad request JSON: %w", err)
	}
	req.Type = "approve"
	fmt.Fprintf(c.stderr, "REQ: %s\n", req.Canonical())
	return c.roundtrip(ep, &req)
}

func (c *cli) cmdClaim(args []string) (int, error) {
	fs := flag.NewFlagSet("claim", flag.ContinueOnError)
	jsonPath := fs.String("json", "-", "request JSON file ('-' = stdin)")
	token := fs.String("token", "", "token to present")
	var ep endpoint
	ep.addFlags(fs)
	if err := c.parseFlags(fs, args); err != nil {
		return 0, err
	}
	if *token == "" {
		return 0, errors.New("claim: --token is required")
	}
	raw, err := c.readJSONFile(*jsonPath)
	if err != nil {
		return 0, err
	}
	var req proto.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return 0, fmt.Errorf("bad request JSON: %w", err)
	}
	req.Type = "claim"
	req.ClaimToken = *token
	fmt.Fprintf(c.stderr, "REQ: %s\n", req.Canonical())
	return c.roundtripCode(ep, &req)
}

func (c *cli) cmdRaw(args []string) error {
	fs := flag.NewFlagSet("raw", flag.ContinueOnError)
	jsonPath := fs.String("json", "-", "request JSON file ('-' = stdin)")
	var ep endpoint
	ep.addFlags(fs)
	if err := c.parseFlags(fs, args); err != nil {
		return err
	}
	raw, err := c.readJSONFile(*jsonPath)
	if err != nil {
		return err
	}
	var req proto.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("bad request JSON: %w", err)
	}
	fmt.Fprintf(c.stderr, "REQ-RAW: %s\n", raw)
	return c.roundtrip(ep, &req)
}

// roundtrip sends the request and prints every frame as JSON (no stream
// decoding) - used by debug subcommands.
func (c *cli) roundtrip(ep endpoint, req *proto.Request) error {
	_, err := c.roundtripCode(ep, req)
	return err
}

func (c *cli) roundtripCode(ep endpoint, req *proto.Request) (int, error) {
	conn, err := dialEndpoint(ep)
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
			fmt.Fprintf(c.stderr, "FRAME: %s\n", b)
		case "stdout", "stderr":
			data, _ := base64.StdEncoding.DecodeString(f.Data)
			if f.Type == "stdout" {
				c.stdout.Write(data)
			} else {
				c.stderr.Write(data)
			}
		case "exit":
			fmt.Fprintf(c.stderr, "EXIT: %d\n", *f.Code)
			return *f.Code, nil
		case "denied":
			b, _ := json.Marshal(f)
			fmt.Fprintf(c.stderr, "FRAME: %s\n", b)
			return -1, &deniedErr{f.Reason, f.Detail}
		default:
			b, _ := json.Marshal(f)
			fmt.Fprintf(c.stderr, "FRAME: %s\n", b)
		}
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
