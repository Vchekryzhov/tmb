package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// lockedBuffer is a stderr stand-in safe to read while the broker writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lockedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *lockedBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// jsonLines decodes the JSON lines of text, failing the test on a bad one.
func jsonLines(t *testing.T, text string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

// Every journal line, in the file and in the stderr reserve, carries
// schema 1.
func TestJournalLinesCarrySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.log")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stderr := &lockedBuffer{}
	l.stderr = stderr
	if err := l.Event("broker_stop", map[string]any{"pid": 1}); err != nil {
		t.Fatalf("event: %v", err)
	}
	if err := l.Event("tls_listen", nil); err != nil {
		t.Fatalf("event with nil fields: %v", err)
	}
	l.sync = func(*os.File) error { return errors.New("injected EIO") }
	if err := l.Event("broker_stop", map[string]any{"pid": 1}); !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("event after a failed fsync: %v, want errAuditUnavailable", err)
	}
	file, reserve := jsonLines(t, readFile(t, path)), jsonLines(t, stderr.String())
	// the failed event's bytes reached the file before fsync failed
	if len(file) != 3 || len(reserve) != 2 { // reserve: audit_unavailable + the event
		t.Fatalf("file %d lines, reserve %d lines; want 3 and 2:\n%s", len(file), len(reserve), stderr)
	}
	for _, ev := range append(file, reserve...) {
		if ev["schema"] != float64(1) {
			t.Errorf("line without schema 1: %v", ev)
		}
	}
	if l.Path() != path {
		t.Errorf("Path() = %q, want %q", l.Path(), path)
	}
}

// Reopen after a rename (logrotate): the next events go to a new file at
// the path, the renamed file does not grow.
func TestJournalReopenAfterRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broker.log")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Event("broker_stop", map[string]any{"pid": 1})
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	old := readFile(t, rotated)
	if err := l.Reopen(); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	l.Event("tls_listen", map[string]any{"addr": "x"})
	if got := readFile(t, rotated); got != old {
		t.Errorf("rotated file grew after reopen:\n%s", got)
	}
	if got := readFile(t, path); !strings.Contains(got, `"event":"tls_listen"`) || strings.Contains(got, "broker_stop") {
		t.Errorf("new file = %q, want only the event after reopen", got)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("new journal %v %v, want mode 0600", st, err)
	}
}

// A failed reopen makes the journal unavailable (events to stderr, the
// reason on stderr); a later successful reopen ends it.
func TestJournalReopenFailureAndRecovery(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "log")
	path := filepath.Join(logDir, "broker.log")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stderr := &lockedBuffer{}
	l.stderr = stderr
	// the directory is gone and a regular file stands in its place: the
	// path cannot be opened, whoever the test runs as
	if err := os.RemoveAll(logDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Reopen(); err == nil {
		t.Fatal("reopen under a regular file succeeded")
	}
	if l.Unavailable() == nil {
		t.Fatal("journal still available after a failed reopen")
	}
	if err := l.Event("exec_exit", map[string]any{"token": "t1"}); !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("event while unavailable: %v", err)
	}
	got := stderr.String()
	for _, want := range []string{"journal unavailable", `"event":"audit_unavailable"`, "journal reopen", `"event":"exec_exit"`} {
		if !strings.Contains(got, want) {
			t.Errorf("stderr lacks %q:\n%s", want, got)
		}
	}
	if err := os.Remove(logDir); err != nil {
		t.Fatal(err)
	}
	if err := l.Reopen(); err != nil {
		t.Fatalf("reopen after repair: %v", err)
	}
	if l.Unavailable() != nil {
		t.Fatal("journal still unavailable after a successful reopen")
	}
	if err := l.Event("tls_listen", map[string]any{"addr": "x"}); err != nil {
		t.Fatalf("event after recovery: %v", err)
	}
	if !strings.Contains(readFile(t, path), `"event":"tls_listen"`) {
		t.Error("event after recovery not in the journal")
	}
	if !strings.Contains(stderr.String(), "accepting requests again") {
		t.Errorf("stderr lacks the recovery line:\n%s", stderr)
	}
}

// A closed journal sends events to stderr only.
func TestJournalClosed(t *testing.T) {
	l, err := NewLogger(filepath.Join(t.TempDir(), "broker.log"))
	if err != nil {
		t.Fatal(err)
	}
	stderr := &lockedBuffer{}
	l.stderr = stderr
	l.Close()
	if err := l.Event("broker_stop", map[string]any{"pid": 1}); err == nil {
		t.Fatal("event after close: want an error")
	}
	if !strings.Contains(stderr.String(), `"event":"broker_stop"`) {
		t.Errorf("event after close not on stderr: %q", stderr)
	}
}

// exchange sends req over a fresh in-memory connection served by
// serveRequest and returns the terminal frame (exit or denied).
func exchange(t *testing.T, b *Broker, req *proto.Request) *proto.Frame {
	t.Helper()
	srv, cli := net.Pipe()
	go func() { defer srv.Close(); b.serveRequest(srv, UIDRequester(4242, 1), "unix") }()
	defer cli.Close()
	if err := proto.WriteFrame(cli, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	return readTerminalFrame(t, cli)
}

// A write or fsync failure while a command runs: the command finishes and
// its exec_exit goes to the stderr reserve; from then on every new
// connection gets audit_unavailable and nothing runs, on both sockets; a
// successful reopen lets requests through again.
func TestJournalFailureFailsClosed(t *testing.T) {
	sleepExe, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("no sleep binary: %v", err)
	}
	touchExe, err := exec.LookPath("touch")
	if err != nil {
		t.Skipf("no touch binary: %v", err)
	}
	for _, kind := range []string{"write", "fsync"} {
		t.Run(kind, func(t *testing.T) {
			b := newTestBroker(t)
			stderr := &lockedBuffer{}
			b.log.stderr = stderr
			var broken atomic.Bool
			injected := errors.New("injected EIO")
			// started closes once exec_start is written AND fsynced: the
			// journal breaks only after the command's record is on disk
			var lastWasStart atomic.Bool
			started := make(chan struct{})
			var startedOnce sync.Once
			b.log.write = func(f *os.File, p []byte) (int, error) {
				if kind == "write" && broken.Load() {
					return 0, injected
				}
				lastWasStart.Store(strings.Contains(string(p), `"event":"exec_start"`))
				return f.Write(p)
			}
			b.log.sync = func(f *os.File) error {
				if kind == "fsync" && broken.Load() {
					return injected
				}
				err := f.Sync()
				if lastWasStart.Load() {
					startedOnce.Do(func() { close(started) })
				}
				return err
			}

			// a command that is running when the journal breaks
			running := &proto.Request{Type: "exec", Executable: sleepExe, Argv: []string{sleepExe, "0.5"},
				Cwd: "/tmp", Nonce: "journal-running-" + kind}
			exitc := make(chan *proto.Frame, 1)
			go func() {
				srv, cli := net.Pipe()
				go func() { defer srv.Close(); b.serveRequest(srv, UIDRequester(4242, 1), "unix") }()
				defer cli.Close()
				if err := proto.WriteFrame(cli, running); err != nil {
					exitc <- nil
					return
				}
				for {
					f, err := proto.ReadFrame(cli)
					if err != nil {
						exitc <- nil
						return
					}
					if f.Type == "exit" || f.Type == "denied" {
						exitc <- f
						return
					}
				}
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("exec_start never reached the disk")
			}
			broken.Store(true)

			marker := filepath.Join(t.TempDir(), "marker")
			touch := func(nonce string) *proto.Request {
				return &proto.Request{Type: "exec", Executable: touchExe, Argv: []string{touchExe, marker},
					Cwd: "/tmp", Nonce: nonce}
			}
			// a connection already past the gate: its request event fails
			if f := exchange(t, b, touch("journal-new-1-"+kind)); f.Type != "denied" || f.Reason != "audit_unavailable" {
				t.Fatalf("request after the failure: %+v, want denied audit_unavailable", f)
			}
			if b.log.Unavailable() == nil {
				t.Fatal("journal still available after an injected failure")
			}

			// new connections on both sockets are refused before anything else
			dir, err := os.MkdirTemp("", "tmbj")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			for _, sock := range []struct {
				name  string
				serve func(*net.UnixConn)
			}{{"requester", b.handleConn}, {"approver", b.handleApproverConn}} {
				path := filepath.Join(dir, sock.name+".sock")
				ln, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				go func() {
					if c, err := ln.Accept(); err == nil {
						sock.serve(c.(*net.UnixConn))
					}
				}()
				c, err := net.Dial("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				if err := proto.WriteFrame(c, touch("journal-new-2-"+kind)); err != nil {
					t.Fatal(err)
				}
				f, err := proto.ReadFrame(c)
				c.Close()
				ln.Close()
				if err != nil || f.Type != "denied" || f.Reason != "audit_unavailable" {
					t.Fatalf("%s socket while unavailable: %+v %v, want denied audit_unavailable", sock.name, f, err)
				}
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("marker exists (%v): a command ran without its record", err)
			}

			// the running command finished; its exit went to stderr
			select {
			case f := <-exitc:
				if f == nil || f.Type != "exit" || f.Code == nil || *f.Code != 0 {
					t.Fatalf("running command: %+v, want exit 0", f)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("running command never finished")
			}
			got := stderr.String()
			for _, want := range []string{`"event":"exec_exit"`, `"event":"audit_unavailable"`, "injected EIO", "journal " + kind} {
				if !strings.Contains(got, want) {
					t.Errorf("stderr lacks %q:\n%s", want, got)
				}
			}
			if kind == "write" && strings.Contains(readFile(t, b.log.Path()), `"event":"exec_exit"`) {
				t.Error("exec_exit reached the journal file through a failing write")
			}

			// repaired and reopened: requests pass again
			broken.Store(false)
			if err := b.log.Reopen(); err != nil {
				t.Fatalf("reopen: %v", err)
			}
			if f := exchange(t, b, touch("journal-new-3-"+kind)); f.Type != "exit" {
				t.Fatalf("after reopen: %+v, want exit", f)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Errorf("command after reopen did not run: %v", err)
			}
		})
	}
}

// A failure at the approval or the exec_start event stops the command
// before it starts.
func TestJournalFailureBeforeExec(t *testing.T) {
	touchExe, err := exec.LookPath("touch")
	if err != nil {
		t.Skipf("no touch binary: %v", err)
	}
	for _, at := range []string{"approval", "exec_start"} {
		t.Run(at, func(t *testing.T) {
			b := newTestBroker(t)
			b.log.stderr = &lockedBuffer{}
			b.log.write = func(f *os.File, p []byte) (int, error) {
				if strings.Contains(string(p), `"event":"`+at+`"`) {
					return 0, errors.New("injected EIO")
				}
				return f.Write(p)
			}
			marker := filepath.Join(t.TempDir(), "marker")
			f := exchange(t, b, &proto.Request{Type: "exec", Executable: touchExe,
				Argv: []string{touchExe, marker}, Cwd: "/tmp", Nonce: "journal-before-" + at})
			if f.Type != "denied" || f.Reason != "audit_unavailable" {
				t.Fatalf("got %+v, want denied audit_unavailable", f)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("marker exists (%v): the command ran without its record", err)
			}
		})
	}
}

// SIGHUP's Reload reopens the journal before its own events: after a
// rename, the reload event is already in the new file.
func TestReloadReopensJournal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeJSONConfig(t, path, reloadConfig(dir, nil))
	b := reloadBroker(t, path, ModeQueue)
	b.log.Event("broker_stop", map[string]any{"pid": 1})
	rotated := b.log.Path() + ".1"
	if err := os.Rename(b.log.Path(), rotated); err != nil {
		t.Fatal(err)
	}
	b.Reload(path)
	if got := readFile(t, b.log.Path()); !strings.Contains(got, `"event":"reload"`) {
		t.Errorf("reload event not in the reopened journal: %q", got)
	}
	if strings.Contains(readFile(t, rotated), `"event":"reload"`) {
		t.Error("reload event went to the rotated file")
	}
}

// A TLS connection to a broker whose journal is unavailable gets
// audit_unavailable after the handshake, and its request is not served.
func TestTLSConnRefusedWhileJournalDown(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	caFile := writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.cert.Raw)
	serverCert, serverKey, _ := ca.issue(t, dir, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	clientCert, clientKey, _ := ca.issue(t, dir, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	srvCfg, err := loadTLSConfig(caFile, serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	b := newTestBroker(t)
	stderr := &lockedBuffer{}
	b.log.stderr = stderr
	b.log.Close() // unavailable from here on
	b.tlsCfg.Store(srvCfg)
	server, client := net.Pipe()
	go b.handleTLSConn(tls.Server(server, b.listenerTLSConfig()))
	kp, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	c := tls.Client(client, &tls.Config{RootCAs: pool, ServerName: "localhost",
		Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS13})
	defer c.Close()
	req := testReq(t, "journal-tls")
	req.Type = "exec"
	if err := proto.WriteFrame(c, req); err != nil {
		t.Fatal(err)
	}
	if f := readTerminalFrame(t, c); f.Type != "denied" || f.Reason != "audit_unavailable" {
		t.Fatalf("tls while unavailable: %+v, want denied audit_unavailable", f)
	}
	if strings.Contains(stderr.String(), `"event":"request"`) {
		t.Error("the request was served while the journal was unavailable")
	}
}
