package main

import (
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tmb-poc/internal/proto"
)

// unixBroker serves the unix listener with the test process's own uid
// allowlisted (or not) and returns the socket path.
func unixBroker(t *testing.T, allowSelf bool) (*Broker, string) {
	t.Helper()
	b := newTestBroker(t)
	if allowSelf {
		uid := os.Getuid()
		if uid < 0 || uid > math.MaxUint32 {
			panic("uid does not fit a uint32")
		}
		b.conf().AllowedRequesterUIDs = []uint32{uint32(uid)}
	}
	dir, err := os.MkdirTemp("", "tmbsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "b.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go b.Serve(ln)
	return b, sock
}

func send(t *testing.T, sock string, req *proto.Request) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteFrame(conn, req); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

func terminal(t *testing.T, conn net.Conn) *proto.Frame {
	t.Helper()
	f, err := readTerminal(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return f
}

// readTerminal reads frames until exit or denied and closes conn.
func readTerminal(conn net.Conn) (*proto.Frame, error) {
	defer conn.Close()
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			return nil, err
		}
		if f.Type == "exit" || f.Type == "denied" {
			return f, nil
		}
	}
}

// exchange sends req on a new connection and returns its terminal frame.
// It does not touch t, so goroutines can call it.
func exchange(sock string, req *proto.Request) (*proto.Frame, error) {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := proto.WriteFrame(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return readTerminal(conn)
}

func TestServeUnixDeniesNonAllowlistedUID(t *testing.T) {
	_, sock := unixBroker(t, false)
	req := testReq(t, "unix-not-allowed")
	req.Type = "exec"
	f := terminal(t, send(t, sock, req))
	if f.Type != "denied" || f.Reason != "requester_not_allowed" {
		t.Fatalf("frame = %+v, want denied requester_not_allowed", f)
	}
}

// SEC-16: concurrent connections redeeming one approval run it at most
// once, over the real listener and SO_PEERCRED.
func TestServeUnixConcurrentConnectionsRunAtMostOnce(t *testing.T) {
	_, sock := unixBroker(t, true)
	req := testReq(t, "unix-concurrent")
	req.Type = "approve"
	approvedFrame, err := proto.ReadFrame(send(t, sock, req))
	if err != nil || approvedFrame.Type != "approved" {
		t.Fatalf("approve: %+v, %v", approvedFrame, err)
	}
	req.Type, req.ClaimToken = "claim", approvedFrame.Token

	const n = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	exits := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := exchange(sock, req)
			if err != nil {
				t.Errorf("concurrent claim: %v", err)
				return
			}
			if f.Type == "exit" {
				mu.Lock()
				exits++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if exits != 1 {
		t.Fatalf("%d concurrent connections executed %d times, want 1", n, exits)
	}
}

// SEC-16: a client that disconnects mid-flow does not get a second run of
// the same request, and the listener keeps serving.
func TestServeUnixClientDisconnect(t *testing.T) {
	b, sock := unixBroker(t, true)

	// connect and leave without a frame
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	// exec, then drop the connection as soon as the approval arrives while
	// the command is still writing output
	sh := shExe(t)
	req := testReq(t, "unix-disconnect")
	req.Type, req.Executable, req.Argv = "exec", sh, []string{sh, "-c", "head -c 4194304 /dev/zero"}
	conn = send(t, sock, req)
	if f, err := proto.ReadFrame(conn); err != nil || f.Type != "approved" {
		t.Fatalf("exec: first frame %+v, %v; want approved", f, err)
	}
	conn.Close()

	// the same request again: approval is granted anew but the claim is spent
	deadline := time.Now().Add(5 * time.Second)
	for {
		log, _ := os.ReadFile(b.log.f.Name())
		if strings.Contains(string(log), `"event":"exec_exit"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the abandoned exec never finished; log:\n%s", log)
		}
		time.Sleep(20 * time.Millisecond)
	}
	f := terminal(t, send(t, sock, req))
	if f.Type != "denied" || f.Reason != "token_consumed_replay" {
		t.Fatalf("replay after disconnect = %+v, want denied token_consumed_replay", f)
	}
	log, _ := os.ReadFile(b.log.f.Name())
	if !strings.Contains(string(log), `"event":"bad_frame"`) {
		t.Errorf("the empty connection left no bad_frame event:\n%s", log)
	}
}

// SEC-16: an approval granted to one requester cannot be redeemed by
// another one through concurrent connections, and stays redeemable by its
// owner.
func TestServeUnixConcurrentForeignClaimsKeepIdentityBinding(t *testing.T) {
	b, sock := unixBroker(t, true)
	owner := UIDRequester(4242, 1) // never the test process's own uid
	req := approved(t, b, testReq(t, "unix-foreign"), owner)
	req.Type = "claim"

	const n = 32
	var wg sync.WaitGroup
	frames := make(chan *proto.Frame, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := exchange(sock, req)
			if err != nil {
				t.Errorf("foreign claim: %v", err)
				return
			}
			frames <- f
		}()
	}
	wg.Wait()
	close(frames)
	for f := range frames {
		if f.Type != "denied" || f.Reason != "requester_mismatch" {
			t.Fatalf("foreign claim = %+v, want denied requester_mismatch", f)
		}
	}
	if f := claimDo(t, b, req, owner); f.Type != "exit" {
		t.Fatalf("owner claim after foreign attempts = %+v, want exit", f)
	}
}
