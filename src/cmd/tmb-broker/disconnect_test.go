package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"tmb-poc/internal/proto"
)

// Deliver the decision and disconnect before the broker resumes after its
// waiting frame. Both notifications can then race at the approval boundary.
func TestDisconnectedExecIsNotRunWhenDecisionIsReady(t *testing.T) {
	testDisconnectedExec(t, func(*testing.T) (net.Conn, net.Conn) { return net.Pipe() })
}

func testDisconnectedExec(t *testing.T, pair func(*testing.T) (net.Conn, net.Conn)) {
	t.Helper()
	t.Run("disconnected", func(t *testing.T) { testQueuedExecDecision(t, pair, true) })
	t.Run("connected", func(t *testing.T) { testQueuedExecDecision(t, pair, false) })
}

func testQueuedExecDecision(t *testing.T, pair func(*testing.T) (net.Conn, net.Conn), disconnect bool) {
	t.Helper()
	for i := 0; i < 30; i++ {
		b := newQueueBroker(t)
		exe, err := exec.LookPath("touch")
		if err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(t.TempDir(), "ran-after-disconnect")
		req := &proto.Request{Type: "exec", Executable: exe, Argv: []string{exe, marker}, Cwd: "/tmp", Nonce: "disconnected-exec"}
		server, client := pair(t)
		t.Cleanup(func() { server.Close(); client.Close() })
		reader := make(chan *proto.Frame, 1)
		go func() {
			defer close(reader)
			_ = proto.WriteFrame(client, req)
			for {
				f, err := proto.ReadFrame(client)
				if err != nil {
					return
				}
				if f.Type == "exit" {
					reader <- f
					return
				}
			}
		}()
		conn := &decisionOnWaitingConn{Conn: server}
		conn.afterWaiting = func() {
			f := approverDo(t, b, UIDRequester(humanUID, 1), &proto.Request{
				Type: "decide", ItemID: proto.TokenID(req.Hash()), ItemHash: req.Hash(), Decision: "approve",
			})
			if f.Type != "decided" {
				t.Fatalf("decision = %+v, want decided", f)
			}
			if disconnect {
				client.Close()
			}
		}
		b.serveRequest(conn, UIDRequester(4242, 7), "unix")
		server.Close()
		f := <-reader
		_, err = os.Stat(marker)
		if disconnect {
			if !os.IsNotExist(err) {
				t.Fatalf("iteration %d: disconnected request ran: stat = %v", i, err)
			}
			if !lineHasBoth(logText(t, b), `"event":"approval"`, `"reason":"request_abandoned"`) {
				t.Fatalf("iteration %d: disconnected request was not abandoned", i)
			}
		} else if err != nil || f == nil || f.Code == nil || *f.Code != 0 {
			t.Fatalf("iteration %d: live request failed: stat = %v, frame = %+v", i, err, f)
		}
	}
}

type decisionOnWaitingConn struct {
	net.Conn
	afterWaiting func()
}

func (c *decisionOnWaitingConn) NetConn() net.Conn { return c.Conn }

func (c *decisionOnWaitingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err == nil && bytes.Contains(p, []byte(`"type":"waiting"`)) {
		c.afterWaiting()
	}
	return n, err
}
