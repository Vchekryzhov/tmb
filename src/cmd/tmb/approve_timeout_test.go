package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A broker that accepts the approver connection and then never answers
// does not hang tmb approve: past the I/O deadline it is a transport
// error (exit 3).
func TestApproveHungBrokerTimesOut(t *testing.T) {
	dir, err := os.MkdirTemp("", "tmbh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	held := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held <- c // read nothing, answer nothing
		}
	}()
	t.Cleanup(func() {
		for len(held) > 0 {
			(<-held).Close()
		}
	})

	orig := approverIOTimeout
	approverIOTimeout = 200 * time.Millisecond
	t.Cleanup(func() { approverIOTimeout = orig })
	start := time.Now()
	code, out, errs := runApprove(t, "", "--list", "--socket", path)
	if code != 3 || out != "" || !strings.Contains(errs, "timeout") {
		t.Errorf("hung broker: exit %d out %q err %q, want exit 3 with a timeout", code, out, errs)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}
