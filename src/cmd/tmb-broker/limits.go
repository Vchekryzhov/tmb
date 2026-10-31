// PROTOTYPE CODE - throwaway PoC, not production.
package main

// Connection limits. A hostile requester can open connections and send
// frames slowly; these bounds keep that from exhausting the broker's fds,
// goroutines and memory, and from ending an accept loop.

import (
	"errors"
	"net"
	"time"
)

// maxConnsPerListener bounds the connections one listener serves at once.
// A waiting queue request holds its connection, so the bound is well above
// any queue a human works through; the approver socket has its own bound,
// so requesters cannot starve approvers.
const maxConnsPerListener = 256

// requestReadTimeout bounds how long a peer may take to deliver its one
// request frame after the connection is accepted.
const requestReadTimeout = 30 * time.Second

// acceptBackoffMax caps the pause after a failed Accept (EMFILE and the like).
const acceptBackoffMax = time.Second

// serveConns runs an accept loop: at most maxConnsPerListener connections
// are served at once (further peers wait in the listen backlog), and a
// failed Accept is retried with backoff instead of ending the loop. It
// returns only when the listener is closed.
func serveConns(ln net.Listener, handle func(net.Conn)) error {
	slots := make(chan struct{}, maxConnsPerListener)
	var backoff time.Duration
	for {
		slots <- struct{}{}
		conn, err := ln.Accept()
		if err != nil {
			<-slots
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > acceptBackoffMax {
				backoff = acceptBackoffMax
			}
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		go func() {
			defer func() { <-slots }()
			handle(conn)
		}()
	}
}
