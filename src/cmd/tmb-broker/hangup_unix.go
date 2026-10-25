//go:build linux || darwin

package main

import (
	"errors"
	"net"
	"syscall"
)

// socketReadReady checks for EOF or unexpected input hidden by the watch's
// cancellation deadline. No reader may run concurrently with this probe.
func socketReadReady(conn net.Conn) bool {
	// TLS owns the record layer; peek at its transport without consuming
	// encrypted bytes. Pending control records conservatively abandon too.
	for {
		wrapped, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		conn = wrapped.NetConn()
	}
	socket, ok := conn.(syscall.Conn)
	if !ok {
		// In-memory test connections have no kernel buffer. Their completed
		// Read already distinguishes peer closure from deadline cancellation.
		return false
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return true
	}
	var ready bool
	err = raw.Control(func(fd uintptr) {
		var buf [1]byte
		_, _, readErr := syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		ready = !errors.Is(readErr, syscall.EAGAIN) && !errors.Is(readErr, syscall.EWOULDBLOCK)
	})
	return err != nil || ready
}
