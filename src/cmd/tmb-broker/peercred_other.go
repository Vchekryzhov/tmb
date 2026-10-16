//go:build !linux

package main

import (
	"fmt"
	"net"
)

// peerCred is unavailable off Linux: SO_PEERCRED is a Linux kernel feature.
// The unix listener refuses every peer (fail closed) on such platforms; the
// broker itself only runs in the Linux host-sim container.
func peerCred(conn *net.UnixConn) (RequesterID, error) {
	return RequesterID{}, fmt.Errorf("SO_PEERCRED not available on this platform")
}
