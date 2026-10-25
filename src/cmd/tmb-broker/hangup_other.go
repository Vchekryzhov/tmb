//go:build !linux && !darwin

package main

import "net"

// The broker supports Linux; Darwin exists for development tests. Unknown
// platforms cannot prove the connection is live after cancelling its read.
func socketReadReady(net.Conn) bool { return true }
