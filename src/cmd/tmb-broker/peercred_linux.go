//go:build linux

package main

import (
	"net"
	"syscall"
)

// peerCred resolves the identity of a unix-socket peer from the
// kernel-provided SO_PEERCRED credentials.
func peerCred(conn *net.UnixConn) (RequesterID, error) {
	var cred *syscall.Ucred
	var serr error
	raw, err := conn.SyscallConn()
	if err != nil {
		return RequesterID{}, err
	}
	err = raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return RequesterID{}, err
	}
	if serr != nil {
		return RequesterID{}, serr
	}
	return UIDRequester(cred.Uid, uint32(cred.Pid)), nil
}
