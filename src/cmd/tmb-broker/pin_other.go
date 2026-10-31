// PROTOTYPE CODE - throwaway PoC, not production.
//
//go:build !linux

package main

import (
	"io"
	"os"
)

// The broker is a Linux PoC (unix socket listener, /proc/self/fd exec); it
// is never run elsewhere. These stubs keep the package buildable/testable
// on dev machines: approvals are not fd-pinned and exec uses the resolved
// exe and cwd paths, so the pinning guarantees DO NOT hold off-Linux.

func pinApproval(p *pendingApproval, exeReal, cwdReal string, dev, ino uint64) (string, string) {
	return "", ""
}

func cwdStillPinned(cwdReal string, dev, ino uint64) bool { return true }

func (p *pendingApproval) execTarget() (string, bool) { return p.ExePath, false }

func (p *pendingApproval) cwdTarget(cwdReal string) (string, bool) { return cwdReal, false }

func closeOnExecInherited() error { return nil }

// exeReader opens the approved path: nothing is pinned off-Linux (the
// broker ships only for Linux, so this open may run under b.mu).
func (p *pendingApproval) exeReader() (io.ReaderAt, func(), error) {
	f, err := os.Open(p.ExePath)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}
