// PROTOTYPE CODE - throwaway PoC, not production.
//
//go:build linux

package main

// Exec-time identity pinning (security contract):
//
// The exe the human approved is pinned by an open read-only fd at approval
// time; at exec the broker execve()s /proc/self/fd/<N> so the kernel runs
// EXACTLY the approved inode even if the path is replaced in the window
// between claim validation and execve (the stat->execve TOCTOU). The fd is
// opened O_CLOEXEC (os.Open): fork inherits it regardless, execve resolves
// the /proc/self/fd symlink before CLOEXEC closes the fd on success, so the
// child still ends with only fds 0,1,2. Verified empirically by
// TestExecChildFdHygieneViaPinnedExec and harness scenario N11.
//
// The cwd is pinned the same way: an O_DIRECTORY fd opened at approval is
// held until exec, and the child chdirs to /proc/self/fd/<N>, so it starts
// in EXACTLY the approved directory even if the path is swapped after the
// last check. The path is still reopened and re-fstat'ed at claim time, and
// a mismatch (same path, new inode) denies with cwd_changed instead of
// running the command in a directory the human did not approve.

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
)

// pinApproval pins exec-time identities onto p: the exe inode via an open
// read-only fd, the cwd directory identity via dev/ino. Returns a
// (denyCode, denyDetail) pair when pinning proves the exe or cwd changed
// mid-validation and the approval must fail closed; ("", "") on success.
func pinApproval(p *pendingApproval, exeReal, cwdReal string, dev, ino uint64) (string, string) {
	f, pdev, pino, deny := pinExe(exeReal, dev, ino)
	if deny != "" {
		return deny, exeReal
	}
	p.ExeFile = f
	p.ExeDev, p.ExeIno = pdev, pino
	cf, cdev, cino, ok := pinDir(cwdReal)
	if !ok {
		p.closePins()
		return "cwd_invalid", cwdReal
	}
	p.CwdFile = cf
	p.CwdDev, p.CwdIno, p.CwdPinned = cdev, cino, true
	return "", ""
}

// exeReader returns the pinned exe fd for scriptDeny; release is a no-op,
// the fd stays pinned for exec.
func (p *pendingApproval) exeReader() (io.ReaderAt, func(), error) {
	if p.ExeFile == nil {
		return nil, nil, os.ErrClosed
	}
	return p.ExeFile, func() {}, nil
}

// pinExe opens exeReal read-only and fstats the fd to verify it is the file
// that was just stat'd as (dev, ino). On a stat/open race it re-resolves
// the path once; if the on-disk truth still is not the fd's file, the
// request is denied exe_changed, fail-closed.
func pinExe(exeReal string, dev, ino uint64) (f *os.File, pdev, pino uint64, deny string) {
	f, err := os.Open(exeReal) // O_RDONLY | O_CLOEXEC
	if err != nil {
		return nil, 0, 0, "exe_changed"
	}
	pdev, pino, ok := fdIdentity(f)
	if !ok {
		f.Close()
		return nil, 0, 0, "exe_changed"
	}
	if pdev == dev && pino == ino {
		return f, pdev, pino, ""
	}
	// swapped between stat and open: accept only if the path has settled
	// on exactly the fd's file
	if st, err := os.Stat(exeReal); err == nil {
		if sti, ok := st.Sys().(*syscall.Stat_t); ok &&
			uint64(sti.Dev) == pdev && uint64(sti.Ino) == pino {
			return f, pdev, pino, ""
		}
	}
	f.Close()
	return nil, 0, 0, "exe_changed"
}

// pinDir opens a directory read-only (O_DIRECTORY, O_CLOEXEC) and returns
// the fd with its identity; the fd is what the child later chdirs through.
func pinDir(path string) (*os.File, uint64, uint64, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, 0, 0, false
	}
	dev, ino, ok := fdIdentity(f)
	if !ok {
		f.Close()
		return nil, 0, 0, false
	}
	return f, dev, ino, true
}

func fdIdentity(f *os.File) (uint64, uint64, bool) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}

// cwdStillPinned reopens the cwd path and checks it is still the exact
// approved directory (dev, ino).
func cwdStillPinned(cwdReal string, dev, ino uint64) bool {
	fd, err := syscall.Open(cwdReal, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return false
	}
	return uint64(st.Dev) == dev && uint64(st.Ino) == ino
}

// execTarget returns the path to execve: the approved inode via
// /proc/self/fd/N (the fd survives fork; execve resolves the symlink in
// the child before CLOEXEC closes it), or the plain resolved path when no
// fd is pinned.
func (p *pendingApproval) execTarget() (string, bool) {
	if p.ExeFile == nil {
		return p.ExePath, false
	}
	return fmt.Sprintf("/proc/self/fd/%d", p.ExeFile.Fd()), true
}

// cwdTarget returns the directory the child chdirs to: the held directory
// via /proc/self/fd/N (inherited across fork, resolved by chdir before
// execve), or the plain resolved path when no fd is pinned.
func (p *pendingApproval) cwdTarget(cwdReal string) (string, bool) {
	if p.CwdFile == nil {
		return cwdReal, false
	}
	return fmt.Sprintf("/proc/self/fd/%d", p.CwdFile.Fd()), true
}

// closeOnExecInherited marks every descriptor above stderr close-on-exec, so
// the child ends with only the fds os/exec sets up (0, 1, 2). Go opens its
// own descriptors O_CLOEXEC; this covers descriptors the broker inherited
// from whatever started it. Failing to enumerate them denies the exec.
func closeOnExecInherited() error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("enumerate inherited fds: %w", err)
	}
	for _, e := range entries {
		if fd, err := strconv.Atoi(e.Name()); err == nil && fd > 2 {
			syscall.CloseOnExec(fd)
		}
	}
	return nil
}
