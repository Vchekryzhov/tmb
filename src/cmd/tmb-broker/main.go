// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "ca" {
		os.Exit(runCA(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, stop))
}

// chown is os.Chown; unprivileged tests replace it, since only root may
// hand the socket to root.
var chown = os.Chown

// run starts the broker and serves until stop fires (exit 0, socket and
// pidfile removed) or a listener fails (exit 1). Setup errors exit 1, flag
// errors 2.
func run(args []string, stdout, stderr io.Writer, stop <-chan os.Signal) int {
	fs := flag.NewFlagSet("tmb-broker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/tmb/config.json", "config file path")
	approval := fs.String("approval", "", "approval mode override: manual|mock-approve|mock-deny|mock-timeout")
	ttlSec := fs.Int("ttl", 0, "token TTL seconds override (PoC: sign short TTLs, e.g. 2-3; production default 60)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "tmb-broker: "+format+"\n", a...)
		return 1
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fail("config: %v", err)
	}
	mode := cfg.ApprovalDefault
	if *approval != "" {
		mode = *approval
	}
	switch mode {
	case ModeQueue, ModeManual, ModeMockApprove, ModeMockDeny, ModeMockTimeout:
	default:
		return fail("unknown approval mode %q", mode)
	}
	ttl := time.Duration(cfg.TokenTTLSeconds) * time.Second
	if *ttlSec > 0 {
		ttl = time.Duration(*ttlSec) * time.Second
	}

	log, err := NewLogger(cfg.LogPath)
	if err != nil {
		return fail("log: %v", err)
	}
	defer log.Close()

	claims, err := NewClaimStore(cfg.StateDir, ttl)
	if err != nil {
		return fail("claim store: %v", err)
	}
	gcStop := make(chan struct{})
	defer close(gcStop)                                // runs before log.Close: the loop never logs into a closed file
	startClaimGC(claims, log, claimGCInterval, gcStop) // before any socket opens

	// socket dir: root:tmb-gid 0755 so unprivileged clients can traverse
	if err := os.MkdirAll(cfg.SocketPath[:lastSlash(cfg.SocketPath)], 0o755); err != nil {
		return fail("socket dir: %v", err)
	}
	if err := chown(cfg.SocketPath[:lastSlash(cfg.SocketPath)], 0, int(cfg.SocketGID)); err != nil {
		return fail("socket dir chown (gid %d): %v", cfg.SocketGID, err)
	}

	// remove a stale socket from a previous run
	if err := os.Remove(cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fail("stale socket: %v", err)
	}

	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return fail("listen %s: %v", cfg.SocketPath, err)
	}
	defer ln.Close()
	// 0660 root:<socket gid>: the sandbox group may connect; everyone else
	// is refused by filesystem permissions even before SO_PEERCRED.
	if err := os.Chmod(cfg.SocketPath, 0o660); err != nil {
		return fail("chmod socket: %v", err)
	}
	if err := chown(cfg.SocketPath, 0, int(cfg.SocketGID)); err != nil {
		return fail("chown socket: %v", err)
	}

	tlsAddr, tlsCA, tlsCert, tlsKey := cfg.TLSAddr, cfg.TLSCAFile, cfg.TLSCertFile, cfg.TLSKeyFile

	var tlsCfg *tls.Config
	var tlsLn net.Listener
	if tlsAddr != "" {
		if tlsCA == "" || tlsCert == "" || tlsKey == "" {
			return fail("tls_addr %s requires tls_ca_file, tls_cert_file and tls_key_file", tlsAddr)
		}
		tlsCfg, err = loadTLSConfig(tlsCA, tlsCert, tlsKey)
		if err != nil {
			return fail("%v", err)
		}
		tlsLn, err = net.Listen("tcp", tlsAddr)
		if err != nil {
			return fail("tls listen %s: %v", tlsAddr, err)
		}
		defer tlsLn.Close()
	}

	if err := os.WriteFile(cfg.PidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		return fail("pidfile: %v", err)
	}

	b := NewBroker(cfg, log, claims, mode, ttl)
	startEv := map[string]any{
		"pid": os.Getpid(), "socket": cfg.SocketPath, "mode": mode,
		"ttl_seconds": int(ttl.Seconds()), "allowed_requester_uids": cfg.AllowedRequesterUIDs,
		"allowed_requester_keys": cfg.AllowedRequesterKeys,
	}
	if tlsLn != nil {
		startEv["tls_addr"] = tlsAddr
	}
	log.Event("broker_start", startEv)
	fmt.Fprintf(stdout, "tmb-broker: listening on %s (mode=%s ttl=%s pid=%d)\n", cfg.SocketPath, mode, ttl, os.Getpid())

	// Both accept loops only ever return an error; the first one ends the
	// broker unless a stop signal came first.
	served := make(chan error, 2)
	go func() { served <- fmt.Errorf("serve: %w", b.Serve(ln)) }()
	if tlsLn != nil {
		log.Event("tls_listen", map[string]any{"addr": tlsAddr})
		fmt.Fprintf(stdout, "tmb-broker: tls listening on %s (client certificates required, no plaintext)\n", tlsAddr)
		go func() { served <- fmt.Errorf("tls serve: %w", b.ServeTLS(tls.NewListener(tlsLn, tlsCfg))) }()
	}

	if err := b.startApprover(cfg.ApproverSocketPath); err != nil {
		return fail("approver socket: %v", err)
	}

	select {
	case <-stop:
		// SIGTERM/SIGINT: remove socket + pidfile, then exit. A stale socket
		// is also unlinked at next startup.
		ln.Close()
		if tlsLn != nil {
			tlsLn.Close()
		}
		os.Remove(cfg.SocketPath)
		os.Remove(cfg.PidFile)
		log.Event("broker_stop", map[string]any{"pid": os.Getpid()})
		return 0
	case err := <-served:
		return fail("%v", err)
	}
}

func lastSlash(p string) int {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return i
		}
	}
	return 0
}
