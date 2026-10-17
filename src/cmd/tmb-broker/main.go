// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tmb-poc/internal/buildinfo"
)

func main() {
	if buildinfo.HandleVersion("tmb-broker", os.Args[1:], os.Stdout) {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "ca" {
		os.Exit(runCA(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	cfgPath := flag.String("config", "/etc/tmb/config.json", "config file path")
	approval := flag.String("approval", "", "approval mode override: manual|mock-approve|mock-deny|mock-timeout")
	ttlSec := flag.Int("ttl", 0, "token TTL seconds override (PoC: sign short TTLs, e.g. 2-3; production default 60)")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: config: %v\n", err)
		os.Exit(1)
	}
	mode := cfg.ApprovalDefault
	if *approval != "" {
		mode = *approval
	}
	switch mode {
	case ModeQueue, ModeManual, ModeMockApprove, ModeMockDeny, ModeMockTimeout:
	default:
		fmt.Fprintf(os.Stderr, "tmb-broker: unknown approval mode %q\n", mode)
		os.Exit(1)
	}
	ttl := time.Duration(cfg.TokenTTLSeconds) * time.Second
	if *ttlSec > 0 {
		ttl = time.Duration(*ttlSec) * time.Second
	}

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	log, err := NewLogger(cfg.LogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: log: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	claims, err := NewClaimStore(cfg.StateDir, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: claim store: %v\n", err)
		os.Exit(1)
	}
	startClaimGC(claims, log, claimGCInterval, nil) // before any socket opens

	// socket dir: root:tmb-gid 0755 so unprivileged clients can traverse
	if err := os.MkdirAll(cfg.SocketPath[:lastSlash(cfg.SocketPath)], 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: socket dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.Chown(cfg.SocketPath[:lastSlash(cfg.SocketPath)], 0, int(cfg.SocketGID)); err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: socket dir chown (gid %d): %v\n", cfg.SocketGID, err)
		os.Exit(1)
	}

	// remove a stale socket from a previous run
	if err := os.Remove(cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "tmb-broker: stale socket: %v\n", err)
		os.Exit(1)
	}

	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: listen %s: %v\n", cfg.SocketPath, err)
		os.Exit(1)
	}
	// 0660 root:<socket gid>: the sandbox group may connect; everyone else
	// is refused by filesystem permissions even before SO_PEERCRED.
	if err := os.Chmod(cfg.SocketPath, 0o660); err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: chmod socket: %v\n", err)
		os.Exit(1)
	}
	if err := os.Chown(cfg.SocketPath, 0, int(cfg.SocketGID)); err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: chown socket: %v\n", err)
		os.Exit(1)
	}

	tlsAddr, tlsCA, tlsCert, tlsKey := cfg.TLSAddr, cfg.TLSCAFile, cfg.TLSCertFile, cfg.TLSKeyFile

	var tlsCfg *tls.Config
	var tlsLn net.Listener
	if tlsAddr != "" {
		if tlsCA == "" || tlsCert == "" || tlsKey == "" {
			fmt.Fprintf(os.Stderr, "tmb-broker: tls_addr %s requires tls_ca_file, tls_cert_file and tls_key_file\n", tlsAddr)
			os.Exit(1)
		}
		tlsCfg, err = loadTLSConfig(tlsCA, tlsCert, tlsKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tmb-broker: %v\n", err)
			os.Exit(1)
		}
		tlsLn, err = net.Listen("tcp", tlsAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tmb-broker: tls listen %s: %v\n", tlsAddr, err)
			os.Exit(1)
		}
	}

	if err := os.WriteFile(cfg.PidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: pidfile: %v\n", err)
		os.Exit(1)
	}

	b := NewBroker(cfg, log, claims, mode, ttl)
	if *ttlSec > 0 {
		b.ttlFlag = ttl
	}
	if tlsCfg != nil {
		b.tlsCfg.Store(tlsCfg)
	}
	startEv := map[string]any{
		"pid": os.Getpid(), "socket": cfg.SocketPath, "mode": mode,
		"ttl_seconds": int(ttl.Seconds()), "allowed_requester_uids": cfg.AllowedRequesterUIDs,
		"allowed_requester_keys": cfg.AllowedRequesterKeys,
	}
	if tlsLn != nil {
		startEv["tls_addr"] = tlsAddr
	}
	log.Event("broker_start", startEv)
	fmt.Printf("tmb-broker: listening on %s (mode=%s ttl=%s pid=%d)\n", cfg.SocketPath, mode, ttl, os.Getpid())
	if tlsLn != nil {
		log.Event("tls_listen", map[string]any{"addr": tlsAddr})
		fmt.Printf("tmb-broker: tls listening on %s (client certificates required, no plaintext)\n", tlsAddr)
		go func() {
			if err := b.ServeTLS(tls.NewListener(tlsLn, b.listenerTLSConfig())); err != nil {
				fmt.Fprintf(os.Stderr, "tmb-broker: tls serve: %v\n", err)
				os.Exit(1)
			}
		}()
	}

	if err := b.startApprover(cfg.ApproverSocketPath); err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: approver socket: %v\n", err)
		os.Exit(1)
	}

	// SIGHUP (systemctl reload): re-read the config; the sockets, the queue
	// and pending approvals stay. Registered before the sockets open, so an
	// early SIGHUP waits here instead of killing the process.
	go func() {
		for range hup {
			b.Reload(*cfgPath)
		}
	}()

	// SIGTERM/SIGINT: remove socket + pidfile, then exit. A stale socket is
	// also unlinked at next startup.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		ln.Close()
		if tlsLn != nil {
			tlsLn.Close()
		}
		os.Remove(cfg.SocketPath)
		os.Remove(cfg.PidFile)
		log.Event("broker_stop", map[string]any{"pid": os.Getpid()})
		os.Exit(0)
	}()

	if err := b.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "tmb-broker: serve: %v\n", err)
		os.Exit(1)
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
