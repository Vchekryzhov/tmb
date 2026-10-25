//go:build linux || darwin

package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestUnixDisconnectedExecIsNotRunWhenDecisionIsReady(t *testing.T) {
	testDisconnectedExec(t, unixConnectionPair)
}

func TestTLSDisconnectedExecIsNotRunWhenDecisionIsReady(t *testing.T) {
	testDisconnectedExec(t, func(t *testing.T) (net.Conn, net.Conn) {
		server, client := unixConnectionPair(t)
		ca := newTestCA(t)
		cert, key, _ := ca.issue(t, t.TempDir(), "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
		pool := x509.NewCertPool()
		pool.AddCert(ca.cert)
		return tls.Server(server, &tls.Config{Certificates: []tls.Certificate{loadPair(t, cert, key)}, MinVersion: tls.VersionTLS13}),
			tls.Client(client, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	})
}

func unixConnectionPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	files := [2]*os.File{os.NewFile(uintptr(fds[0]), "server"), os.NewFile(uintptr(fds[1]), "client")}
	defer files[0].Close()
	defer files[1].Close()
	server, err := net.FileConn(files[0])
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.FileConn(files[1])
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(); client.Close() })
	return server, client
}
