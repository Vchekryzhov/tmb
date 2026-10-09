// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
)

// loadTLSConfig builds the server-side TLS config for the mTLS listener:
// TLS 1.3 minimum, client certificates REQUIRED and verified against the
// configured CA. There is no plaintext fallback - this is the only thing the
// TCP listener ever speaks.
func loadTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("tls ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("tls ca %s: no certificates parsed", caFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls server keypair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// certFingerprint is the requester identity of a client certificate:
// lowercase hex SHA-256 over the DER encoding, matching
// `openssl x509 -fingerprint -sha256` with the colons stripped.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ServeTLS runs the accept loop of the TLS listener. Handshakes are driven
// explicitly per connection so failures surface as tls_handshake_failed
// events instead of a lazy first-read error deep in the frame loop.
func (b *Broker) ServeTLS(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go b.handleTLSConn(conn.(*tls.Conn))
	}
}

// tlsHandshakeTimeout bounds one handshake so dead peers cannot pin
// connection goroutines.
const tlsHandshakeTimeout = 10 * time.Second

func (b *Broker) handleTLSConn(conn *tls.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := conn.Handshake(); err != nil {
		// No client certificate was verified -> no fingerprint exists yet.
		b.log.Event("tls_handshake_failed", map[string]any{
			"remote": conn.RemoteAddr().String(), "error": err.Error(),
		})
		return
	}
	_ = conn.SetDeadline(time.Time{})

	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		// Unreachable under RequireAndVerifyClientCert; fail closed anyway.
		b.log.Event("tls_no_client_cert", map[string]any{
			"remote": conn.RemoteAddr().String(),
		})
		return
	}
	id := CertRequester(certFingerprint(st.PeerCertificates[0].Raw))

	if !b.allowedRequester(id) {
		b.denyRequesterNotAllowed(conn, id)
		return
	}
	b.serveRequest(conn, id, "tls")
}
