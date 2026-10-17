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

// listenerTLSConfig is the config of the TLS listener itself: every
// handshake takes the current material from the snapshot, so a reload
// reaches new connections only; an established connection keeps what it
// was handshaken with until it closes.
func (b *Broker) listenerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return b.tlsCfg.Load(), nil
		},
	}
}

// keyFingerprint is the requester identity of a client certificate:
// lowercase hex SHA-256 over its DER SubjectPublicKeyInfo. Every
// certificate issued on the same key has the same fingerprint (ADR 0005).
func keyFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// ServeTLS runs the accept loop of the TLS listener. Handshakes are driven
// explicitly per connection so failures surface as tls_handshake_failed
// events instead of a lazy first-read error deep in the frame loop.
func (b *Broker) ServeTLS(ln net.Listener) error {
	return serveConns(ln, func(c net.Conn) { b.handleTLSConn(c.(*tls.Conn)) })
}

// tlsHandshakeTimeout bounds one handshake so dead peers cannot pin
// connection goroutines.
const tlsHandshakeTimeout = 10 * time.Second

func (b *Broker) handleTLSConn(conn *tls.Conn) {
	defer conn.Close()
	// read before the handshake: a journal that fails meanwhile still
	// refuses this connection at the request event
	down := b.log.Unavailable() != nil
	_ = conn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
	if err := conn.Handshake(); err != nil {
		// No client certificate was verified -> no fingerprint exists yet.
		b.log.Event("tls_handshake_failed", map[string]any{
			"remote": conn.RemoteAddr().String(), "error": err.Error(),
		})
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if down {
		// the denial needs a handshaken channel; nothing else is done
		b.refuseAuditDown(conn)
		return
	}

	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		// Unreachable under RequireAndVerifyClientCert; fail closed anyway.
		b.log.Event("tls_no_client_cert", map[string]any{
			"remote": conn.RemoteAddr().String(),
		})
		return
	}
	id := KeyRequester(keyFingerprint(st.PeerCertificates[0]))

	if !b.allowedRequester(id) {
		b.denyRequesterNotAllowed(conn, id)
		return
	}
	b.serveRequest(conn, id, "tls")
}
