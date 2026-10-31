// PROTOTYPE CODE - throwaway PoC, not production.
package proto

// The approval payload (ADR 0006): the exact bytes a trusted signer shows
// and signs, built by the broker once per queue item. The broker is the only
// source of these bytes; a signer parses them, shows what it parsed and signs
// the received array, never its own serialization.
//
// Format: the domain prefix "tmb-approval-v1\x00" followed by one JSON object
// in canonical form. Canonical means exactly what canonicalJSON produces:
// fields in the declaration order of ApprovalPayload, no whitespace, strings
// escaped as encoding/json does with HTML escaping off (\" \\ \b \f \n \r \t,
// other control characters as \u00xx, U+2028 and U+2029 as \u2028 and
// \u2029, everything else literal UTF-8), integers in decimal. A parser
// accepts the bytes only when re-encoding what it parsed gives the same
// bytes, so duplicate keys, unknown or missing fields, another order,
// whitespace, other escapes and invalid UTF-8 are all refused. The Swift
// signer implements the same rule; signer/Tests/vectors holds the shared
// vectors both sides test against.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// PayloadPrefix separates the approval payload from every other signed
// format: a signature over it is no SSH signature and no other version.
const PayloadPrefix = "tmb-approval-v1\x00"

// shortCodePrefix separates the short code hash from the signing digest.
const shortCodePrefix = "tmb-approval-code-v1\x00"

// ShortCodeLen is the number of base32 characters in a short code.
const ShortCodeLen = 8

// ApprovalPayload is everything one approval binds to (ADR 0006, В12): the
// host, the queue item, the broker challenge, who asked, what runs as whom
// and where (as the broker resolved it), and the broker's deadlines. The
// field order is the canonical order.
type ApprovalPayload struct {
	HostID      string   `json:"host_id"`      // host_id from the broker config
	HostKey     string   `json:"host_key"`     // SPKI SHA-256 of the broker TLS server key; "" without a TLS listener
	ItemID      string   `json:"item_id"`      // queue item id (TokenID of the request hash)
	RequestHash string   `json:"request_hash"` // full Request.Hash()
	Challenge   string   `json:"challenge"`    // 32 random bytes per item, hex
	Requester   string   `json:"requester"`    // requester identity (uid:N or keyfp:HEX)
	UID         int      `json:"uid"`          // target uid
	User        string   `json:"user"`         // target user name; "" when the uid has none
	Executable  string   `json:"executable"`   // realpath
	ExeDev      uint64   `json:"exe_dev"`      // pinned inode of the executable
	ExeIno      uint64   `json:"exe_ino"`
	Argv        []string `json:"argv"`
	Cwd         string   `json:"cwd"` // realpath
	Env         []string `json:"env"` // final process environment, KEY=VALUE sorted
	Nonce       string   `json:"nonce"`
	QueuedAt    int64    `json:"queued_at"`         // unix milliseconds, broker clock
	Deadline    int64    `json:"deadline"`          // unix milliseconds: no decision is accepted after it
	TokenTTL    int      `json:"token_ttl_seconds"` // the token issued on approval lives at most this long
}

// canonicalJSON encodes p in canonical form (without the prefix). Nil
// slices encode as empty arrays, so the encoding of a built payload never
// contains null.
func (p *ApprovalPayload) canonicalJSON() ([]byte, error) {
	c := *p
	if c.Argv == nil {
		c.Argv = []string{}
	}
	if c.Env == nil {
		c.Env = []string{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&c); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Encode returns the payload bytes: prefix and canonical JSON. It refuses a
// payload with a string that is not valid UTF-8 (encoding/json would replace
// the bytes and the signer would be shown another path than the one that
// runs) and one that does not pass the field checks of ParseApprovalPayload.
func (p *ApprovalPayload) Encode() ([]byte, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	for _, s := range p.strings() {
		if !utf8.ValidString(s) {
			return nil, fmt.Errorf("proto: approval payload: %q is not valid UTF-8", s)
		}
	}
	js, err := p.canonicalJSON()
	if err != nil {
		return nil, err
	}
	return append([]byte(PayloadPrefix), js...), nil
}

func (p *ApprovalPayload) strings() []string {
	out := []string{p.HostID, p.HostKey, p.ItemID, p.RequestHash, p.Challenge, p.Requester, p.User, p.Executable, p.Cwd, p.Nonce}
	out = append(out, p.Argv...)
	return append(out, p.Env...)
}

// check holds the field rules every payload must pass, built or parsed.
func (p *ApprovalPayload) check() error {
	switch {
	case p.HostID == "":
		return errors.New("proto: approval payload: empty host_id")
	case p.HostKey != "" && !isHex(p.HostKey, 64):
		return errors.New("proto: approval payload: host_key is not a SHA-256 hex fingerprint")
	case !isHex(p.RequestHash, 64):
		return errors.New("proto: approval payload: request_hash is not a SHA-256 hex digest")
	case p.ItemID != TokenID(p.RequestHash):
		return errors.New("proto: approval payload: item_id does not match request_hash")
	case !isHex(p.Challenge, 64):
		return errors.New("proto: approval payload: challenge is not 32 bytes of hex")
	case p.Requester == "" || p.Executable == "" || p.Cwd == "":
		return errors.New("proto: approval payload: empty requester, executable or cwd")
	case p.UID < 0:
		return errors.New("proto: approval payload: negative uid")
	case p.QueuedAt <= 0 || p.Deadline <= p.QueuedAt:
		return errors.New("proto: approval payload: deadline is not after queued_at")
	case p.TokenTTL <= 0:
		return errors.New("proto: approval payload: token_ttl_seconds is not positive")
	}
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ParseApprovalPayload parses payload bytes strictly: the prefix, then one
// JSON object with exactly the known fields, and re-encoding the result must
// give the same bytes. Anything else is an error and no payload.
func ParseApprovalPayload(raw []byte) (*ApprovalPayload, error) {
	if !bytes.HasPrefix(raw, []byte(PayloadPrefix)) {
		return nil, errors.New("proto: approval payload: missing the tmb-approval-v1 prefix")
	}
	body := raw[len(PayloadPrefix):]
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var p ApprovalPayload
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("proto: approval payload: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("proto: approval payload: trailing data")
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	js, err := p.canonicalJSON()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(js, body) {
		return nil, errors.New("proto: approval payload: not in canonical form")
	}
	return &p, nil
}

// ShortCode is the human-comparable code of a payload: the first
// ShortCodeLen characters of base32 over SHA-256(shortCodePrefix ||
// payload), grouped as XXXX-XXXX. The broker logs it and tmb approve shows
// it; the signer shows it in its window and in the Touch ID sheet, so a
// person can match the three. It is a help, not a proof: the signature is
// over the payload, not the code.
func ShortCode(payload []byte) string {
	h := sha256.New()
	h.Write([]byte(shortCodePrefix))
	h.Write(payload)
	s := base32.StdEncoding.EncodeToString(h.Sum(nil))[:ShortCodeLen]
	return s[:4] + "-" + s[4:]
}

// PayloadDigest is what an approver key signs: SHA-256 over the whole
// payload, prefix included (ECDSA P-256 with SHA-256, as the Secure Enclave
// and CryptoKit sign).
func PayloadDigest(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
}

// VerifyPayloadSignature checks a DER (ASN.1) ECDSA signature over payload.
func VerifyPayloadSignature(pub *ecdsa.PublicKey, payload, sigDER []byte) bool {
	return ecdsa.VerifyASN1(pub, PayloadDigest(payload), sigDER)
}

// KeyFingerprint is the identity of a public key: lowercase hex SHA-256 over
// its DER SubjectPublicKeyInfo (ADR 0005). Approver keys use the same form.
func KeyFingerprint(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return hex.EncodeToString(sum[:])
}

// ParseApproverPublicKey decodes a base64 DER SubjectPublicKeyInfo and
// accepts only an ECDSA P-256 key, the only kind a Secure Enclave holds.
// It returns the key and its fingerprint.
func ParseApproverPublicKey(b64 string) (*ecdsa.PublicKey, string, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, "", fmt.Errorf("public_key is not base64: %v", err)
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", fmt.Errorf("public_key is not a DER SubjectPublicKeyInfo: %v", err)
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, "", errors.New("public_key is not an ECDSA P-256 key")
	}
	return ec, KeyFingerprint(der), nil
}
