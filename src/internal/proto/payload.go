package proto

// The approval payload (ADR 0006): the exact bytes a trusted signer shows
// and signs, built by the broker once per queue item. The broker is the only
// source of these bytes; a signer parses them, shows what it parsed and signs
// the received array, never its own serialization.
//
// Format: the domain prefix "tmb-approval-v1\x00" followed by one JSON object
// in canonical form, written by canonicalJSON (not encoding/json, whose
// escaping has changed between Go releases):
//
//   - the fields of ApprovalPayload in declaration order, every field always
//     present, no whitespace anywhere;
//   - integers in plain decimal (a minus sign only for a negative number, no
//     leading zeros, no fraction or exponent);
//   - an array of strings as [..] with "," between elements, [] when empty;
//   - a string is '"', its UTF-8 bytes, '"', where only these are escaped:
//     '"' and '\' with a backslash, U+0008 U+000C U+000A U+000D U+0009 as
//     the short escapes b f n r t, every other code point below U+0020 and
//     U+2028 and U+2029 in the \uXXXX form with lowercase hex. Everything
//     else, DEL, '/', '<', '>', '&' and all non-ASCII included, is written
//     as its literal UTF-8 bytes.
//
// A parser accepts the bytes only when re-encoding what it parsed gives the
// same bytes, so duplicate keys, unknown or missing fields, another key case
// or order, whitespace, other escapes, other number forms, null and invalid
// UTF-8 are all refused. The Swift signer implements the same rules;
// signer/Tests/vectors holds the shared vectors both sides test against.

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
	"math"
	"strconv"
	"strings"
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
// field order is the canonical order. ExeDev and ExeIno are not in the В12
// list: they bind the signature to the executable pin the broker keeps
// anyway, and a signer shows them as service fields.
type ApprovalPayload struct {
	HostID      string   `json:"host_id"`      // host_id from the broker config
	HostKey     string   `json:"host_key"`     // KeyFingerprint of the broker identity key
	ItemID      string   `json:"item_id"`      // queue item id (TokenID of the request hash)
	RequestHash string   `json:"request_hash"` // full Request.Hash()
	Challenge   string   `json:"challenge"`    // 32 random bytes per item, lowercase hex
	Requester   string   `json:"requester"`    // requester identity (uid:N or keyfp:HEX)
	UID         int      `json:"uid"`          // target uid, 0..2^32-1
	User        string   `json:"user"`         // target user name; "" when the uid has none
	Executable  string   `json:"executable"`   // realpath
	ExeDev      uint64   `json:"exe_dev"`      // pinned device and inode of the executable
	ExeIno      uint64   `json:"exe_ino"`
	Argv        []string `json:"argv"`              // at least one element
	Cwd         string   `json:"cwd"`               // realpath
	Env         []string `json:"env"`               // final process environment, KEY=VALUE sorted, distinct keys
	Nonce       string   `json:"nonce"`             // the request nonce
	QueuedAt    int64    `json:"queued_at"`         // unix milliseconds, broker clock
	Deadline    int64    `json:"deadline"`          // unix milliseconds: no decision is accepted after it
	TokenTTL    int      `json:"token_ttl_seconds"` // the token issued on approval lives at most this long
}

// canonicalJSON encodes p in canonical form (without the prefix). Nil
// slices encode as empty arrays, so an encoding never contains null.
func (p *ApprovalPayload) canonicalJSON() []byte {
	var w canonWriter
	w.buf.WriteByte('{')
	w.str("host_id", p.HostID)
	w.str("host_key", p.HostKey)
	w.str("item_id", p.ItemID)
	w.str("request_hash", p.RequestHash)
	w.str("challenge", p.Challenge)
	w.str("requester", p.Requester)
	w.num("uid", strconv.Itoa(p.UID))
	w.str("user", p.User)
	w.str("executable", p.Executable)
	w.num("exe_dev", strconv.FormatUint(p.ExeDev, 10))
	w.num("exe_ino", strconv.FormatUint(p.ExeIno, 10))
	w.list("argv", p.Argv)
	w.str("cwd", p.Cwd)
	w.list("env", p.Env)
	w.str("nonce", p.Nonce)
	w.num("queued_at", strconv.FormatInt(p.QueuedAt, 10))
	w.num("deadline", strconv.FormatInt(p.Deadline, 10))
	w.num("token_ttl_seconds", strconv.Itoa(p.TokenTTL))
	w.buf.WriteByte('}')
	return w.buf.Bytes()
}

// canonWriter writes the canonical JSON object one field at a time.
type canonWriter struct {
	buf    bytes.Buffer
	fields int
}

func (w *canonWriter) key(k string) {
	if w.fields > 0 {
		w.buf.WriteByte(',')
	}
	w.fields++
	writeCanonicalString(&w.buf, k)
	w.buf.WriteByte(':')
}

func (w *canonWriter) str(k, v string) { w.key(k); writeCanonicalString(&w.buf, v) }
func (w *canonWriter) num(k, v string) { w.key(k); w.buf.WriteString(v) }

func (w *canonWriter) list(k string, vs []string) {
	w.key(k)
	w.buf.WriteByte('[')
	for i, v := range vs {
		if i > 0 {
			w.buf.WriteByte(',')
		}
		writeCanonicalString(&w.buf, v)
	}
	w.buf.WriteByte(']')
}

// writeCanonicalString writes s as a JSON string under the escaping rules
// of the package comment. s must be valid UTF-8 (check refuses the rest).
func writeCanonicalString(buf *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case '\b':
			buf.WriteString("\\b")
		case '\f':
			buf.WriteString("\\f")
		case '\n':
			buf.WriteString("\\n")
		case '\r':
			buf.WriteString("\\r")
		case '\t':
			buf.WriteString("\\t")
		default:
			if r < 0x20 || r == 0x2028 || r == 0x2029 {
				buf.WriteString("\\u")
				for shift := 12; shift >= 0; shift -= 4 {
					buf.WriteByte(hexDigits[(r>>shift)&15])
				}
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// Encode returns the payload bytes: prefix and canonical JSON. It refuses a
// payload that does not pass the field checks of ParseApprovalPayload, among
// them a string that is not valid UTF-8 (the signer would be shown another
// path than the one that runs): the broker then denies before queueing.
func (p *ApprovalPayload) Encode() ([]byte, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	return append([]byte(PayloadPrefix), p.canonicalJSON()...), nil
}

func (p *ApprovalPayload) strings() []string {
	out := []string{p.HostID, p.HostKey, p.ItemID, p.RequestHash, p.Challenge, p.Requester, p.User, p.Executable, p.Cwd, p.Nonce}
	out = append(out, p.Argv...)
	return append(out, p.Env...)
}

// check holds the field rules every payload must pass, built or parsed:
// what an honest broker builds, and nothing a signer could show two ways.
func (p *ApprovalPayload) check() error {
	for _, s := range p.strings() {
		if !utf8.ValidString(s) {
			return fmt.Errorf("proto: approval payload: %q is not valid UTF-8", s)
		}
	}
	switch {
	case p.HostID == "":
		return errors.New("proto: approval payload: empty host_id")
	case !isHex(p.HostKey, 64):
		return errors.New("proto: approval payload: host_key is not a SHA-256 hex fingerprint")
	case !isHex(p.RequestHash, 64):
		return errors.New("proto: approval payload: request_hash is not a SHA-256 hex digest")
	case p.ItemID != TokenID(p.RequestHash):
		return errors.New("proto: approval payload: item_id does not match request_hash")
	case !isHex(p.Challenge, 64):
		return errors.New("proto: approval payload: challenge is not 32 bytes of hex")
	case p.Requester == "" || p.Nonce == "":
		return errors.New("proto: approval payload: empty requester or nonce")
	case !strings.HasPrefix(p.Executable, "/") || !strings.HasPrefix(p.Cwd, "/"):
		return errors.New("proto: approval payload: executable or cwd is not an absolute path")
	case p.UID < 0 || uint64(p.UID) > math.MaxUint32:
		return errors.New("proto: approval payload: uid out of range")
	case len(p.Argv) == 0:
		return errors.New("proto: approval payload: empty argv")
	case p.QueuedAt <= 0 || p.Deadline <= p.QueuedAt:
		return errors.New("proto: approval payload: deadline is not after queued_at")
	case p.TokenTTL <= 0:
		return errors.New("proto: approval payload: token_ttl_seconds is not positive")
	}
	return checkEnv(p.Env)
}

// checkEnv: the final environment is KEY=VALUE entries with non-empty,
// distinct keys, sorted by bytes as the broker builds it, so one
// environment has exactly one payload.
func checkEnv(env []string) error {
	prevKey := ""
	for i, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			return fmt.Errorf("proto: approval payload: env entry %d is not KEY=VALUE", i)
		}
		if i > 0 && (e <= env[i-1] || k == prevKey) {
			return errors.New("proto: approval payload: env is not sorted with distinct keys")
		}
		prevKey = k
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
	if !bytes.Equal(p.canonicalJSON(), body) {
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
// A nil key verifies nothing.
func VerifyPayloadSignature(pub *ecdsa.PublicKey, payload, sigDER []byte) bool {
	if pub == nil {
		return false
	}
	return ecdsa.VerifyASN1(pub, PayloadDigest(payload), sigDER)
}

// KeyFingerprint is the identity of a public key: lowercase hex SHA-256 over
// its DER SubjectPublicKeyInfo (ADR 0005). Approver keys and the broker
// identity key (host_key) use the same form.
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
