// Package proto defines the wire protocol between the tmb client and the
// tmb-broker: length-prefixed JSON frames, the request object, and the
// canonical request hash that approvals/tokens bind to.
//
// PROTOTYPE CODE - throwaway PoC, not production.
package proto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrame is the hard cap on one wire frame (1 MiB).
const MaxFrame = 1 << 20

// Request is the structured execution request sent by the client.
// The broker NEVER executes anything except the fields of this object.
type Request struct {
	Type       string            `json:"type"` // requester: "exec" | "approve" | "claim"; approver: "list" | "decide"
	Executable string            `json:"executable"`
	Argv       []string          `json:"argv"`
	Cwd        string            `json:"cwd"`
	UID        int               `json:"uid"`
	Env        map[string]string `json:"env,omitempty"`
	Nonce      string            `json:"nonce"`
	ClaimToken string            `json:"claim_token,omitempty"`

	// approver "decide": the queue item, the request hash the approver was
	// shown, and the decision ("approve" or "deny")
	ItemID   string `json:"item_id,omitempty"`
	ItemHash string `json:"item_hash,omitempty"`
	Decision string `json:"decision,omitempty"`
}

// QueueItem is one request waiting in the approval queue, as the approver
// sees it: everything that will run, resolved by the broker.
type QueueItem struct {
	ID         string   `json:"id"`   // short id of the request hash (TokenID)
	Hash       string   `json:"hash"` // full request hash; decide must echo it
	Requester  string   `json:"requester"`
	Executable string   `json:"executable"` // realpath
	Argv       []string `json:"argv"`
	Cwd        string   `json:"cwd"` // realpath
	UID        int      `json:"uid"`
	Env        []string `json:"env"` // final process environment
	Nonce      string   `json:"nonce"`
	QueuedAt   string   `json:"queued_at"`
}

// canonicalRequest is the exact tuple an approval binds to. Type and
// ClaimToken are transport/protocol fields and are deliberately excluded.
type canonicalRequest struct {
	Executable string            `json:"executable"`
	Argv       []string          `json:"argv"`
	Cwd        string            `json:"cwd"`
	UID        int               `json:"uid"`
	Env        map[string]string `json:"env"`
	Nonce      string            `json:"nonce"`
}

// DecodeRequest parses one request frame body strictly: invalid JSON, a
// wrongly typed field, an unknown field or trailing data is an error, and a
// JSON null decodes to a zero Request. The protocol carries no version, so
// a field this side does not know (from a newer peer) is refused instead of
// dropped: dropping it would run the request without what it asked for. The
// request type, and so a zero Request, is checked by the broker.
func DecodeRequest(raw []byte) (*Request, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("proto: trailing data after the request")
	}
	return &req, nil
}

// Canonical returns the deterministic JSON encoding of the request tuple.
// Go marshals struct fields in declaration order and map keys sorted, so
// this is stable across processes.
func (r *Request) Canonical() []byte {
	env := r.Env
	if env == nil {
		env = map[string]string{}
	}
	b, err := json.Marshal(canonicalRequest{
		Executable: r.Executable,
		Argv:       r.Argv,
		Cwd:        r.Cwd,
		UID:        r.UID,
		Env:        env,
		Nonce:      r.Nonce,
	})
	if err != nil {
		// cannot happen for string/slice/map-of-string data
		panic(fmt.Sprintf("proto: canonical marshal: %v", err))
	}
	return b
}

// Hash returns sha256 over the canonical request, hex encoded.
func (r *Request) Hash() string {
	sum := sha256.Sum256(r.Canonical())
	return hex.EncodeToString(sum[:])
}

// TokenID derives the short, human-showable token id for a request hash.
// The full hash is used for on-disk claim filenames.
func TokenID(hash string) string { return hash[:16] }

// NewNonce returns a fresh client-generated unique nonce (32 hex chars).
func NewNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("proto: rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Frame is a broker->client response frame.
type Frame struct {
	Type   string `json:"type"` // approved|denied|stdout|stderr|exit|error; approver: queue|decided
	Token  string `json:"token,omitempty"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	Data   string `json:"data,omitempty"` // base64 payload for stdout/stderr
	Code   *int   `json:"code,omitempty"`

	Items []QueueItem `json:"items,omitempty"` // queue: the waiting requests
}

// Stdout/Stderr build chunk frames.
func Chunk(kind string, p []byte) *Frame {
	return &Frame{Type: kind, Data: base64.StdEncoding.EncodeToString(p)}
}

// ErrFrameTooLarge is returned when a frame exceeds MaxFrame.
var ErrFrameTooLarge = errors.New("frame too large")

// WriteFrame writes one length-prefixed (4-byte big-endian) JSON frame.
func WriteFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if err := writeAll(w, hdr[:]); err != nil {
		return err
	}
	return writeAll(w, b)
}

// writeAll treats a short write as a failure even from a writer that breaks
// the io.Writer contract by not returning an error: a partly written frame
// is never reported as delivered.
func writeAll(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

// ReadRawFrame reads one frame and returns the raw JSON bytes.
func ReadRawFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	// grow with the bytes that actually arrive: a peer that announces a
	// large frame and then sends nothing holds no more than it sent
	var buf bytes.Buffer
	got, err := io.CopyN(&buf, r, int64(n))
	if err != nil {
		if err == io.EOF && got > 0 {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadFrame reads one frame into a *Frame.
func ReadFrame(r io.Reader) (*Frame, error) {
	buf, err := ReadRawFrame(r)
	if err != nil {
		return nil, err
	}
	var f Frame
	if err := json.Unmarshal(buf, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
