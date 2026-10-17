package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

// frameBytes frames payload exactly as WriteFrame would, without
// validating it as JSON.
func frameBytes(payload []byte) []byte {
	n := len(payload)
	if n < 0 || n > math.MaxUint32 {
		panic("frameBytes: payload too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(n))
	return append(hdr[:], payload...)
}

func TestFrameRoundTrip(t *testing.T) {
	code := 7
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Frame{Type: "exit", Code: &code}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := WriteFrame(&buf, Chunk("stdout", []byte("hi\n"))); err != nil {
		t.Fatalf("write chunk: %v", err)
	}
	f, err := ReadFrame(&buf)
	if err != nil || f.Type != "exit" || f.Code == nil || *f.Code != 7 {
		t.Fatalf("first frame = %+v, %v; want exit 7", f, err)
	}
	f, err = ReadFrame(&buf)
	if err != nil || f.Type != "stdout" || f.Data != "aGkK" {
		t.Fatalf("second frame = %+v, %v; want stdout aGkK", f, err)
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("read past the last frame = %v, want io.EOF", err)
	}
}

// SEC-07: every malformed frame is a controlled error, never a panic or a
// hang, and never a frame the caller would act on.
func TestReadFrameRejectsMalformedInput(t *testing.T) {
	huge := make([]byte, 4)
	binary.BigEndian.PutUint32(huge, MaxFrame+1)
	cases := []struct {
		name string
		in   []byte
		want error // nil: any non-nil error
	}{
		{"empty stream", nil, io.EOF},
		{"truncated header", []byte{0, 0}, io.ErrUnexpectedEOF},
		{"truncated body", frameBytes([]byte(`{"type":"exit"}`))[:10], io.ErrUnexpectedEOF},
		{"oversized length", huge, ErrFrameTooLarge},
		{"empty body", frameBytes(nil), nil},
		{"invalid JSON", frameBytes([]byte(`{"type":`)), nil},
		{"wrong JSON type", frameBytes([]byte(`["exit"]`)), nil},
		{"wrong field type", frameBytes([]byte(`{"type":7}`)), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ReadFrame(bytes.NewReader(c.in))
			if err == nil {
				t.Fatalf("ReadFrame accepted %q as %+v", c.in, f)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("ReadFrame error = %v, want %v", err, c.want)
			}
		})
	}
}

func TestReadRawFrameAcceptsExactlyMaxFrame(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), MaxFrame)
	got, err := ReadRawFrame(bytes.NewReader(frameBytes(payload)))
	if err != nil || len(got) != MaxFrame {
		t.Fatalf("MaxFrame-sized frame: len=%d err=%v", len(got), err)
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, Chunk("stdout", bytes.Repeat([]byte("x"), MaxFrame)))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized write error = %v, want ErrFrameTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("oversized frame wrote %d bytes; nothing may reach the wire", buf.Len())
	}
}

func TestWriteFrameRejectsUnencodableValue(t *testing.T) {
	if err := WriteFrame(io.Discard, map[string]any{"c": make(chan int)}); err == nil {
		t.Fatal("WriteFrame encoded a channel")
	}
}

// failWriter fails (or writes short) on the nth Write call.
type failWriter struct {
	calls  int
	failOn int
	short  bool
	buf    bytes.Buffer
}

var errWire = errors.New("wire down")

func (w *failWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failOn {
		if w.short {
			w.buf.Write(p[:len(p)/2])
			return len(p) / 2, nil // contract violation: short write without error
		}
		return 0, errWire
	}
	return w.buf.Write(p)
}

// SEC-08: a failed or short header/body write is an error, never a
// delivered frame.
func TestWriteFrameReportsWriteFailures(t *testing.T) {
	cases := []struct {
		name string
		w    *failWriter
		want error
	}{
		{"header write error", &failWriter{failOn: 1}, errWire},
		{"body write error", &failWriter{failOn: 2}, errWire},
		{"short header write", &failWriter{failOn: 1, short: true}, io.ErrShortWrite},
		{"short body write", &failWriter{failOn: 2, short: true}, io.ErrShortWrite},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := WriteFrame(c.w, &Frame{Type: "denied", Reason: "x"})
			if !errors.Is(err, c.want) {
				t.Fatalf("WriteFrame error = %v, want %v", err, c.want)
			}
		})
	}
}

// errReader fails every read.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errWire }

func TestReadFrameReportsReadFailure(t *testing.T) {
	if _, err := ReadFrame(errReader{}); !errors.Is(err, errWire) {
		t.Fatalf("ReadFrame error = %v, want the reader's error", err)
	}
	body := io.MultiReader(bytes.NewReader([]byte{0, 0, 0, 5}), errReader{})
	if _, err := ReadFrame(body); !errors.Is(err, errWire) {
		t.Fatalf("ReadFrame body error = %v, want the reader's error", err)
	}
}

func TestDecodeRequest(t *testing.T) {
	req, err := DecodeRequest([]byte(`{"type":"claim","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"nonce":"n1","claim_token":"abc"}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.Type != "claim" || req.Executable != "/usr/bin/id" || len(req.Argv) != 2 || req.ClaimToken != "abc" || req.Nonce != "n1" {
		t.Fatalf("decoded %+v", req)
	}
	for _, bad := range []string{``, `{`, `[]`, `"exec"`, `{"uid":"0"}`, `{"argv":"x"}`, `{"env":{"A":1}}`} {
		if _, err := DecodeRequest([]byte(bad)); err == nil {
			t.Errorf("DecodeRequest accepted %q", bad)
		}
	}
	// null decodes to a zero Request; the broker denies its empty type
	if req, err := DecodeRequest([]byte(`null`)); err != nil || req.Type != "" {
		t.Errorf("DecodeRequest(null) = %+v, %v; want a zero Request", req, err)
	}
}

func TestDecodeRequestRejectsTrailingData(t *testing.T) {
	if _, err := DecodeRequest([]byte(`{"type":"exec"} {"type":"claim"}`)); err == nil {
		t.Fatal("DecodeRequest accepted two JSON values in one frame")
	}
}

// The canonical hash is the approval binding; this vector pins its exact
// encoding so a change in field order or naming cannot slip through.
func TestCanonicalAndHashVector(t *testing.T) {
	r := &Request{Type: "exec", Executable: "/usr/bin/id", Argv: []string{"/usr/bin/id", "-u"},
		Cwd: "/tmp", UID: 0, Nonce: "n1", ClaimToken: "ignored"}
	want := `{"executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"env":{},"nonce":"n1"}`
	if got := string(r.Canonical()); got != want {
		t.Fatalf("canonical = %s\nwant        %s", got, want)
	}
	sum := sha256.Sum256([]byte(want))
	if got := r.Hash(); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash = %q, want sha256 of the canonical form", got)
	}
	if TokenID(r.Hash()) != r.Hash()[:16] {
		t.Fatal("token id is not the 16-char hash prefix")
	}
}

// Every field of the approved tuple changes the hash; transport fields do not.
func TestHashCoversEveryApprovedField(t *testing.T) {
	base := func() *Request {
		return &Request{Executable: "/usr/bin/id", Argv: []string{"/usr/bin/id"}, Cwd: "/tmp",
			UID: 0, Env: map[string]string{"LANG": "C"}, Nonce: "n1"}
	}
	h := base().Hash()
	mutations := map[string]func(*Request){
		"executable": func(r *Request) { r.Executable = "/usr/bin/whoami" },
		"argv":       func(r *Request) { r.Argv = append(r.Argv, "-u") },
		"cwd":        func(r *Request) { r.Cwd = "/" },
		"uid":        func(r *Request) { r.UID = 1 },
		"env value":  func(r *Request) { r.Env["LANG"] = "D" },
		"env key":    func(r *Request) { r.Env["TZ"] = "UTC" },
		"nonce":      func(r *Request) { r.Nonce = "n2" },
	}
	for name, mutate := range mutations {
		r := base()
		mutate(r)
		if r.Hash() == h {
			t.Errorf("changing %s does not change the request hash", name)
		}
	}
	r := base()
	r.Type, r.ClaimToken = "claim", "tok"
	if r.Hash() != h {
		t.Error("type and claim_token must not change the request hash")
	}
}

func TestNewNonceIsFreshHex(t *testing.T) {
	a, b := NewNonce(), NewNonce()
	if len(a) != 32 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("nonce %q is not 32 lowercase hex chars", a)
	}
	if a == b {
		t.Fatal("two nonces are equal")
	}
}
