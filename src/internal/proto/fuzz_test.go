package proto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// FuzzReadFrame: any byte stream yields either a frame whose declared
// length matches what was read, or an error. Never a panic, never more
// than MaxFrame bytes buffered.
func FuzzReadFrame(f *testing.F) {
	seeds := [][]byte{
		nil,
		{0, 0},
		{0, 0, 0, 0},
		frameBytes([]byte(`{"type":"exit","code":0}`)),
		frameBytes([]byte(`{"type":"stdout","data":"aGkK"}`)),
		frameBytes([]byte(`{"type":"denied","reason":"x","detail":"y"}`)),
		frameBytes([]byte(`{"type":`)),
		frameBytes([]byte(`["exit"]`)),
		frameBytes([]byte(`{"type":7}`)),
		frameBytes([]byte(`{"type":"exit"}`))[:9],
		{0xff, 0xff, 0xff, 0xff},
		{0x00, 0x10, 0x00, 0x01},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		raw, err := ReadRawFrame(bytes.NewReader(in))
		if err != nil {
			if raw != nil {
				t.Fatalf("error %v returned with %d bytes of frame", err, len(raw))
			}
			if len(in) >= 4 {
				n := binary.BigEndian.Uint32(in[:4])
				if n > MaxFrame && !errors.Is(err, ErrFrameTooLarge) {
					t.Fatalf("length %d over MaxFrame gave %v, want ErrFrameTooLarge", n, err)
				}
			}
			return
		}
		if n := binary.BigEndian.Uint32(in[:4]); int(n) != len(raw) || n > MaxFrame {
			t.Fatalf("declared %d bytes, read %d", n, len(raw))
		}
		if !bytes.Equal(raw, in[4:4+len(raw)]) {
			t.Fatal("frame body differs from the input")
		}
		fr, err := ReadFrame(bytes.NewReader(in))
		if err != nil {
			return
		}
		// a decoded frame must survive a write/read round trip unchanged
		var buf bytes.Buffer
		if err := WriteFrame(&buf, fr); err != nil {
			if errors.Is(err, ErrFrameTooLarge) {
				return
			}
			t.Fatalf("re-encode %+v: %v", fr, err)
		}
		back, err := ReadFrame(&buf)
		if err != nil || back.Type != fr.Type || back.Data != fr.Data || (back.Code == nil) != (fr.Code == nil) {
			t.Fatalf("round trip %+v -> %+v, %v", fr, back, err)
		}
		if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
			t.Fatalf("round trip left trailing bytes: %v", err)
		}
	})
}

// FuzzDecodeRequest: any frame body either fails to decode or yields a
// request whose canonical hash is deterministic and survives a re-encode.
func FuzzDecodeRequest(f *testing.F) {
	seeds := []string{
		``,
		`{}`,
		`[]`,
		`null`,
		`"exec"`,
		`{"type":"exec","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"env":{"LANG":"C.UTF-8"},"nonce":"nonce-1"}`,
		`{"type":"claim","executable":"/usr/bin/id","argv":["/usr/bin/id"],"nonce":"n","claim_token":"tok-1"}`,
		`{"type":"approve","uid":-1,"argv":[]}`,
		`{"type":"exec","uid":"0"}`,
		`{"type":"exec","env":{"A":1}}`,
		`{"type":"exec"} {"type":"claim"}`,
		`{"type":"\u0000","argv":["\ud800"]}`,
		`{"uid":1e40}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		req, err := DecodeRequest(raw)
		if err != nil {
			if req != nil {
				t.Fatalf("error %v returned with a request", err)
			}
			return
		}
		h := req.Hash()
		if len(h) != 64 || req.Hash() != h {
			t.Fatalf("hash %q is not a stable sha256 hex", h)
		}
		var buf bytes.Buffer
		if err := WriteFrame(&buf, req); err != nil {
			if errors.Is(err, ErrFrameTooLarge) {
				return
			}
			t.Fatalf("re-encode: %v", err)
		}
		body, err := ReadRawFrame(&buf)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		back, err := DecodeRequest(body)
		if err != nil {
			t.Fatalf("decode of re-encoded request: %v", err)
		}
		if back.Hash() != h || back.Type != req.Type || back.ClaimToken != req.ClaimToken {
			t.Fatalf("re-encoded request differs: %+v vs %+v", back, req)
		}
	})
}

// FuzzParseApprovalPayload: any byte string either is refused with no
// payload, or parses to a payload whose encoding is exactly those bytes, so
// a signer that shows the parse result shows what it signs.
func FuzzParseApprovalPayload(f *testing.F) {
	good, err := samplePayload().Encode()
	if err != nil {
		f.Fatal(err)
	}
	tricky, err := trickyPayload().Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(tricky)
	f.Add([]byte(PayloadPrefix))
	f.Add([]byte(PayloadPrefix + "{}"))
	f.Add(good[len(PayloadPrefix):])
	for _, v := range invalidCases(f) {
		raw, _ := base64.StdEncoding.DecodeString(v.Payload)
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := ParseApprovalPayload(raw)
		if err != nil {
			if p != nil {
				t.Fatalf("error %v returned with a payload", err)
			}
			return
		}
		again, err := p.Encode()
		if err != nil {
			t.Fatalf("parsed payload does not encode: %v", err)
		}
		if !bytes.Equal(again, raw) {
			t.Fatalf("parse/encode changed the bytes:\n%q\n%q", raw, again)
		}
		if ShortCode(raw) != ShortCode(again) {
			t.Fatal("short code is not stable")
		}
	})
}
