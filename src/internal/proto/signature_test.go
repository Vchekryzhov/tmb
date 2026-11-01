package proto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// A decide's signature field has one spelling: canonical standard base64,
// non-empty, at most MaxSignatureB64 characters.
func TestDecodeSignature(t *testing.T) {
	der := bytes.Repeat([]byte{0x30, 0x45, 0x02}, 24) // 72 bytes, the DER maximum
	good := base64.StdEncoding.EncodeToString(der)
	if got, err := DecodeSignature(good); err != nil || !bytes.Equal(got, der) {
		t.Fatalf("canonical: %x, %v", got, err)
	}
	for name, s := range map[string]string{
		"empty":          "",
		"CRLF":           good[:8] + "\r\n" + good[8:],
		"newline":        good + "\n",
		"spare bits":     "MEX=", // canonical is MEU=
		"unpadded":       "MEU",
		"url alphabet":   "__8=",
		"not base64":     "not base64!",
		"over the limit": base64.StdEncoding.EncodeToString(make([]byte, 99)),
	} {
		if _, err := DecodeSignature(s); err == nil {
			t.Errorf("%s: %q accepted", name, s)
		}
	}
}
