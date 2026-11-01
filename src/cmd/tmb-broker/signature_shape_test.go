package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The signature field is taken only in canonical standard base64 of at
// most maxSignatureB64 characters, before any verification: line breaks
// (which the decoder skips), non-zero padding bits or an oversized value
// are signature_invalid, so the journal never records a bloated or
// ambiguous form of a signature. The item keeps waiting.
func TestSignatureFieldShape(t *testing.T) {
	signer := newFakeSigner(t, "mac")
	b := newSignedBroker(t, true, signer)
	item, done := queueRequest(t, b, testReq(t, "signature-shape"), UIDRequester(4242, 7))
	good := signer.decide(t, item, "approve")
	der, _ := base64.StdEncoding.DecodeString(good.Signature)

	// flip the low bit of the last data character: spare bits the decoder
	// ignores when the DER length leaves some, a changed byte otherwise
	alt := []byte(good.Signature)
	trimmed := strings.TrimRight(good.Signature, "=")
	i := len(trimmed) - 1
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	alt[i] = alphabet[strings.IndexByte(alphabet, alt[i])^1]

	for name, sig := range map[string]string{
		"CRLF inside":       good.Signature[:20] + "\r\n" + good.Signature[20:],
		"trailing newline":  good.Signature + "\n",
		"spare bits set":    string(alt),
		"longer than limit": base64.StdEncoding.EncodeToString(append(der, make([]byte, 100)...)),
		"unpadded":          trimmed,
	} {
		r := *good
		r.Signature = sig
		if f := approverDo(t, b, human(), &r); f.Type != "denied" || f.Reason != "signature_invalid" {
			t.Errorf("%s: %+v, want denied signature_invalid", name, f)
		}
	}
	for _, ev := range logEvents(t, b, "decision_rejected") {
		if _, has := ev["signature"]; has {
			t.Errorf("a rejected signature reached the journal: %v", ev)
		}
	}
	if f := approverDo(t, b, human(), good); f.Type != "decided" {
		t.Fatalf("canonical signature: %+v", f)
	}
	if f := <-done; f.Type != "approved" {
		t.Fatalf("requester got %+v", f)
	}
}
