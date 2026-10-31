package main

// The fake signer (spec #99, test seam 2): a software P-256 key that signs
// the payload bytes a queue item carries, as the trusted signer does after
// Touch ID. Tests only; the key never leaves the test process.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"tmb-poc/internal/proto"
)

// testHostKey stands in for the broker identity key fingerprint in brokers
// built by tests (run loads the real one from state_dir).
var testHostKey = strings.Repeat("c0", 32)

type fakeSigner struct {
	name string
	key  *ecdsa.PrivateKey
	fp   string // KeyFingerprint of the SPKI: what decide names in approver_key
	spki string // base64 DER SPKI: what approver_keys lists
}

func newFakeSigner(t *testing.T, name string) *fakeSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSigner{name: name, key: key, fp: proto.KeyFingerprint(der), spki: base64.StdEncoding.EncodeToString(der)}
}

// entry is the signer's approver_keys record.
func (s *fakeSigner) entry() ApproverKey {
	return ApproverKey{Name: s.name, Class: KeyClassMacSE, PublicKey: s.spki}
}

// signBytes signs raw payload bytes and returns the base64 DER signature.
func (s *fakeSigner) signBytes(t *testing.T, payload []byte) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// sign signs the payload of a queue item as listed.
func (s *fakeSigner) sign(t *testing.T, item proto.QueueItem) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(item.Payload)
	if err != nil || len(raw) == 0 {
		t.Fatalf("item %s carries no payload (%v)", item.ID, err)
	}
	return s.signBytes(t, raw)
}

// decide is the signed decide for item.
func (s *fakeSigner) decide(t *testing.T, item proto.QueueItem, decision string) *proto.Request {
	t.Helper()
	return &proto.Request{Type: "decide", ItemID: item.ID, ItemHash: item.Hash, Decision: decision,
		Signature: s.sign(t, item), ApproverKey: s.fp}
}

// newSignedBroker is a queue broker whose approver_keys list the signers.
func newSignedBroker(t *testing.T, requireSigned bool, signers ...*fakeSigner) *Broker {
	t.Helper()
	b := newQueueBroker(t)
	cfg := b.conf()
	cfg.RequireSignedDecision = requireSigned
	cfg.HostID = "test-host"
	for _, s := range signers {
		cfg.ApproverKeys = append(cfg.ApproverKeys, s.entry())
	}
	b.pol.Store(newPolicy(cfg, b.tokenTTL()))
	return b
}
