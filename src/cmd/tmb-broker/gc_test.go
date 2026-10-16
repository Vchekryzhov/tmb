package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newGCStore(t *testing.T) (*ClaimStore, *Logger, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewClaimStore(dir, time.Minute)
	if err != nil {
		t.Fatalf("claim store: %v", err)
	}
	log, err := NewLogger(filepath.Join(dir, "broker.log"))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return s, log, filepath.Join(dir, "broker.log")
}

func plant(t *testing.T, s *ClaimStore, name, body string, mtime time.Time) string {
	t.Helper()
	p := filepath.Join(s.dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("plant %s: %v", name, err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	return p
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestClaimFilesCarryExpiresAt(t *testing.T) {
	s, _, _ := newGCStore(t)
	fixed := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return fixed }
	if ok, err := s.ClaimToken("h1", "t1", "uid:4242"); !ok || err != nil {
		t.Fatalf("claim token: %v %v", ok, err)
	}
	b, err := os.ReadFile(s.tokenPath("h1"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := fixed.Add(time.Minute + ClaimGrace).Unix()
	if got, _ := meta["expires_at"].(float64); int64(got) != want {
		t.Fatalf("expires_at = %v, want %d", meta["expires_at"], want)
	}
}

func TestClaimGCRemovesOnlyExpired(t *testing.T) {
	s, log, logPath := newGCStore(t)
	now := time.Now()
	past := plant(t, s, "past.claim", `{"kind":"token","expires_at":1}`, now)
	future := plant(t, s, "future.nonce", `{"kind":"nonce","expires_at":4102444800}`, now)
	oldLegacy := plant(t, s, "old.claim", `{"kind":"token"}`, now.Add(-(time.Minute + ClaimGrace + time.Hour)))
	newLegacy := plant(t, s, "new.nonce", `{"kind":"nonce"}`, now)
	broken := plant(t, s, "broken.claim", `{not json`, now.Add(-365*24*time.Hour))
	other := plant(t, s, "keep.txt", `x`, now.Add(-365*24*time.Hour))

	runClaimGC(s, log)

	for p, want := range map[string]bool{past: false, future: true, oldLegacy: false, newLegacy: true, broken: true, other: true} {
		if exists(p) != want {
			t.Errorf("%s exists = %v, want %v", filepath.Base(p), !want, want)
		}
	}
	logBytes, _ := os.ReadFile(logPath)
	if !lineHasBoth(string(logBytes), `"event":"claim_gc"`, `"removed":2`) {
		t.Errorf("claim_gc removed=2 missing:\n%s", logBytes)
	}
	if !lineHasBoth(string(logBytes), `"event":"claim_gc_skipped"`, `"file":"broken.claim"`) {
		t.Errorf("claim_gc_skipped for broken.claim missing:\n%s", logBytes)
	}
}

func TestClaimGCSkipsUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file")
	}
	s, _, _ := newGCStore(t)
	p := plant(t, s, "locked.claim", `{"expires_at":1}`, time.Now())
	if err := os.Chmod(p, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	removed, skipped, err := s.GC()
	if err != nil || removed != 0 || len(skipped) != 1 || skipped[0].File != "locked.claim" {
		t.Fatalf("GC = %d %+v %v, want the unreadable file skipped", removed, skipped, err)
	}
	if !exists(p) {
		t.Fatalf("unreadable file removed")
	}
}

// An expired file that cannot be removed is reported, not counted.
func TestClaimGCReportsRemoveFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes files from a read-only directory")
	}
	s, _, _ := newGCStore(t)
	p := plant(t, s, "stuck.claim", `{"expires_at":1}`, time.Now())
	if err := os.Chmod(s.dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(s.dir, 0o700) })
	removed, skipped, err := s.GC()
	if err != nil || removed != 0 || len(skipped) != 1 || skipped[0].File != "stuck.claim" {
		t.Fatalf("GC = %d %+v %v, want the stuck file skipped", removed, skipped, err)
	}
	if !exists(p) {
		t.Fatalf("file vanished from a read-only directory")
	}
}

// A fresh claim stays: a replay inside the TTL is still refused after GC.
func TestClaimGCKeepsLiveReplayProtection(t *testing.T) {
	s, log, _ := newGCStore(t)
	if ok, _ := s.ClaimToken("h2", "t2", "uid:4242"); !ok {
		t.Fatal("first claim refused")
	}
	runClaimGC(s, log)
	if ok, err := s.ClaimToken("h2", "t2", "uid:4242"); ok || err != nil {
		t.Fatalf("replay after GC: ok=%v err=%v, want refused", ok, err)
	}
}

func TestClaimGCLoopRepeats(t *testing.T) {
	s, log, logPath := newGCStore(t)
	early := plant(t, s, "early.claim", `{"expires_at":1}`, time.Now())
	stop := make(chan struct{})
	startClaimGC(s, log, 10*time.Millisecond, stop)
	if exists(early) {
		t.Fatal("the start-up pass did not run before startClaimGC returned")
	}
	p := plant(t, s, "late.claim", `{"expires_at":1}`, time.Now())
	deadline := time.Now().Add(2 * time.Second)
	for exists(p) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	if exists(p) {
		t.Fatal("expired file planted after start was not collected by the timer")
	}
	logBytes, _ := os.ReadFile(logPath)
	if strings.Count(string(logBytes), `"event":"claim_gc"`) < 1 {
		t.Fatalf("no claim_gc event from the loop")
	}
}

func TestClaimGCMissingDir(t *testing.T) {
	s, log, logPath := newGCStore(t)
	if err := os.RemoveAll(s.dir); err != nil {
		t.Fatalf("remove: %v", err)
	}
	runClaimGC(s, log)
	logBytes, _ := os.ReadFile(logPath)
	if !lineHasBoth(string(logBytes), `"event":"claim_gc"`, `"error":`) {
		t.Fatalf("claim_gc error missing:\n%s", logBytes)
	}
}
