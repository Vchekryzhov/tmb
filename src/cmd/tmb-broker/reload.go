// PROTOTYPE CODE - throwaway PoC, not production.
package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"
)

// policy is the reloadable part of the broker: the config plus the TTLs
// derived from it. A reload builds a new policy and swaps the pointer, so a
// reader sees either the old policy or the new one, never a mix.
type policy struct {
	cfg  *Config
	ttl  time.Duration          // token: approval -> claim
	wait time.Duration          // queue: enqueue -> decision (approval_wait_seconds)
	keys map[string]approverKey // approver_keys by fingerprint
	// required is required_signatures, at least 1
	required int
}

func newPolicy(cfg *Config, ttl time.Duration) *policy {
	wait := time.Duration(cfg.ApprovalWaitSeconds) * time.Second
	if wait <= 0 {
		wait = 300 * time.Second
	}
	// loadConfig has validated the keys, so this cannot fail for a loaded
	// config; a Config built in code with a bad entry gets no keys, which
	// only ever refuses signed decisions
	keys, err := parseApproverKeys(cfg.ApproverKeys)
	if err != nil {
		keys = nil
	}
	required := cfg.RequiredSignatures
	if required < 1 {
		required = defaultRequiredSignatures
	}
	return &policy{cfg: cfg, ttl: ttl, wait: wait, keys: keys, required: required}
}

// signatureRule is what a signature is counted against now.
func (p *policy) signatureRule() signatureRule {
	return signatureRule{required: p.required, keys: p.keys}
}

func (b *Broker) conf() *Config               { return b.pol.Load().cfg }
func (b *Broker) tokenTTL() time.Duration     { return b.pol.Load().ttl }
func (b *Broker) approvalWait() time.Duration { return b.pol.Load().wait }

// startupOnlyFields are the config fields a reload never applies: sockets
// and their owner, the TLS address, the state, log and pid paths, and the
// approval mode. A change is reported as reload_ignored_field and takes
// effect at the next start. Every other field is reloadable.
var startupOnlyFields = map[string]bool{
	"socket_path":          true,
	"socket_gid":           true,
	"approver_socket_path": true,
	"tls_addr":             true,
	"state_dir":            true,
	"log_path":             true,
	"pid_file":             true,
	"approval_default":     true,
}

// configDiff compares two configs field by field (by JSON name, sorted) and
// splits the differences into reloadable and startup-only fields.
func configDiff(cur, next *Config) (changed, ignored []string) {
	cv, nv := reflect.ValueOf(cur).Elem(), reflect.ValueOf(next).Elem()
	t := cv.Type()
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if reflect.DeepEqual(cv.Field(i).Interface(), nv.Field(i).Interface()) {
			continue
		}
		if startupOnlyFields[name] {
			ignored = append(ignored, name)
		} else {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	sort.Strings(ignored)
	return changed, ignored
}

// keepStartupFields copies the startup-only fields of the running config
// into next, so the new policy describes what the broker actually runs.
func keepStartupFields(next, cur *Config) {
	nv, cv := reflect.ValueOf(next).Elem(), reflect.ValueOf(cur).Elem()
	t := nv.Type()
	for i := 0; i < t.NumField(); i++ {
		if startupOnlyFields[strings.Split(t.Field(i).Tag.Get("json"), ",")[0]] {
			nv.Field(i).Set(cv.Field(i))
		}
	}
}

// fieldValue returns the value of a config field by its JSON name.
func fieldValue(c *Config, name string) any {
	v := reflect.ValueOf(c).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if strings.Split(t.Field(i).Tag.Get("json"), ",")[0] == name {
			return v.Field(i).Interface()
		}
	}
	return nil
}

// tlsMaterialChanged reports whether the server certificate chain or the
// client CA pool differs between two listener configs.
func tlsMaterialChanged(cur, next *tls.Config) bool {
	if cur == nil || next == nil {
		return cur != next
	}
	if !cur.ClientCAs.Equal(next.ClientCAs) || len(cur.Certificates) != len(next.Certificates) {
		return true
	}
	for i := range cur.Certificates {
		a, b := cur.Certificates[i].Certificate, next.Certificates[i].Certificate
		if len(a) != len(b) {
			return true
		}
		for j := range a {
			if !bytes.Equal(a[j], b[j]) {
				return true
			}
		}
	}
	return false
}

// Reload re-reads the config at path (SIGHUP) and reopens the journal. An invalid config, or TLS
// files that do not load, change nothing: reload_failed with the reason, in
// the log and on stderr. Otherwise the reloadable fields and the TLS
// material are swapped in at once; changed startup-only fields are reported
// one by one as reload_ignored_field and keep their running values.
// Requests in the queue and pending approvals are not touched: they keep the
// identity, the expiry and the wait they were given.
func (b *Broker) Reload(path string) {
	next, err := loadConfig(path)
	// reopen the journal at its path (logrotate moved it away) whatever the
	// config says, and before this reload's events, so they land in the new
	// file; a failed reopen makes the journal unavailable (log.go)
	_ = b.log.Reopen()
	if err == nil {
		err = checkSignedMode(next, b.mode)
	}
	if err != nil {
		b.reloadFailed(err)
		return
	}
	cur := b.pol.Load()
	changed, ignored := configDiff(cur.cfg, next)
	type ignoredField struct {
		field           string
		running, config any
	}
	ignoredFields := make([]ignoredField, 0, len(ignored))
	for _, f := range ignored {
		ignoredFields = append(ignoredFields, ignoredField{f, fieldValue(cur.cfg, f), fieldValue(next, f)})
	}
	keepStartupFields(next, cur.cfg)

	curTLS := b.tlsCfg.Load()
	var nextTLS *tls.Config
	if next.TLSAddr != "" { // the running listener's address (kept above)
		if next.TLSCAFile == "" || next.TLSCertFile == "" || next.TLSKeyFile == "" {
			b.reloadFailed(fmt.Errorf("tls_addr %s requires tls_ca_file, tls_cert_file and tls_key_file", next.TLSAddr))
			return
		}
		if nextTLS, err = loadTLSConfig(next.TLSCAFile, next.TLSCertFile, next.TLSKeyFile); err != nil {
			b.reloadFailed(err)
			return
		}
		if tlsMaterialChanged(curTLS, nextTLS) {
			changed = append(changed, "tls_material")
		}
	}

	ttl := time.Duration(next.TokenTTLSeconds) * time.Second
	if b.ttlFlag > 0 {
		ttl = b.ttlFlag
	}
	if b.claims != nil {
		b.claims.ExtendRetention(ttl)
	}
	for _, f := range ignoredFields {
		fmt.Fprintf(os.Stderr, "tmb-broker: reload: %s changed, ignored until restart\n", f.field)
		b.log.Event("reload_ignored_field", map[string]any{"field": f.field, "running": f.running, "config": f.config})
	}
	b.storePolicy(newPolicy(next, ttl))
	if nextTLS != nil {
		b.tlsCfg.Store(nextTLS)
	}
	if changed == nil {
		changed = []string{}
	}
	if ignored == nil {
		ignored = []string{}
	}
	b.log.Event("reload", map[string]any{"pid": os.Getpid(), "changed": changed, "ignored": ignored})
}

// storePolicy swaps the policy under the queue lock, so a vote in the
// queue counts either wholly before the reload or wholly after it
// (serveDecide re-checks a decide whose policy was replaced).
func (b *Broker) storePolicy(p *policy) {
	if b.queue == nil {
		b.pol.Store(p)
		return
	}
	b.queue.mu.Lock()
	defer b.queue.mu.Unlock()
	b.pol.Store(p)
}

func (b *Broker) reloadFailed(err error) {
	fmt.Fprintf(os.Stderr, "tmb-broker: reload failed, keeping the running config: %v\n", err)
	b.log.Event("reload_failed", map[string]any{"pid": os.Getpid(), "error": err.Error()})
}
