package proto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"strings"
	"testing"
)

// vectorsPath is shared with the Swift signer tests: both sides parse the
// same bytes and must agree on what is canonical.
const vectorsPath = "../../../signer/Tests/vectors/approval-v1.json"

var updateVectors = flag.Bool("update-vectors", false, "rewrite "+vectorsPath+" (signature vectors from other sources are kept)")

// testSignerScalar is the private key of the fake signer used only in
// tests and vectors; it must never be enrolled anywhere.
const testSignerScalar = "4e7ab3d2a9c1f05e6b8d17c3a2e94f60b5d8c7e1f2a3b4c5d6e7f8091a2b3c4d"

func testSignerKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	raw, err := hex.DecodeString(testSignerScalar)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdh.P256().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub := ek.PublicKey().Bytes() // 0x04 || X || Y
	k := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(raw)}
	k.Curve = elliptic.P256()
	k.X = new(big.Int).SetBytes(pub[1:33])
	k.Y = new(big.Int).SetBytes(pub[33:])
	return k
}

func spkiB64(t testing.TB, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func samplePayload() *ApprovalPayload {
	hash := strings.Repeat("ab", 32)
	return &ApprovalPayload{
		HostID:      "build-01",
		HostKey:     strings.Repeat("0f", 32),
		ItemID:      TokenID(hash),
		RequestHash: hash,
		Challenge:   strings.Repeat("c3", 32),
		Requester:   "uid:1000",
		UID:         0,
		User:        "root",
		Executable:  "/usr/bin/systemctl",
		ExeDev:      2049,
		ExeIno:      131077,
		Argv:        []string{"systemctl", "restart", "nginx"},
		Cwd:         "/srv/app",
		Env:         []string{"LANG=C.UTF-8", "PATH=/usr/sbin:/usr/bin"},
		Nonce:       "0123456789abcdef0123456789abcdef",
		QueuedAt:    1793534400000,
		Deadline:    1793534700000,
		TokenTTL:    60,
	}
}

// trickyPayload carries every class of string the display must escape and
// the canonical encoding must reproduce byte for byte.
func trickyPayload() *ApprovalPayload {
	p := samplePayload()
	p.User = ""
	p.UID = 4294967294
	p.ExeIno = 1<<63 + 5
	p.Argv = []string{"", `quote " and \ backslash`, "nl\ncr\rtab\tbs\bff\f", "ctl\x01\x1f del\x7f", "<html>&amp;", "\u00e9 \u65e5\u672c \U0001f600", "bidi\u202eevil", "zero\u200bwidth", "ls\u2028\u2029", "--flag=a b"}
	p.Env = []string{}
	return p
}

// envEdgePayload: empty values, '=' inside a value, keys that sort by bytes
// (uppercase before underscore before lowercase), the largest uid.
func envEdgePayload() *ApprovalPayload {
	p := samplePayload()
	p.UID = 4294967295
	p.Env = []string{"A=", "B=x=y", "B_C=1", "b=2"}
	return p
}

type vectorFile struct {
	Comment    string          `json:"comment"`
	PublicKey  string          `json:"public_key"` // base64 SPKI of the test signer key
	Valid      []validVector   `json:"valid"`
	Invalid    []invalidVector `json:"invalid"`
	Signatures []sigVector     `json:"signatures"`
}

type validVector struct {
	Name      string          `json:"name"`
	Payload   string          `json:"payload"` // base64
	Fields    ApprovalPayload `json:"fields"`
	ShortCode string          `json:"short_code"`
	Digest    string          `json:"digest"` // hex SHA-256 of the payload
}

type invalidVector struct {
	Name    string `json:"name"`
	Payload string `json:"payload"` // base64
}

type sigVector struct {
	Name      string `json:"name"`
	Source    string `json:"source"`     // go | cryptokit
	PublicKey string `json:"public_key"` // base64 SPKI
	Payload   string `json:"payload"`
	Signature string `json:"signature"` // base64 DER
	Valid     bool   `json:"valid"`
}

func mustEncode(t testing.TB, p *ApprovalPayload) []byte {
	t.Helper()
	b, err := p.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

// invalidCases derives refused byte strings from a canonical payload: each
// differs from canonical in one way a lenient parser would let through.
func invalidCases(t testing.TB) []invalidVector {
	good := mustEncode(t, samplePayload())
	body := string(good[len(PayloadPrefix):])
	pre := PayloadPrefix
	alt := func(name, s string) invalidVector {
		return invalidVector{name, base64.StdEncoding.EncodeToString([]byte(s))}
	}
	return []invalidVector{
		alt("no prefix", body),
		alt("other version prefix", "tmb-approval-v2\x00"+body),
		alt("prefix without NUL", "tmb-approval-v1"+body),
		alt("whitespace after colon", pre+strings.Replace(body, `"host_id":"`, `"host_id": "`, 1)),
		alt("trailing newline", pre+body+"\n"),
		alt("trailing second object", pre+body+"{}"),
		alt("fields reordered", pre+strings.Replace(body, `{"host_id":"build-01","host_key":"`+strings.Repeat("0f", 32)+`",`, `{"host_key":"`+strings.Repeat("0f", 32)+`","host_id":"build-01",`, 1)),
		alt("duplicate key", pre+strings.Replace(body, `"host_id":"build-01"`, `"host_id":"evil","host_id":"build-01"`, 1)),
		alt("unknown field", pre+strings.Replace(body, `"token_ttl_seconds":60}`, `"token_ttl_seconds":60,"extra":1}`, 1)),
		alt("missing field", pre+strings.Replace(body, `"user":"root",`, ``, 1)),
		alt("unicode escape of a plain letter", pre+strings.Replace(body, `"build-01"`, `"\u0062uild-01"`, 1)),
		alt("escaped slash", pre+strings.Replace(body, `"/srv/app"`, `"\/srv\/app"`, 1)),
		alt("HTML-escaped ampersand", pre+strings.Replace(body, `"restart"`, `"re\u0026start"`, 1)),
		alt("null argv", pre+strings.Replace(body, `"argv":["systemctl","restart","nginx"]`, `"argv":null`, 1)),
		alt("float uid", pre+strings.Replace(body, `"uid":0,`, `"uid":0.0,`, 1)),
		alt("exponent ttl", pre+strings.Replace(body, `"token_ttl_seconds":60`, `"token_ttl_seconds":6e1`, 1)),
		alt("invalid UTF-8", pre+strings.Replace(body, `"nginx"`, "\"ngin\xff\"", 1)),
		alt("lone surrogate escape", pre+strings.Replace(body, `"nginx"`, `"\ud800"`, 1)),
		alt("uppercase challenge", pre+strings.Replace(body, strings.Repeat("c3", 32), strings.Repeat("C3", 32), 1)),
		alt("item_id not from request_hash", pre+strings.Replace(body, `"item_id":"abababababababab"`, `"item_id":"abababababababac"`, 1)),
		alt("deadline before queued_at", pre+strings.Replace(body, `"deadline":1793534700000`, `"deadline":1793534400000`, 1)),
		alt("zero token ttl", pre+strings.Replace(body, `"token_ttl_seconds":60`, `"token_ttl_seconds":0`, 1)),
		alt("empty host_id", pre+strings.Replace(body, `"host_id":"build-01"`, `"host_id":""`, 1)),
		alt("negative uid", pre+strings.Replace(body, `"uid":0,`, `"uid":-1,`, 1)),
		alt("not an object", pre+`[]`),
		alt("empty body", pre),
		alt("empty host_key", pre+strings.Replace(body, `"host_key":"`+strings.Repeat("0f", 32)+`"`, `"host_key":""`, 1)),
		alt("key in other case", pre+strings.Replace(body, `"host_id":`, `"HOST_ID":`, 1)),
		alt("long escape of a backspace", pre+strings.Replace(body, `"nginx"`, "\"ngi\\u0008nx\"", 1)),
		alt("uppercase hex in an escape", pre+strings.Replace(body, `"nginx"`, "\"ngi\\u001Fnx\"", 1)),
		alt("escaped DEL", pre+strings.Replace(body, `"nginx"`, "\"ngi\\u007fnx\"", 1)),
		alt("literal U+2028", pre+strings.Replace(body, `"nginx"`, "\"ngi\xe2\x80\xa8nx\"", 1)),
		alt("raw control byte in a string", pre+strings.Replace(body, `"nginx"`, "\"ngi\x01nx\"", 1)),
		alt("leading zero in a number", pre+strings.Replace(body, `"exe_dev":2049`, `"exe_dev":02049`, 1)),
		alt("negative zero uid", pre+strings.Replace(body, `"uid":0,`, `"uid":-0,`, 1)),
		alt("uid above 32 bits", pre+strings.Replace(body, `"uid":0,`, `"uid":4294967296,`, 1)),
		alt("relative cwd", pre+strings.Replace(body, `"/srv/app"`, `"srv/app"`, 1)),
		alt("empty argv", pre+strings.Replace(body, `["systemctl","restart","nginx"]`, `[]`, 1)),
		alt("env not sorted", pre+strings.Replace(body, `["LANG=C.UTF-8","PATH=/usr/sbin:/usr/bin"]`, `["PATH=/usr/sbin:/usr/bin","LANG=C.UTF-8"]`, 1)),
		alt("env entry without =", pre+strings.Replace(body, `"LANG=C.UTF-8"`, `"LANG"`, 1)),
	}
}

func buildVectors(t testing.TB) vectorFile {
	key := testSignerKey(t)
	vf := vectorFile{
		Comment:   "Shared by src/internal/proto (Go) and signer/ (Swift). Regenerate with: cd src && go test ./internal/proto -run TestApprovalVectors -update-vectors",
		PublicKey: spkiB64(t, &key.PublicKey),
	}
	for _, c := range []struct {
		name string
		p    *ApprovalPayload
	}{{"sample", samplePayload()}, {"tricky strings and large numbers", trickyPayload()}, {"env edge values", envEdgePayload()}} {
		b := mustEncode(t, c.p)
		vf.Valid = append(vf.Valid, validVector{
			Name: c.name, Payload: base64.StdEncoding.EncodeToString(b), Fields: *c.p,
			ShortCode: ShortCode(b), Digest: hexOf(PayloadDigest(b)),
		})
	}
	vf.Invalid = invalidCases(t)
	good := mustEncode(t, samplePayload())
	sig, err := ecdsa.SignASN1(rand.Reader, key, PayloadDigest(good))
	if err != nil {
		t.Fatal(err)
	}
	other := samplePayload()
	other.Challenge = strings.Repeat("d4", 32)
	vf.Signatures = []sigVector{
		{"go signature over sample", "go", vf.PublicKey, base64.StdEncoding.EncodeToString(good), base64.StdEncoding.EncodeToString(sig), true},
		{"go signature over another challenge", "go", vf.PublicKey, base64.StdEncoding.EncodeToString(mustEncode(t, other)), base64.StdEncoding.EncodeToString(sig), false},
	}
	return vf
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func readVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return vf
}

// TestApprovalVectors holds the committed vectors to this implementation:
// every valid payload parses to its fields, re-encodes to the same bytes and
// has its short code and digest; every invalid one is refused; every
// signature verifies (or not) as recorded, including those CryptoKit made.
func TestApprovalVectors(t *testing.T) {
	if *updateVectors {
		vf := buildVectors(t)
		if old, err := os.ReadFile(vectorsPath); err == nil {
			var prev vectorFile
			if json.Unmarshal(old, &prev) == nil {
				for _, s := range prev.Signatures {
					if s.Source != "go" {
						vf.Signatures = append(vf.Signatures, s)
					}
				}
			}
		}
		out, err := json.MarshalIndent(vf, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, append(out, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vf := readVectors(t)
	want := buildVectors(t)
	if vf.PublicKey != want.PublicKey {
		t.Fatalf("vector public key differs from the test signer key")
	}
	if len(vf.Valid) != len(want.Valid) || len(vf.Invalid) != len(want.Invalid) {
		t.Fatalf("vectors are stale: %d/%d valid, %d/%d invalid; regenerate with -update-vectors", len(vf.Valid), len(want.Valid), len(vf.Invalid), len(want.Invalid))
	}
	for i, v := range vf.Valid {
		raw, _ := base64.StdEncoding.DecodeString(v.Payload)
		if v.Payload != want.Valid[i].Payload {
			t.Errorf("%s: committed payload differs from today's encoding", v.Name)
		}
		p, err := ParseApprovalPayload(raw)
		if err != nil {
			t.Errorf("%s: parse: %v", v.Name, err)
			continue
		}
		again := mustEncode(t, p)
		if !bytes.Equal(again, raw) {
			t.Errorf("%s: re-encode differs", v.Name)
		}
		if got, _ := json.Marshal(p); string(got) != string(mustJSON(t, v.Fields)) {
			t.Errorf("%s: fields %s, want %s", v.Name, got, mustJSON(t, v.Fields))
		}
		if ShortCode(raw) != v.ShortCode || hexOf(PayloadDigest(raw)) != v.Digest {
			t.Errorf("%s: short code or digest differ", v.Name)
		}
	}
	for i, v := range vf.Invalid {
		if v.Payload != want.Invalid[i].Payload {
			t.Errorf("%s: committed invalid vector differs from today's", v.Name)
		}
		raw, _ := base64.StdEncoding.DecodeString(v.Payload)
		if p, err := ParseApprovalPayload(raw); err == nil || p != nil {
			t.Errorf("%s: parsed, want refused", v.Name)
		}
	}
	sources := map[string]bool{}
	for _, s := range vf.Signatures {
		pub, _, err := ParseApproverPublicKey(s.PublicKey)
		if err != nil {
			t.Fatalf("%s: public key: %v", s.Name, err)
		}
		payload, _ := base64.StdEncoding.DecodeString(s.Payload)
		sig, _ := base64.StdEncoding.DecodeString(s.Signature)
		if got := VerifyPayloadSignature(pub, payload, sig); got != s.Valid {
			t.Errorf("%s (%s): verify = %v, want %v", s.Name, s.Source, got, s.Valid)
		}
		sources[s.Source] = true
	}
	if !sources["cryptokit"] {
		t.Errorf("no CryptoKit signature vector: run signer/Scripts/cryptokit-vector.swift and add its output")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEncodeRefusesInvalidUTF8AndBadFields(t *testing.T) {
	p := samplePayload()
	p.Executable = "/opt/bad\xffname"
	if _, err := p.Encode(); err == nil {
		t.Fatal("encoded a non-UTF-8 executable path")
	}
	p = samplePayload()
	p.ItemID = "0000000000000000"
	if _, err := p.Encode(); err == nil {
		t.Fatal("encoded an item id that is not the request hash's")
	}
}

func TestShortCodeShape(t *testing.T) {
	b := mustEncode(t, samplePayload())
	c := ShortCode(b)
	if len(c) != ShortCodeLen+1 || c[4] != '-' || strings.Trim(c, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567-") != "" {
		t.Fatalf("short code %q", c)
	}
	p := samplePayload()
	p.Challenge = strings.Repeat("d4", 32)
	if ShortCode(mustEncode(t, p)) == c {
		t.Fatal("another challenge gave the same short code")
	}
}

func TestVerifyPayloadSignature(t *testing.T) {
	key := testSignerKey(t)
	b := mustEncode(t, samplePayload())
	sig, err := ecdsa.SignASN1(rand.Reader, key, PayloadDigest(b))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPayloadSignature(&key.PublicKey, b, sig) {
		t.Fatal("own signature does not verify")
	}
	if VerifyPayloadSignature(&key.PublicKey, b[:len(b)-1], sig) {
		t.Fatal("signature verifies over other bytes")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if VerifyPayloadSignature(&other.PublicKey, b, sig) {
		t.Fatal("signature verifies under another key")
	}
}

func TestParseApproverPublicKey(t *testing.T) {
	key := testSignerKey(t)
	b64 := spkiB64(t, &key.PublicKey)
	pub, fp, err := ParseApproverPublicKey(b64)
	if err != nil || !pub.Equal(&key.PublicKey) || len(fp) != 64 {
		t.Fatalf("parse = %v, %q, %v", pub, fp, err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, in := range map[string]string{
		"not base64": "!!",
		"not SPKI":   base64.StdEncoding.EncodeToString([]byte("junk")),
		"P-384":      spkiB64(t, &p384.PublicKey),
	} {
		if _, _, err := ParseApproverPublicKey(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestPayloadFieldRules: a payload the broker could not have built honestly
// is refused on both sides (Encode and Parse share the rules).
func TestPayloadFieldRules(t *testing.T) {
	for name, mut := range map[string]func(p *ApprovalPayload){
		"empty host_key":        func(p *ApprovalPayload) { p.HostKey = "" },
		"uppercase host_key":    func(p *ApprovalPayload) { p.HostKey = strings.Repeat("0F", 32) },
		"short host_key":        func(p *ApprovalPayload) { p.HostKey = strings.Repeat("0f", 31) },
		"uid above 32 bits":     func(p *ApprovalPayload) { p.UID = 1 << 32 },
		"relative executable":   func(p *ApprovalPayload) { p.Executable = "bin/systemctl" },
		"relative cwd":          func(p *ApprovalPayload) { p.Cwd = "srv/app" },
		"empty argv":            func(p *ApprovalPayload) { p.Argv = nil },
		"empty nonce":           func(p *ApprovalPayload) { p.Nonce = "" },
		"env not sorted":        func(p *ApprovalPayload) { p.Env = []string{"PATH=/bin", "LANG=C"} },
		"env entry without =":   func(p *ApprovalPayload) { p.Env = []string{"LANG"} },
		"env entry with no key": func(p *ApprovalPayload) { p.Env = []string{"=x"} },
		"env duplicate key":     func(p *ApprovalPayload) { p.Env = []string{"A=1", "A=2"} },
		"invalid UTF-8 in argv": func(p *ApprovalPayload) { p.Argv = []string{"ls", "a\xffb"} },
		"invalid UTF-8 host_id": func(p *ApprovalPayload) { p.HostID = "h\xc3" },
		"negative queued_at":    func(p *ApprovalPayload) { p.QueuedAt = -1 },
		"negative token ttl":    func(p *ApprovalPayload) { p.TokenTTL = -5 },
		"empty request_hash":    func(p *ApprovalPayload) { p.RequestHash = ""; p.ItemID = "" },
		"short challenge":       func(p *ApprovalPayload) { p.Challenge = "c3" },
		"empty requester":       func(p *ApprovalPayload) { p.Requester = "" },
	} {
		p := samplePayload()
		mut(p)
		if b, err := p.Encode(); err == nil {
			t.Errorf("%s: encoded %q", name, b)
		}
	}
	// an empty value and a value containing '=' are fine
	p := samplePayload()
	p.Env = []string{"A=", "B=x=y"}
	if _, err := p.Encode(); err != nil {
		t.Fatalf("env with = in value: %v", err)
	}
}

// TestCanonicalEscaping pins the escaping rules with hand-written bytes, so
// the encoding does not depend on what encoding/json of a Go release does:
// the Swift signer implements these rules from their description.
func TestCanonicalEscaping(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain", `"plain"`},
		{`q"b\`, `"q\"b\\"`},
		{"\b\f\n\r\t", `"\b\f\n\r\t"`},
		{"\x00\x01\x1f", `"\u0000\u0001\u001f"`},
		{"\x7f", "\"\x7f\""},
		{"<&>/'", `"<&>/'"`},
		{"\u2028\u2029", "\"\\u2028\\u2029\""},
		{"\u00e9\u202e\u200b\U0001f600\ufffd", "\"\u00e9\u202e\u200b\U0001f600\ufffd\""},
	} {
		p := samplePayload()
		p.Argv = []string{c.in}
		b := mustEncode(t, p)
		if !bytes.Contains(b, []byte(`"argv":[`+c.want+`]`)) {
			t.Errorf("%q: encoded as %q, want %s", c.in, b, c.want)
		}
		if _, err := ParseApprovalPayload(b); err != nil {
			t.Errorf("%q: canonical bytes refused: %v", c.in, err)
		}
	}
	// the whole canonical sample, written by hand
	want := PayloadPrefix + `{"host_id":"build-01","host_key":"` + strings.Repeat("0f", 32) + `","item_id":"abababababababab","request_hash":"` + strings.Repeat("ab", 32) + `","challenge":"` + strings.Repeat("c3", 32) + `","requester":"uid:1000","uid":0,"user":"root","executable":"/usr/bin/systemctl","exe_dev":2049,"exe_ino":131077,"argv":["systemctl","restart","nginx"],"cwd":"/srv/app","env":["LANG=C.UTF-8","PATH=/usr/sbin:/usr/bin"],"nonce":"0123456789abcdef0123456789abcdef","queued_at":1793534400000,"deadline":1793534700000,"token_ttl_seconds":60}`
	if got := string(mustEncode(t, samplePayload())); got != want {
		t.Fatalf("sample encoding:\n%s\nwant\n%s", got, want)
	}
}

func TestVerifyPayloadSignatureNilKey(t *testing.T) {
	if VerifyPayloadSignature(nil, []byte("x"), []byte("y")) {
		t.Fatal("verified with no key")
	}
}
