package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// auditDoc is the journal schema document, relative to this package.
const auditDoc = "../../../docs/audit-schema.md"

var (
	schemaViolationsMu sync.Mutex
	schemaViolations   []string
)

// TestMain checks every event any test writes against the register: an
// event or a field the register does not know, or a value of another type,
// fails the run even if the test that wrote it passed.
func TestMain(m *testing.M) {
	eventHook = checkEventAgainstRegister
	code := m.Run()
	if len(schemaViolations) > 0 {
		fmt.Fprintln(os.Stderr, "journal events outside the register (audit.go):")
		for _, v := range schemaViolations {
			fmt.Fprintln(os.Stderr, "  "+v)
		}
		code = 1
	}
	os.Exit(code)
}

func checkEventAgainstRegister(event string, fields map[string]any) {
	var bad []string
	own, known := auditEvents[event]
	if !known {
		bad = append(bad, fmt.Sprintf("event %q is not registered", event))
	}
	for k, v := range fields {
		typ, ok := auditCommonFields[k]
		if !ok {
			typ, ok = own[k]
		}
		if !ok {
			if known {
				bad = append(bad, fmt.Sprintf("event %q: field %q is not registered", event, k))
			}
			continue
		}
		if !valueHasType(v, typ) {
			bad = append(bad, fmt.Sprintf("event %q: field %q is %T, register says %s", event, k, v, typ))
		}
	}
	if len(bad) > 0 {
		schemaViolationsMu.Lock()
		schemaViolations = append(schemaViolations, bad...)
		schemaViolationsMu.Unlock()
	}
}

func valueHasType(v any, typ string) bool {
	if typ == tAnyValue {
		return true
	}
	t := reflect.TypeOf(v)
	if t == nil {
		return false
	}
	isInt := func(k reflect.Kind) bool {
		switch k {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return true
		}
		return false
	}
	switch typ {
	case tString:
		return t.Kind() == reflect.String
	case tInt:
		return isInt(t.Kind())
	case tBool:
		return t.Kind() == reflect.Bool
	case tStrings:
		return t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.String
	case tInts:
		return t.Kind() == reflect.Slice && isInt(t.Elem().Kind())
	case tStrMap:
		return t.Kind() == reflect.Map && t.Key().Kind() == reflect.String && t.Elem().Kind() == reflect.String
	}
	return false
}

func TestValueHasType(t *testing.T) {
	for _, c := range []struct {
		v    any
		typ  string
		want bool
	}{
		{"x", tString, true}, {1, tString, false}, {uint32(1), tInt, true}, {int64(1), tInt, true},
		{true, tBool, true}, {[]string(nil), tStrings, true}, {[]uint32{1}, tInts, true},
		{[]string{"a"}, tInts, false}, {map[string]string{}, tStrMap, true}, {nil, tString, false},
		{nil, tAnyValue, true}, {1.5, "float", false},
	} {
		if got := valueHasType(c.v, c.typ); got != c.want {
			t.Errorf("valueHasType(%#v, %s) = %v, want %v", c.v, c.typ, got, c.want)
		}
	}
}

// schema is event -> field -> type; the "" event holds the common fields.
type schema map[string]map[string]string

func registerSchema() schema {
	s := schema{"": auditCommonFields}
	for ev, f := range auditEvents {
		s[ev] = f
	}
	return s
}

// schemaDiff lists every difference between two schemas: an event or a
// field only one side has, and a field typed differently. Types are
// compared only when both sides carry them (the code side has none).
func schemaDiff(aName string, a schema, bName string, b schema) []string {
	var out []string
	for ev, af := range a {
		bf, ok := b[ev]
		if !ok {
			out = append(out, fmt.Sprintf("event %q: in %s, not in %s", ev, aName, bName))
			continue
		}
		for f, at := range af {
			bt, ok := bf[f]
			switch {
			case !ok:
				out = append(out, fmt.Sprintf("event %q field %q: in %s, not in %s", ev, f, aName, bName))
			case at != "" && bt != "" && at != bt:
				out = append(out, fmt.Sprintf("event %q field %q: %s says %s, %s says %s", ev, f, aName, at, bName, bt))
			}
		}
		for f := range bf {
			if _, ok := af[f]; !ok {
				out = append(out, fmt.Sprintf("event %q field %q: in %s, not in %s", ev, f, bName, aName))
			}
		}
	}
	for ev := range b {
		if _, ok := a[ev]; !ok {
			out = append(out, fmt.Sprintf("event %q: in %s, not in %s", ev, bName, aName))
		}
	}
	sort.Strings(out)
	return out
}

// The comparison itself catches each kind of drift: an undocumented event
// or field, a documented field nobody writes, and a type mismatch.
func TestSchemaDiffCatchesDrift(t *testing.T) {
	base := func() schema {
		return schema{"": {"schema": tInt}, "deny": {"reason": tString, "detail": tString}}
	}
	if d := schemaDiff("doc", base(), "code", base()); len(d) != 0 {
		t.Fatalf("equal schemas differ: %v", d)
	}
	for name, mutate := range map[string]func(s schema){
		"undocumented event": func(s schema) { s["exec_new"] = map[string]string{} },
		"undocumented field": func(s schema) { s["deny"]["extra"] = tString },
		"unwritten field":    func(s schema) { delete(s["deny"], "detail") },
		"type changed":       func(s schema) { s["deny"]["reason"] = tInt },
	} {
		code := base()
		mutate(code)
		if d := schemaDiff("doc", base(), "code", code); len(d) != 1 {
			t.Errorf("%s: diff %v, want exactly one difference", name, d)
		}
	}
}

var (
	docEventHeading = regexp.MustCompile("^### `([a-z_]+)`")
	docFieldRow     = regexp.MustCompile("^\\| `([a-z_]+)` \\| ([^|]+?) \\|")
)

// parseAuditDoc reads the field tables of docs/audit-schema.md: the table
// under "## Общие поля" holds the common fields, the table under each
// "### `event`" heading that event's own fields.
func parseAuditDoc(path string) (schema, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := schema{}
	cur, in := "", false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "## Общие поля"):
			cur, in = "", true
			s[cur] = map[string]string{}
		case docEventHeading.MatchString(line):
			cur, in = docEventHeading.FindStringSubmatch(line)[1], true
			if _, dup := s[cur]; dup {
				return nil, fmt.Errorf("event %q documented twice", cur)
			}
			s[cur] = map[string]string{}
		case strings.HasPrefix(line, "#"):
			in = false
		case in && docFieldRow.MatchString(line):
			m := docFieldRow.FindStringSubmatch(line)
			if _, dup := s[cur][m[1]]; dup {
				return nil, fmt.Errorf("event %q field %q documented twice", cur, m[1])
			}
			s[cur][m[1]] = strings.TrimSpace(m[2])
		}
	}
	return s, sc.Err()
}

// docs/audit-schema.md and the register in audit.go describe the same
// events with the same fields and types.
func TestAuditSchemaDoc(t *testing.T) {
	doc, err := parseAuditDoc(auditDoc)
	if err != nil {
		t.Fatalf("read %s: %v", auditDoc, err)
	}
	for _, d := range schemaDiff("docs/audit-schema.md", doc, "register (audit.go)", registerSchema()) {
		t.Error(d)
	}
	raw, err := os.ReadFile(auditDoc)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("Текущая версия схемы: `%d`.", auditSchemaVersion); !strings.Contains(string(raw), want) {
		t.Errorf("%s does not state %q", auditDoc, want)
	}
}

// The register in audit.go and the code agree: every event the broker
// source writes, with every field it can carry, is registered, and every
// registered field is written somewhere. The fields are read from the
// source (go/ast), so a field written on a rare path counts too.
func TestAuditSchemaCode(t *testing.T) {
	code, err := codeSchema(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range schemaDiff("code", code, "register (audit.go)", registerSchema()) {
		t.Error(d)
	}
}

// codeSchema extracts event -> fields from the package source: every
// X.Event("name", fields) and X.stderrEvent("name", fields) call, with the
// fields resolved through map literals, a local map variable (its literal
// or RequesterID.LogFields() plus the keys assigned to it before the
// call), and package functions that return such a map. The common fields
// are the keys the two writers set on their fields argument.
func codeSchema(dir string) (schema, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, err
	}
	funcs := map[string]*ast.FuncDecl{}
	var files []*ast.File
	for _, p := range pkgs {
		for _, f := range p.Files {
			files = append(files, f)
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
					funcs[fd.Name.Name] = fd
				}
			}
		}
	}
	x := &extractor{fset: fset, funcs: funcs, out: schema{"": {}}}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if fd.Recv != nil && (fd.Name.Name == "Event" || fd.Name.Name == "stderrEvent") {
				for k := range indexKeys(fd.Body.List, "fields", fd.Body.Pos(), fd.Body.End()) {
					x.out[""][k] = ""
				}
			}
			x.walk(fd)
		}
	}
	if len(x.errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(x.errs, "\n"))
	}
	return x.out, nil
}

type extractor struct {
	fset  *token.FileSet
	funcs map[string]*ast.FuncDecl
	out   schema
	errs  []string
}

func (x *extractor) walk(fd *ast.FuncDecl) {
	var stack []ast.Node
	ast.Inspect(fd, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Event" && sel.Sel.Name != "stderrEvent") {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			x.errs = append(x.errs, fmt.Sprintf("%s: event name is not a string literal", x.fset.Position(call.Pos())))
			return true
		}
		name, _ := strconv.Unquote(lit.Value)
		fields, err := x.resolve(call.Args[1], stack, call.Pos())
		if err != nil {
			x.errs = append(x.errs, fmt.Sprintf("%s: event %q: %v", x.fset.Position(call.Pos()), name, err))
			return true
		}
		if x.out[name] == nil {
			x.out[name] = map[string]string{}
		}
		for f := range fields {
			x.out[name][f] = ""
		}
		return true
	})
}

// resolve returns the keys the map expression e can carry at pos; stack is
// the path from the function declaration down to the use.
func (x *extractor) resolve(e ast.Expr, stack []ast.Node, pos token.Pos) (map[string]bool, error) {
	switch v := e.(type) {
	case *ast.CompositeLit:
		keys := map[string]bool{}
		for _, el := range v.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				return nil, fmt.Errorf("map literal element without a key")
			}
			k, ok := kv.Key.(*ast.BasicLit)
			if !ok || k.Kind != token.STRING {
				return nil, fmt.Errorf("map literal key is not a string literal")
			}
			s, _ := strconv.Unquote(k.Value)
			keys[s] = true
		}
		return keys, nil
	case *ast.CallExpr:
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "LogFields" {
			keys := map[string]bool{}
			for k := range requesterFields {
				keys[k] = true
			}
			return keys, nil
		}
		if id, ok := v.Fun.(*ast.Ident); ok && x.funcs[id.Name] != nil {
			return x.returned(x.funcs[id.Name])
		}
		return nil, fmt.Errorf("cannot resolve the fields of call %T", v.Fun)
	case *ast.Ident:
		// the innermost statement list that defines the variable before pos
		for i := len(stack) - 1; i >= 0; i-- {
			list := stmtList(stack[i])
			for _, st := range list {
				as, ok := st.(*ast.AssignStmt)
				if !ok || as.Tok != token.DEFINE || as.Pos() >= pos || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
					continue
				}
				if lhs, ok := as.Lhs[0].(*ast.Ident); !ok || lhs.Name != v.Name {
					continue
				}
				keys, err := x.resolve(as.Rhs[0], stack[:i+1], as.Pos())
				if err != nil {
					return nil, err
				}
				for k := range indexKeys(list, v.Name, as.End(), pos) {
					keys[k] = true
				}
				return keys, nil
			}
		}
		return nil, fmt.Errorf("no definition of %s before its use", v.Name)
	}
	return nil, fmt.Errorf("cannot resolve the fields of %T", e)
}

// returned resolves the map a function returns (one return statement).
func (x *extractor) returned(fd *ast.FuncDecl) (map[string]bool, error) {
	var stack []ast.Node
	var keys map[string]bool
	var err error
	ast.Inspect(fd, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if r, ok := n.(*ast.ReturnStmt); ok && len(r.Results) == 1 && keys == nil && err == nil {
			keys, err = x.resolve(r.Results[0], stack, r.Pos())
		}
		return true
	})
	if keys == nil && err == nil {
		err = fmt.Errorf("%s returns no map", fd.Name.Name)
	}
	return keys, err
}

func stmtList(n ast.Node) []ast.Stmt {
	switch v := n.(type) {
	case *ast.BlockStmt:
		return v.List
	case *ast.CaseClause:
		return v.Body
	case *ast.CommClause:
		return v.Body
	}
	return nil
}

// indexKeys collects the string keys of name["key"] = ... assignments in
// list (at any depth) between from and to.
func indexKeys(list []ast.Stmt, name string, from, to token.Pos) map[string]bool {
	keys := map[string]bool{}
	for _, st := range list {
		ast.Inspect(st, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || as.Pos() < from || as.Pos() >= to {
				return true
			}
			for _, l := range as.Lhs {
				ix, ok := l.(*ast.IndexExpr)
				if !ok {
					continue
				}
				if id, ok := ix.X.(*ast.Ident); !ok || id.Name != name {
					continue
				}
				if k, ok := ix.Index.(*ast.BasicLit); ok && k.Kind == token.STRING {
					s, _ := strconv.Unquote(k.Value)
					keys[s] = true
				}
			}
			return true
		})
	}
	return keys
}

// The extractor resolves each shape of event the broker uses, and refuses
// one it cannot read rather than skipping it.
func TestCodeSchemaShapes(t *testing.T) {
	dir := t.TempDir()
	src := `package main

func helper(id RequesterID) map[string]any {
	ev := id.LogFields()
	ev["item"] = "x"
	return ev
}

func shapes(l *Logger, id RequesterID, err error) {
	l.Event("lit", map[string]any{"a": 1})
	ev := map[string]any{"b": 1}
	if err != nil {
		ev["c"] = 2
	}
	l.Event("local", ev)
	if err != nil {
		ev := id.LogFields()
		ev["d"] = 1
		l.Event("scoped", ev)
	}
	switch {
	case err == nil:
		l.Event("helper", helper(id))
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := codeSchema(dir)
	if err != nil {
		t.Fatal(err)
	}
	req := func(extra ...string) map[string]string {
		m := map[string]string{}
		for k := range requesterFields {
			m[k] = ""
		}
		for _, k := range extra {
			m[k] = ""
		}
		return m
	}
	want := schema{
		"":       {},
		"lit":    {"a": ""},
		"local":  {"b": "", "c": ""},
		"scoped": req("d"),
		"helper": req("item"),
	}
	if d := schemaDiff("extracted", got, "want", want); len(d) != 0 {
		t.Errorf("extracted schema differs: %v", d)
	}

	bad := `package main

func f(l *Logger, name string, m map[string]any) {
	l.Event(name, m)
}
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := codeSchema(dir); err == nil {
		t.Error("an event name that is not a literal must fail the extraction")
	}
}

// frozenSchemas holds, per schema version, the field set of every event as
// formatSchemaLines renders it. A released version does not change:
// TestAuditSchemaVersion fails when an event's fields or types differ from
// the frozen set of auditSchemaVersion (raise the version and freeze the new
// set) and when an event is missing from it (a new event keeps the version:
// add its line).
var frozenSchemas = map[int]string{
	1: `
* event:string schema:integer ts:string
approval approver:string argv:array_of_string decision:string executable:string mode:string nonce:string reason:string requester_fp:string requester_pid:integer requester_uid:integer result:string
approval_timeout item:string requester_fp:string requester_pid:integer requester_uid:integer wait_seconds:integer
approver_denied reason:string requester_fp:string requester_pid:integer requester_uid:integer
audit_unavailable error:string path:string pid:integer
bad_frame error:string requester_fp:string requester_pid:integer requester_uid:integer
bad_request error:string requester_fp:string requester_pid:integer requester_uid:integer
broker_start allowed_requester_keys:array_of_string allowed_requester_uids:array_of_integer mode:string pid:integer socket:string tls_addr:string ttl_seconds:integer
broker_stop pid:integer
claim executable:string hash:string nonce:string requester_fp:string requester_pid:integer requester_uid:integer result:string token:string
claim_gc error:string removed:integer skipped:integer
claim_gc_skipped error:string file:string
decision_rejected item:string reason:string requester_fp:string requester_pid:integer requester_uid:integer
deny argv:array_of_string detail:string executable:string nonce:string reason:string requester_fp:string requester_pid:integer requester_uid:integer
exec_exit duration_ms:integer executable:string exit_status:integer requester_fp:string requester_pid:integer requester_uid:integer token:string
exec_fail error:string token:string
exec_start argv:array_of_string cwd:string cwd_verified:boolean cwd_via_fd:boolean env_count:integer exe_dev:integer exe_ino:integer exe_via_fd:boolean executable:string requester_fp:string requester_pid:integer requester_uid:integer token:string uid:integer
peercred_error error:string socket:string
queued argv:array_of_string cwd:string executable:string hash:string item:string nonce:string requester_fp:string requester_pid:integer requester_uid:integer
reload changed:array_of_string ignored:array_of_string pid:integer
reload_failed error:string pid:integer
reload_ignored_field config:any field:string running:any
request argv:array_of_string claim_token:string cwd:string env:object_of_string executable:string nonce:string requester_fp:string requester_pid:integer requester_uid:integer transport:string type:string uid:integer
request_abandoned item:string requester_fp:string requester_pid:integer requester_uid:integer wait_seconds:integer
requester_denied reason:string requester_fp:string requester_pid:integer requester_uid:integer
tls_handshake_failed error:string remote:string
tls_listen addr:string
tls_no_client_cert remote:string
`,
}

// formatSchemaLines renders a schema as one line per event, "event
// field:type ...", fields sorted; "*" stands for the common fields.
func formatSchemaLines(s schema) map[string]string {
	out := map[string]string{}
	for ev, fields := range s {
		var fs []string
		for f, typ := range fields {
			fs = append(fs, f+":"+strings.ReplaceAll(typ, " ", "_"))
		}
		sort.Strings(fs)
		name := ev
		if name == "" {
			name = "*"
		}
		out[name] = name + " " + strings.Join(fs, " ")
	}
	return out
}

// Changing the fields of an existing event raises the schema version.
func TestAuditSchemaVersion(t *testing.T) {
	cur := formatSchemaLines(registerSchema())
	frozen := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(frozenSchemas[auditSchemaVersion]), "\n") {
		if ev, _, ok := strings.Cut(line, " "); ok {
			frozen[ev] = line
		}
	}
	if len(frozen) == 0 {
		all := make([]string, 0, len(cur))
		for _, line := range cur {
			all = append(all, line)
		}
		sort.Strings(all)
		t.Fatalf("no frozen field set for schema %d; freeze this one:\n%s", auditSchemaVersion, strings.Join(all, "\n"))
	}
	for ev, line := range frozen {
		if cur[ev] != line {
			t.Errorf("event %q changed under schema %d: raise auditSchemaVersion and freeze the new set\n frozen: %s\n now:    %s", ev, auditSchemaVersion, line, cur[ev])
		}
	}
	for ev, line := range cur {
		if _, ok := frozen[ev]; !ok {
			t.Errorf("new event %q: add its line to frozenSchemas[%d] (a new event keeps the version):\n%s", ev, auditSchemaVersion, line)
		}
	}
}
