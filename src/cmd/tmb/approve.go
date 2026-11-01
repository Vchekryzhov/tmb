// PROTOTYPE CODE - throwaway PoC, not production.
package main

// tmb approve: the approver side of the approval queue (ADR 0004). It talks
// only to the approver socket on the host; the broker checks the caller's
// uid against approver_uids via SO_PEERCRED.
//
// Exit codes: 0 decision accepted (or --list printed), 1 the item was
// already decided or is not in the queue, 2 usage (and a malformed decision
// on stdin for --decide), 3 transport, 125 the broker refused
// (approver_not_allowed and other denials).
//
// Machine mode, what the trusted signer runs over SSH (ADR 0006):
// --list --json prints {"type":"queue","items":[...]} on one line, each item
// exactly as the broker sent it (payload, short_code and fields this client
// does not know included); --decide reads one decision object from stdin
// (decisionFields) and prints the broker's answer frame on one line. A
// broker denial is printed the same way, and the exit code is as above.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"tmb-poc/internal/proto"
	"tmb-poc/internal/termsafe"
)

const defaultApproveSocket = "/run/tmb/approve.sock"

type approverDenied struct{ reason, detail string }

func (e *approverDenied) Error() string {
	if e.detail != "" {
		return fmt.Sprintf("DENIED: %s (%s)", e.reason, e.detail)
	}
	return "DENIED: " + e.reason
}

func cmdApprover(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("socket", "", "approver socket (env TMB_APPROVE_SOCK, default "+defaultApproveSocket+")")
	list := fs.Bool("list", false, "print the queue and exit")
	yes := fs.String("yes", "", "approve the item with this id")
	no := fs.String("no", "", "deny the item with this id")
	asJSON := fs.Bool("json", false, "with --list: print the queue as one JSON object")
	decideIn := fs.Bool("decide", false, "send the decision JSON object read from stdin")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	modes := 0
	for _, set := range []bool{*list, *yes != "", *no != "", *decideIn} {
		if set {
			modes++
		}
	}
	if modes > 1 || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "tmb approve: use at most one of --list, --yes ID, --no ID, --decide")
		return 2
	}
	if *asJSON && !*list {
		fmt.Fprintln(stderr, "tmb approve: --json goes with --list")
		return 2
	}
	// a malformed decision never reaches the broker
	var req *proto.Request
	if *decideIn {
		var err error
		if req, err = readDecision(stdin); err != nil {
			fmt.Fprintf(stderr, "tmb approve: decision on stdin: %v\n", err)
			return 2
		}
	}
	path := orEnv(*sock, "TMB_APPROVE_SOCK")
	if path == "" {
		path = defaultApproveSocket
	}
	c := approverClient{path: path}

	var err error
	switch {
	case *decideIn:
		err = c.decideMachine(req, stdout)
	case *list && *asJSON:
		err = c.listJSON(stdout)
	case *list:
		var items []proto.QueueItem
		items, err = c.list()
		if err == nil {
			if len(items) == 0 {
				fmt.Fprintln(stdout, "queue is empty")
			}
			for _, it := range items {
				printItem(stdout, it)
			}
		}
	case *yes != "":
		err = c.decideByID(*yes, "approve", stdout)
	case *no != "":
		err = c.decideByID(*no, "deny", stdout)
	default:
		err = c.interactive(stdin, stdout)
	}
	if err == nil {
		return 0
	}
	fmt.Fprintf(stderr, "tmb approve: %v\n", err)
	var de *approverDenied
	var te *transportErr
	switch {
	case errors.As(err, &de) && (de.reason == "already_decided" || de.reason == "no_such_item"):
		return 1
	case errors.As(err, &de):
		return 125
	case errors.As(err, &te):
		return 3
	}
	return 1
}

type approverClient struct{ path string }

// approverIOTimeout bounds one approver exchange after connect: a broker
// that accepts and never answers ends in a transport error instead of
// hanging the approver (or the signer that runs it) forever. The broker
// answers a decide at once, so the bound is generous.
var approverIOTimeout = 60 * time.Second

// roundtrip sends one approver message and returns the single answer frame.
func (c approverClient) roundtrip(req *proto.Request) (*proto.Frame, error) {
	f, _, err := c.roundtripRaw(req)
	return f, err
}

// roundtripRaw also returns the answer frame's bytes as the broker sent them
// (for a denial too), so machine mode can pass on fields this client does not
// know.
func (c approverClient) roundtripRaw(req *proto.Request) (*proto.Frame, []byte, error) {
	conn, err := net.DialTimeout("unix", c.path, 3*time.Second)
	if err != nil {
		return nil, nil, &transportErr{fmt.Errorf("approver socket %s: %w", c.path, err)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(approverIOTimeout))
	if err := proto.WriteFrame(conn, req); err != nil {
		return nil, nil, &transportErr{err}
	}
	raw, err := proto.ReadRawFrame(conn)
	var f proto.Frame
	if err == nil {
		err = json.Unmarshal(raw, &f)
	}
	if err != nil {
		return nil, nil, &transportErr{fmt.Errorf("connection to broker lost: %w", err)}
	}
	if f.Type == "denied" {
		return nil, raw, &approverDenied{f.Reason, f.Detail}
	}
	return &f, raw, nil
}

// printRaw writes one broker frame (or a value built from one) as a single
// line of JSON. termsafe.JSON keeps it valid JSON while escaping what would
// act on a terminal: someone may read the machine output there too.
func printRaw(w io.Writer, b []byte) {
	fmt.Fprintln(w, termsafe.JSON(b))
}

// printCompact prints a frame the broker sent on one line. raw already
// decoded as a Frame, so it is valid JSON and Compact cannot fail.
func printCompact(w io.Writer, raw []byte) {
	var buf bytes.Buffer
	_ = json.Compact(&buf, raw)
	printRaw(w, buf.Bytes())
}

// printDenial passes a broker denial on in machine mode; roundtripRaw
// returns the frame only with a denial.
func printDenial(w io.Writer, raw []byte) {
	if raw != nil {
		printCompact(w, raw)
	}
}

// listJSON prints the queue for the signer: every item as the broker sent
// it, so fields added on the broker side reach the signer without a client
// change.
func (c approverClient) listJSON(stdout io.Writer) error {
	f, raw, err := c.roundtripRaw(&proto.Request{Type: "list"})
	if err != nil {
		printDenial(stdout, raw)
		return err
	}
	if f.Type != "queue" {
		return fmt.Errorf("unexpected answer %q to list", f.Type)
	}
	// raw already decoded as a Frame, so items is an array of objects and
	// neither step below can fail
	var q struct {
		Items []json.RawMessage `json:"items"`
	}
	_ = json.Unmarshal(raw, &q)
	if q.Items == nil {
		q.Items = []json.RawMessage{}
	}
	out, _ := json.Marshal(struct {
		Type  string            `json:"type"`
		Items []json.RawMessage `json:"items"`
	}{"queue", q.Items})
	printRaw(stdout, out)
	return nil
}

// decideMachine sends a decision read by --decide and prints the broker's
// answer. "recorded" (a valid signature below the threshold) is a success
// like "decided".
func (c approverClient) decideMachine(req *proto.Request, stdout io.Writer) error {
	f, raw, err := c.roundtripRaw(req)
	if err != nil {
		printDenial(stdout, raw)
		return err
	}
	if f.Type != "decided" && f.Type != "recorded" {
		return fmt.Errorf("unexpected answer %q to decide", f.Type)
	}
	printCompact(stdout, raw)
	return nil
}

// maxDecisionInput bounds what --decide reads from stdin: a decision is a
// few hundred bytes.
const maxDecisionInput = 64 << 10

// decisionFields are the keys of the object --decide reads: the signer's
// DecideMessage. item_id, item_hash and decision are required; signature
// (base64 DER) and approver_key (key fingerprint) come together or not at all.
var decisionFields = []string{"item_id", "item_hash", "decision", "signature", "approver_key"}

// readDecision parses the decision object strictly: exactly one JSON object,
// only known keys spelled exactly, each once, every value a string, nothing
// after it. Anything else is refused before the broker is contacted.
func readDecision(r io.Reader) (*proto.Request, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxDecisionInput+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDecisionInput {
		return nil, fmt.Errorf("more than %d bytes", maxDecisionInput)
	}
	vals, err := parseStringObject(b)
	if err != nil {
		return nil, err
	}
	req := &proto.Request{Type: "decide", ItemID: vals["item_id"], ItemHash: vals["item_hash"], Decision: vals["decision"],
		Signature: vals["signature"], ApproverKey: vals["approver_key"]}
	switch {
	case !isLowerHex(req.ItemHash, 64):
		return nil, errors.New("item_hash must be 64 lowercase hex characters")
	case req.ItemID != proto.TokenID(req.ItemHash):
		return nil, errors.New("item_id must be the first 16 characters of item_hash")
	case req.Decision != "approve" && req.Decision != "deny":
		return nil, errors.New(`decision must be "approve" or "deny"`)
	}
	_, hasSig := vals["signature"]
	_, hasKey := vals["approver_key"]
	if hasSig != hasKey {
		return nil, errors.New("signature and approver_key go together")
	}
	if hasSig {
		if _, err := proto.DecodeSignature(req.Signature); err != nil {
			return nil, err
		}
		if !isLowerHex(req.ApproverKey, 64) {
			return nil, errors.New("approver_key must be 64 lowercase hex characters")
		}
	}
	return req, nil
}

// parseStringObject reads one JSON object whose keys are among
// decisionFields and whose values are strings. encoding/json alone would
// accept duplicate keys, case-folded keys and trailing data.
func parseStringObject(b []byte) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("want one JSON object")
	}
	vals := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("not JSON: %w", err)
		}
		key, _ := tok.(string)
		known := false
		for _, k := range decisionFields {
			known = known || k == key
		}
		if !known {
			return nil, fmt.Errorf("unknown field %s", termsafe.Text(key))
		}
		if _, dup := vals[key]; dup {
			return nil, fmt.Errorf("field %s given twice", key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("not JSON: %w", err)
		}
		var s string
		if v[0] != '"' || json.Unmarshal(v, &s) != nil {
			return nil, fmt.Errorf("field %s must be a string", key)
		}
		vals[key] = s
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	return vals, nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (c approverClient) list() ([]proto.QueueItem, error) {
	f, err := c.roundtrip(&proto.Request{Type: "list"})
	if err != nil {
		return nil, err
	}
	if f.Type != "queue" {
		return nil, fmt.Errorf("unexpected answer %q to list", f.Type)
	}
	return f.Items, nil
}

func (c approverClient) decide(it proto.QueueItem, decision string) error {
	f, err := c.roundtrip(&proto.Request{Type: "decide", ItemID: it.ID, ItemHash: it.Hash, Decision: decision})
	if err != nil {
		if de := (*approverDenied)(nil); errors.As(err, &de) && de.reason == "already_decided" {
			return fmt.Errorf("item %s already decided: %w", it.ID, err)
		}
		return err
	}
	if f.Type != "decided" {
		return fmt.Errorf("unexpected answer %q to decide", f.Type)
	}
	return nil
}

// decideByID looks the item up in the queue, so the decision carries the
// hash of exactly the request the broker holds.
func (c approverClient) decideByID(id, decision string, stdout io.Writer) error {
	items, err := c.list()
	if err != nil {
		return err
	}
	for _, it := range items {
		if it.ID == id {
			if err := c.decide(it, decision); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "%s: %s\n", id, decision)
			return nil
		}
	}
	// not waiting any more: let the broker say whether it was decided
	err = c.decide(proto.QueueItem{ID: id}, decision)
	if err == nil {
		return fmt.Errorf("item %s accepted a decision without a hash", id)
	}
	return err
}

// interactive shows every waiting item and asks y/N for each.
func (c approverClient) interactive(stdin io.Reader, stdout io.Writer) error {
	items, err := c.list()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Fprintln(stdout, "queue is empty")
		return nil
	}
	in := bufio.NewReader(stdin)
	for _, it := range items {
		printItem(stdout, it)
		fmt.Fprint(stdout, "Approve exactly this command? [y/N]: ")
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			// end of input is no answer: leave this item and the rest queued
			fmt.Fprintf(stdout, "\nno answer, %s and later items left in the queue\n", it.ID)
			return nil
		}
		decision := "deny"
		if ans := strings.ToLower(strings.TrimSpace(line)); ans == "y" || ans == "yes" {
			decision = "approve"
		}
		if err := c.decide(it, decision); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s: %s\n", it.ID, decision)
	}
	return nil
}

// printItem renders one queue item: what will run, as the broker resolved it.
// Every field passes through termsafe.Text or termsafe.JSON: the requester
// chooses the nonce, argv, env and the paths, and a control sequence in any of
// them must not redraw the lines the approver reads.
func printItem(w io.Writer, it proto.QueueItem) {
	argv, _ := json.Marshal(it.Argv)
	env, _ := json.Marshal(it.Env)
	fmt.Fprintf(w, "=== %s ===\n", termsafe.Text(it.ID))
	if it.ShortCode != "" {
		// the code the signer's dialog shows: the approver matches the two
		fmt.Fprintf(w, "  short code: %s\n", termsafe.Text(it.ShortCode))
	}
	fmt.Fprintf(w, "  requester : %s\n", termsafe.Text(it.Requester))
	fmt.Fprintf(w, "  executable: %s\n", termsafe.Text(it.Executable))
	fmt.Fprintf(w, "  argv      : %s\n", termsafe.JSON(argv))
	fmt.Fprintf(w, "  cwd       : %s\n", termsafe.Text(it.Cwd))
	fmt.Fprintf(w, "  run as uid: %d\n", it.UID)
	fmt.Fprintf(w, "  env       : %s\n", termsafe.JSON(env))
	fmt.Fprintf(w, "  nonce     : %s\n", termsafe.Text(it.Nonce))
	fmt.Fprintf(w, "  queued at : %s\n", termsafe.Text(it.QueuedAt))
	fmt.Fprintf(w, "  hash      : %s\n", termsafe.Text(it.Hash))
}
