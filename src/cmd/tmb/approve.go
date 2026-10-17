// PROTOTYPE CODE - throwaway PoC, not production.
package main

// tmb approve: the approver side of the approval queue (ADR 0004). It talks
// only to the approver socket on the host; the broker checks the caller's
// uid against approver_uids via SO_PEERCRED.
//
// Exit codes: 0 decision accepted (or --list printed), 1 the item was
// already decided or is not in the queue, 2 usage, 3 transport, 125 the
// broker refused (approver_not_allowed and other denials).

import (
	"bufio"
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	modes := 0
	for _, set := range []bool{*list, *yes != "", *no != ""} {
		if set {
			modes++
		}
	}
	if modes > 1 || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "tmb approve: use at most one of --list, --yes ID, --no ID")
		return 2
	}
	path := orEnv(*sock, "TMB_APPROVE_SOCK")
	if path == "" {
		path = defaultApproveSocket
	}
	c := approverClient{path: path}

	var err error
	switch {
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

// roundtrip sends one approver message and returns the single answer frame.
func (c approverClient) roundtrip(req *proto.Request) (*proto.Frame, error) {
	conn, err := net.DialTimeout("unix", c.path, 3*time.Second)
	if err != nil {
		return nil, &transportErr{fmt.Errorf("approver socket %s: %w", c.path, err)}
	}
	defer conn.Close()
	if err := proto.WriteFrame(conn, req); err != nil {
		return nil, &transportErr{err}
	}
	f, err := proto.ReadFrame(conn)
	if err != nil {
		return nil, &transportErr{fmt.Errorf("connection to broker lost: %w", err)}
	}
	if f.Type == "denied" {
		return nil, &approverDenied{f.Reason, f.Detail}
	}
	return f, nil
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
