package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/approval"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// startApprovalGateway runs a Gateway in process with the Approval
// Service and returns its config path and the service.
func startApprovalGateway(t *testing.T) (string, *approval.Service, string) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	hash := func(pw string) string {
		h, err := keys.HashPassword(pw)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	pol := `{"revision":"r1","framework_profiles":{"dev":{"templates":["ro"],"default_template":"ro"}},"templates":{"ro":{"rules":[]}}}`
	writeFile(t, dir, "policy.json", pol)
	cfgPath := writeFile(t, dir, "smcp.toml", fmt.Sprintf(`
[listener]
address = "127.0.0.1:%s"
[admin_listener]
address = "127.0.0.1:%s"
[state]
dir = %q
[admin]
username = "admin"
password_hash = %q
[[approver]]
username = "sessionapprover"
password_hash = %q
[approvals]
notify = "off"
[[approvals.account]]
username = "alice"
password_hash = %q
[policy]
file = "policy.json"
`, freePort(t), freePort(t), state, hash("admin password 12"), hash("session approver 1"), hash("alice password 12")))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := approval.New(approval.Options{Config: cfg, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), Approver: svc, Approvals: svc})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	svc.Start(ctx, a.Evidence, a.Admin, a.Gateway)
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done; a.Close(); svc.Close() })
	return cfgPath, svc, writeFile(t, dir, "alice.pw", "alice password 12\n")
}

func heldCall(svc *approval.Service, text string) <-chan pipeline.ApprovalResult {
	ch := make(chan pipeline.ApprovalResult, 1)
	go func() {
		c := pipeline.Call{CorrelationID: "corr-" + text, SessionID: "s1", PrincipalID: "cc", Server: "fs", Tool: "write", PublicName: "fs_write",
			ServerRevision: "sr1", ToolRevision: "tr1", PolicyRevision: "r1", DecisiveRules: []string{"rule-w"}}
		r, _ := svc.Request(context.Background(), pipeline.ApprovalRequest{Call: c, Arguments: json.RawMessage(`{"text":"` + text + `"}`), Hold: 20 * time.Second})
		ch <- r
	}()
	return ch
}

func waitPending(t *testing.T, svc *approval.Service, n int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if l := svc.List(approval.StatePending); len(l) >= n {
			return l[0].ID
		}
		if time.Now().After(deadline) {
			t.Fatal("no pending approval")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestApprovalsCLI(t *testing.T) {
	// The Auditor refusal of FR-3.24 needs Auditor accounts, which do not
	// exist yet; a Session Approver account is refused instead.
	reqtest.Partial(t, "FR-3.24", "FR-3.18", "FR-3.23")
	cfgPath, svc, alicePW := startApprovalGateway(t)
	cli := func(stdin string, args ...string) (string, error) {
		var out bytes.Buffer
		err := approvalsCmd(args, strings.NewReader(stdin), &out)
		return out.String(), err
	}

	// watch prints a new approval as it is requested.
	watchOut := &syncBuf{}
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- approvalsCmd([]string{"watch", "--config", cfgPath, "--user", "alice", "--password-file", alicePW, "--max-events", "1"}, strings.NewReader(""), watchOut)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(watchOut.String(), "watching") {
		if time.Now().After(deadline) {
			t.Fatalf("watch did not start: %s", watchOut.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	created := time.Now()
	ch := heldCall(svc, "one")
	id := waitPending(t, svc, 1)
	select {
	case err := <-watchDone:
		if err != nil || !strings.Contains(watchOut.String(), "requested "+id+" fs_write on fs") {
			t.Fatalf("watch: %v %s", err, watchOut.String())
		}
		if time.Since(created) > 2*time.Second {
			t.Fatal("watch notice later than 2 s")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("watch printed nothing: %s", watchOut.String())
	}

	// list (operator token) and show (Approver).
	out, err := cli("", "--config", cfgPath)
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, "fs_write") || !strings.Contains(out, "pending") {
		t.Fatalf("list: %v %s", err, out)
	}
	out, err = cli("", "show", id, "--config", cfgPath, "--user", "alice", "--password-file", alicePW)
	for _, want := range []string{"fs_write", "sr1", "tr1", "rule-w", `"text": "one"`, "sha256:", "/approvals/" + id} {
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("show lacks %q: %v %s", want, err, out)
		}
	}
	// approve shows the evidence and asks; "n" changes nothing.
	out, err = cli("n\n", "approve", id, "--config", cfgPath, "--user", "alice", "--password-file", alicePW)
	if err == nil || !strings.Contains(out, `"text": "one"`) || !strings.Contains(out, "Approve this call? [y/N]") {
		t.Fatalf("unconfirmed approve: %v %s", err, out)
	}
	if r, _ := svc.Get(id); r.State != approval.StatePending {
		t.Fatalf("approved without confirmation: %+v", r)
	}
	out, err = cli("y\n", "approve", id, "--config", cfgPath, "--user", "alice", "--password-file", alicePW, "--comment", "checked")
	if err != nil || !strings.Contains(out, "approved "+id+" by approver:alice") {
		t.Fatalf("approve: %v %s", err, out)
	}
	if r := <-ch; r.Outcome != pipeline.Approved || r.Approver != "approver:alice" {
		t.Fatalf("held call: %+v", r)
	}
	if r, _ := svc.Get(id); r.State != approval.StateConsumed || r.DecidedBy != "approver:alice" || r.Comment != "checked" {
		t.Fatalf("%+v", r)
	}

	// deny with --yes, as the administrator (operator token).
	ch = heldCall(svc, "two")
	id2 := waitPending(t, svc, 1)
	out, err = cli("", "deny", id2, "--yes", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "denied "+id2+" by operator-token") || !strings.Contains(out, `"text": "two"`) {
		t.Fatalf("deny: %v %s", err, out)
	}
	if r := <-ch; r.Outcome != pipeline.Denied {
		t.Fatalf("%+v", r)
	}
	// Deciding again fails; list --state all --json shows both.
	if out, err := cli("", "approve", id2, "--yes", "--config", cfgPath); err == nil || !strings.Contains(out, "denied") {
		t.Fatalf("second decision: %v %s", err, out)
	}
	out, err = cli("", "list", "--state", "all", "--json", "--config", cfgPath)
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, id2) {
		t.Fatalf("list all: %v %s", err, out)
	}

	// A Session Approver account and a wrong password are refused.
	spw := writeFile(t, t.TempDir(), "s.pw", "session approver 1")
	if out, err := cli("", "list", "--config", cfgPath, "--user", "sessionapprover", "--password-file", spw); err == nil || !strings.Contains(out+err.Error(), "sign-in failed") {
		t.Fatalf("session approver signed in: %v %s", err, out)
	}
	if _, err := cli("", "show", "--config", cfgPath); err == nil {
		t.Fatal("show without an ID")
	}
	if _, err := cli("", "bogus", "--config", cfgPath); err == nil {
		t.Fatal("unknown subcommand")
	}
	if out, err := cli("", "help"); err != nil || !strings.Contains(out, "approve <id>") {
		t.Fatalf("%v %s", err, out)
	}
	_ = os.Remove(spw)
}
