package connector_test

import (
	"path/filepath"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestImportEvidenceJournal is FR-22.14 against the Gateway's real
// Evidence Journal: a successful, a refused and a declined import of
// hosted entries each record one catalog_import event, each decision one
// catalog_trust_decision event, with the entry ID and digest, class,
// catalog SHA-256, actor, outcome with reason and, on success, the
// package server ID and revision; and the journal verifies afterwards, as
// `smcpctl journal verify` checks it (FR-22.13 in part: the imported
// package is verified-disabled).
func TestImportEvidenceJournal(t *testing.T) {
	reqtest.Verifies(t, "FR-22.14")
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{
		{ID: "ev-ok", URL: "https://ev-ok.example.com/mcp"},
		{ID: "ev-key", URL: "https://ev-key.example.com/mcp", AuthType: "API Key", RequiresAPIKey: true},
		{ID: "ev-no", URL: "https://ev-no.example.com/mcp"},
	}})
	g := e.StartGateway(cfharness.GatewayOptions{Approve: true})
	cat := e.Conn.Status().CatalogSHA256

	// Success.
	p, err := e.Probe("ev-ok", connector.LocalImport{})
	if err != nil || p.State != "ready" {
		t.Fatalf("probe: %v %+v", err, p)
	}
	ok, err := e.Conn.Decide(p.ID, true, p.Decision.SHA256, "op-alice")
	if err != nil || ok.Outcome != "imported" {
		t.Fatalf("accept: %v %+v", err, ok)
	}
	if r, _ := e.Lib.Get(ok.ServerID, ok.Revision); r.State != library.StateVerifiedDisabled {
		t.Fatalf("imported revision %s", r.State)
	}
	// Refused: an API-key entry without a probe secret.
	if _, err := e.Conn.ProposeLocal("ev-key", connector.LocalImport{}, "op-alice"); packaging.ReasonOf(err) != connector.ReasonProbeSecretRequired {
		t.Fatalf("refused import: %v", err)
	}
	// Declined.
	q, err := e.Probe("ev-no", connector.LocalImport{})
	if err != nil || q.State != "ready" {
		t.Fatalf("probe: %v %+v", err, q)
	}
	if _, err := e.Conn.Decide(q.ID, false, "", "op-bob"); err != nil {
		t.Fatal(err)
	}
	g.Stop()

	imports, decisions := map[string][]map[string]any{}, map[string][]map[string]any{}
	for _, ev := range g.Events() {
		d, _ := ev.Detail.(map[string]any)
		switch ev.Class {
		case connector.ClassImport:
			imports[d["entry_id"].(string)] = append(imports[d["entry_id"].(string)], d)
			if d["entry_sha256"] == "" || d["class"] != "hosted" || d["catalog_sha256"] != cat || d["actor"] == "" || d["outcome"] != ev.Outcome {
				t.Errorf("catalog_import event %+v", d)
			}
		case connector.ClassTrustDecision:
			decisions[d["entry_id"].(string)] = append(decisions[d["entry_id"].(string)], d)
		}
	}
	for id, want := range map[string]string{"ev-ok": "imported", "ev-key": "refused", "ev-no": "declined"} {
		if len(imports[id]) != 1 || imports[id][0]["outcome"] != want {
			t.Errorf("%s: catalog_import events %+v, want one %s", id, imports[id], want)
		}
	}
	if d := imports["ev-ok"][0]; d["server_id"] != ok.ServerID || d["revision"] != ok.Revision {
		t.Errorf("imported event %+v", d)
	}
	if d := imports["ev-key"][0]; d["reason"] == nil {
		t.Errorf("refused event without a reason %+v", d)
	}
	if len(decisions["ev-ok"]) != 1 || len(decisions["ev-no"]) != 1 || len(decisions["ev-key"]) != 0 {
		t.Errorf("catalog_trust_decision events %+v", decisions)
	}
	root, err := keys.LoadEvidenceTrustRoot(e.State)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := audit.VerifyWith(filepath.Join(e.State, "journal"), root, audit.VerifyOptions{})
	if err != nil {
		t.Fatalf("journal verification: %v", err)
	}
	t.Logf("journal OK: %d segments, %d events", rep.Segments, rep.Events)
}
