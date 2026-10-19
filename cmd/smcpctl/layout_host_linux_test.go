//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// otherIdentities are the CP-46 identities other than smcp-core, plus
// nobody: none of them may read smcpd's keys or write its evidence copies.
var otherIdentities = []string{"smcp-evidence", "smcp-keys", "smcp-vault", "smcp-data", "smcp-console", "smcp-srv", "nobody"}

// TestEnforcedLayoutOnHost inspects the directories, owners and modes of
// an Enforced installation made by `smcpctl install --profile enforced`
// (scripts/ci-systemd.sh, after smcpd.service ran and was stopped) and
// tries to read the evidence key and to write the evidence checkpoints as
// every other identity.
//
// SR-6.12-1: the evidence-signing key is readable by smcp-core only, the
// identity of smcpd, which hosts the evidence exporter in release 1.x
// (SR-4.1-1); every other CP-46 identity, nobody and the operator's
// account are refused. The checkpoints (each closed segment and the signed
// anchor) are copied by smcpd's exporter to [evidence] export_dir, which
// the installation sets to /var/lib/smcp/exports (smcp-core, 0750): the
// copy is there and verifies, and creating, replacing or appending to the
// copies is refused to every other identity.
//
// FR-12.4 (Enforced half, Partial: the Standalone layouts are checked by
// scripts/ci-install-standalone.sh, and the Inspection record combines
// them) and SR-4.2-2 (Inspection, Partial here: the record verifies it):
// each CP-46 directory has the owner and mode CP-46 states, the
// Observation Store's files are smcp-core's with mode 0600 or stricter.
//
// It reads root-owned files with sudo, so it runs only with
// SMCP_ENFORCED_LAYOUT_TEST=1 (scripts/ci-systemd.sh).
func TestEnforcedLayoutOnHost(t *testing.T) {
	if os.Getenv("SMCP_ENFORCED_LAYOUT_TEST") != "1" {
		t.Skip("inspects an Enforced installation; set SMCP_ENFORCED_LAYOUT_TEST=1 after scripts/ci-systemd.sh installed it")
	}
	reqtest.Verifies(t, "SR-6.12-1")
	reqtest.Partial(t, "FR-12.4", "SR-4.2-2")
	const (
		state   = "/var/lib/smcp/state"
		exports = "/var/lib/smcp/exports"
	)
	statOf := func(p string) string {
		t.Helper()
		out, err := sudoOut(t, "", "stat", "-c", "%U:%G %a", p)
		if err != nil {
			t.Fatalf("stat %s: %v %s", p, err, out)
		}
		return strings.TrimSpace(out)
	}

	// CP-46 (Enforced) as narrowed for release 1.x.
	for _, d := range []struct{ path, want string }{
		{"/etc/smcp", "root:smcp 750"},
		{"/etc/smcp/smcp.toml", "root:smcp 640"},
		{"/var/lib/smcp", "root:smcp 755"},
		{state, "smcp-core:smcp 700"},
		{"/var/lib/smcp/policy", "smcp-core:smcp 700"},
		{"/var/lib/smcp/registry", "smcp-core:smcp 700"},
		{"/var/lib/smcp/artifacts", "smcp-core:smcp 700"},
		{exports, "smcp-core:smcp 750"},
		{"/var/lib/smcp/journal", "smcp-evidence:smcp 700"},
		{"/var/lib/smcp/keys", "smcp-keys:smcp 700"},
		{"/var/lib/smcp/vault", "smcp-vault:smcp 700"},
		{"/var/log/smcp", "smcp-core:smcp 750"},
		{"/var/lib/smcp/home", "root:root 755"},
		{"/var/lib/smcp/srv", "smcp-core:smcp-srv 751"},
		{filepath.Join(state, "keys"), "smcp-core:smcp 700"},
		{filepath.Join(state, keys.EvidenceKeyFile), "smcp-core:smcp 600"},
		{filepath.Join(state, "journal"), "smcp-core:smcp 700"},
	} {
		got := statOf(d.path)
		t.Logf("%s %s", d.path, got)
		if got != d.want {
			t.Errorf("%s is %s, CP-46 states %s", d.path, got, d.want)
		}
	}

	// SR-4.2-2: the Observation Store's files.
	obs := filepath.Join(state, "observation")
	list, err := sudoOut(t, "", "find", obs, "-printf", "%y %u %m %p\n")
	if err != nil {
		t.Fatalf("find %s: %v %s", obs, err, list)
	}
	files := 0
	for _, l := range strings.Split(strings.TrimSpace(list), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		mode, err := strconv.ParseUint(f[2], 8, 32)
		if err != nil {
			t.Fatalf("mode of %s: %v", f[3], err)
		}
		if f[1] != "smcp-core" {
			t.Errorf("%s is owned by %s, not smcp-core", f[3], f[1])
		}
		switch f[0] {
		case "f":
			files++
			if mode&0o177 != 0 {
				t.Errorf("observation file %s has mode %s, wider than 0600", f[3], f[2])
			}
		case "d":
			if mode&0o077 != 0 {
				t.Errorf("observation directory %s has mode %s, wider than 0700", f[3], f[2])
			}
		}
	}
	t.Logf("observation store: %d files, all smcp-core's with mode 0600 or stricter", files)
	if files == 0 {
		t.Error("the Observation Store holds no files to inspect")
	}

	// SR-6.12-1: the key and the checkpoint copies.
	key := filepath.Join(state, keys.EvidenceKeyFile)
	if out, err := sudoOut(t, "", "-u", "smcp-core", "test", "-r", key); err != nil {
		t.Fatalf("smcp-core cannot read the evidence key: %v %s", err, out)
	}
	anchor := filepath.Join(exports, "journal.anchor")
	before, err := sudoOut(t, "", "cat", anchor)
	if err != nil || !strings.Contains(before, `"type":"anchor"`) {
		t.Fatalf("no checkpoint copy at %s: %v %s", anchor, err, before)
	}
	genesis := filepath.Join(exports, "keys", "evidence-genesis.pub")
	if out, err := sudoOut(t, "", "-u", "smcp-core", "/usr/local/bin/smcpctl", "journal", "verify",
		"--dir", filepath.Join(exports, "journal"), "--key", genesis); err != nil || !strings.Contains(out, "journal OK") {
		t.Fatalf("the exported journal and checkpoint do not verify: %v\n%s", err, out)
	}
	if b, err := os.ReadFile(key); err == nil || len(b) > 0 {
		t.Errorf("the operator's account read the evidence key (%v)", err)
	}
	for _, id := range otherIdentities {
		if out, err := sudoOut(t, "", "-u", id, "cat", key); err == nil {
			t.Errorf("%s read the evidence key: %d bytes", id, len(out))
		}
		for _, p := range []string{filepath.Join(exports, "planted-"+id), filepath.Join(exports, "journal", "planted-"+id)} {
			if _, err := sudoOut(t, "", "-u", id, "touch", p); err == nil {
				t.Errorf("%s created %s", id, p)
			}
		}
		if _, err := sudoOut(t, "{}\n", "-u", id, "tee", "-a", anchor); err == nil {
			t.Errorf("%s appended to the checkpoint copy", id)
		}
		if _, err := sudoOut(t, "", "-u", id, "cp", "/dev/null", anchor); err == nil {
			t.Errorf("%s replaced the checkpoint copy", id)
		}
	}
	if f, err := os.OpenFile(anchor, os.O_WRONLY|os.O_APPEND, 0); err == nil {
		f.Close()
		t.Error("the operator's account opened the checkpoint copy for writing")
	}
	if after, _ := sudoOut(t, "", "cat", anchor); after != before {
		t.Error("the checkpoint copy changed during the attempts")
	}
}
