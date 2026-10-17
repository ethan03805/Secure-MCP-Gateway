package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestRuntimeCommands(t *testing.T) {
	reqtest.Partial(t, "FR-5.9")
	dir := t.TempDir()
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	share := filepath.Join(dir, "sandbox")
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("\n[runtime]\nsandbox = \"podman\"\n[[runtime.server]]\nalias = \"ref\"\n[[runtime.server.mount]]\nsource = \"" + share + "\"\ntarget = \"/data\"\n")
	f.Close()

	// spec works offline on any platform and prints names, not values.
	out := mustCtl(t, "runtime", "spec", "--config", cfgPath)
	var doc struct {
		Sandbox string `json:"sandbox"`
		Servers []struct {
			LaunchSpec struct {
				Alias    string `json:"alias"`
				Artifact struct {
					Digest string `json:"digest"`
				} `json:"artifact"`
			} `json:"launch_spec"`
			PodmanArgs []string `json:"podman_args"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if doc.Sandbox != "podman" || len(doc.Servers) != 1 || doc.Servers[0].LaunchSpec.Alias != "ref" ||
		!strings.HasPrefix(doc.Servers[0].LaunchSpec.Artifact.Digest, "sha256:") {
		t.Fatalf("%s", out)
	}
	args := doc.Servers[0].PodmanArgs
	for _, want := range []string{"--read-only", "--cap-drop=all", "--network=none", "--mount=type=bind,src=" + share + ",dst=/data,ro,bind-propagation=rprivate"} {
		if !slices.Contains(args, want) {
			t.Errorf("spec lacks %s", want)
		}
	}

	out, err = ctl(t, "", "runtime", "doctor")
	if runtime.GOOS != "linux" && (err == nil || !strings.Contains(out, "FAIL  Linux")) {
		t.Fatalf("doctor on %s: %v %s", runtime.GOOS, err, out)
	}
	out, _ = ctl(t, "", "runtime", "doctor", "--json")
	if !strings.Contains(out, `"checks"`) {
		t.Fatalf("doctor --json: %s", out)
	}
	if out, err := ctl(t, "", "runtime", "show"); err == nil || !strings.Contains(out, "instance ID is required") {
		t.Fatalf("show without id: %v %s", err, out)
	}
	if out, err := ctl(t, "", "runtime", "bogus"); err == nil || !strings.Contains(out, "usage: smcpctl runtime") {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := ctl(t, "", "runtime", "help"); err != nil || !strings.Contains(out, "kill <id>") {
		t.Fatalf("%v %s", err, out)
	}
	if out := mustCtl(t, "help"); !strings.Contains(out, "runtime") {
		t.Fatal(out)
	}
}

func TestRuntimeControlCommandsStandalone(t *testing.T) {
	dir := t.TempDir()
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	d := startDaemon(t, cfgPath)
	defer stopDaemon(t, d)
	if out := mustCtl(t, "runtime", "status", "--config", cfgPath); !strings.Contains(out, `"sandbox": "none"`) {
		t.Fatalf("status: %s", out)
	}
	if out := mustCtl(t, "runtime", "instances", "--config", cfgPath); !strings.Contains(out, `"instances": []`) {
		t.Fatalf("instances: %s", out)
	}
	if out, err := ctl(t, "", "runtime", "kill", "0192", "--config", cfgPath, "--reason", "x"); err == nil || !strings.Contains(out, "no_instance") {
		t.Fatalf("kill: %v %s", err, out)
	}
}
