package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWSLInstallPlan: smcpctl install --wsl (FR-21.15) creates the
// dedicated distribution when it is missing, writes a wsl.conf with
// systemd on and interop and the Windows PATH off, restarts the
// distribution, installs the release by install.sh (FR-13.5), reports the
// Enforced prerequisites and installs the Enforced profile, each as a fixed
// argument vector run as root inside smcp-gateway; it refuses off Windows,
// without a release tag and without WSL. Inside the distribution the
// Gateway is labelled wsl2 and never enforced (SR-4-2). The run on a host
// with WSL2 is a recorded Demonstration (hosted runners have no nested
// virtualization).
func TestWSLInstallPlan(t *testing.T) {
	reqtest.Partial(t, "FR-21.15", "SR-4-2")
	conf := wslConf()
	for _, want := range []string{"[boot]\nsystemd=true", "[interop]\nenabled=false\nappendWindowsPath=false"} {
		if !strings.Contains(conf, want) {
			t.Errorf("wsl.conf lacks %q:\n%s", want, conf)
		}
	}
	if p, err := wslPath(`C:\Users\u\AppData\Local\Temp\smcp-wsl-1\wsl.conf`); err != nil || p != "/mnt/c/Users/u/AppData/Local/Temp/smcp-wsl-1/wsl.conf" {
		t.Fatalf("wslPath = %q, %v", p, err)
	}
	if _, err := wslPath(`\\host\share\x`); err == nil {
		t.Fatal("a UNC path has no automount path")
	}

	var ran [][]string
	newIn := func(goos string, wslOK, distroOK bool) (*installer, *bytes.Buffer) {
		var out bytes.Buffer
		ran = nil
		in := &installer{goos: goos, out: &out, wslTemp: func(name string, _ []byte) (string, func(), error) {
			return `C:\Users\u\AppData\Local\Temp\smcp-wsl-1\` + name, func() {}, nil
		}}
		in.run = func(argv ...string) error { ran = append(ran, argv); return nil }
		in.ok = func(argv ...string) bool {
			if slices.Contains(argv, "--status") {
				return wslOK
			}
			return distroOK
		}
		return in, &out
	}
	if in, _ := newIn("linux", true, true); in.windowsWSL("v1.3.0") == nil {
		t.Error("--wsl accepted off Windows")
	}
	if in, _ := newIn("windows", true, true); in.windowsWSL("") == nil {
		t.Error("--wsl accepted without a release tag")
	}
	if in, _ := newIn("windows", false, false); in.windowsWSL("v1.3.0") == nil || len(ran) != 0 {
		t.Errorf("--wsl without WSL: ran %v", ran)
	}
	in, out := newIn("windows", true, false)
	if err := in.windowsWSL("v1.3.0"); err != nil {
		t.Fatal(err)
	}
	joined := make([]string, len(ran))
	for i, a := range ran {
		joined[i] = strings.Join(a, " ")
	}
	want := []string{
		"wsl.exe --install --distribution Ubuntu-24.04 --name smcp-gateway --no-launch --web-download",
		"wsl.exe --distribution smcp-gateway --user root -- cp /mnt/c/Users/u/AppData/Local/Temp/smcp-wsl-1/wsl.conf /etc/wsl.conf",
		"wsl.exe --terminate smcp-gateway",
		"wsl.exe --distribution smcp-gateway --user root -- apt-get install -y curl minisign podman nftables uidmap",
		"wsl.exe --distribution smcp-gateway --user root -- curl -fsSLo /root/smcp-install.sh https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/v1.3.0/install.sh",
		"wsl.exe --distribution smcp-gateway --user root -- sh /root/smcp-install.sh --version v1.3.0 --dir /usr/local/bin",
		"wsl.exe --distribution smcp-gateway --user root -- /usr/local/bin/smcpctl install --check --profile enforced",
		"wsl.exe --distribution smcp-gateway --user root -- /usr/local/bin/smcpctl install --profile enforced --bootstrap-token",
	}
	at := 0
	for _, w := range want {
		i := slices.IndexFunc(joined[at:], func(s string) bool { return strings.HasPrefix(s, w) })
		if i < 0 {
			t.Fatalf("missing or out of order: %q\nran:\n%s", w, strings.Join(joined, "\n"))
		}
		at += i + 1
	}
	for _, a := range ran {
		if slices.ContainsFunc(a, func(s string) bool { return strings.EqualFold(s, "cmd.exe") || strings.EqualFold(s, "powershell.exe") }) {
			t.Errorf("a Windows shell in %v", a)
		}
	}
	if !strings.Contains(out.String(), "not enforced, wsl2") {
		t.Errorf("no label in the output:\n%s", out.String())
	}
	// An existing distribution is reused.
	in, _ = newIn("windows", true, true)
	if err := in.windowsWSL("v1.3.0"); err != nil || slices.ContainsFunc(ran, func(a []string) bool { return slices.Contains(a, "--install") }) {
		t.Errorf("existing distribution: %v %v", ran, err)
	}
	// Inside the distribution the host is WSL even for a systemd service
	// (no WSL_DISTRO_NAME), and Enforced is never resolved there.
	if !profile.IsWSL("6.18.3-microsoft-standard-WSL2", "") {
		t.Error("the WSL2 kernel release is not detected")
	}
}
