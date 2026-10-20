package installsh

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"aead.dev/minisign"
)

// packageName is the release file name of the smcp package of a format for
// this host's architecture, as GoReleaser's nFPM names it.
func packageName(format string) string {
	switch format {
	case "deb":
		return "smcp_" + version + "_" + runtime.GOARCH + ".deb"
	case "rpm":
		a := "x86_64"
		if runtime.GOARCH == "arm64" {
			a = "aarch64"
		}
		return "smcp-" + version + "-1." + a + ".rpm"
	}
	return "smcp_" + version + "_darwin_arm64.pkg"
}

// verifierFarm is a tool farm with minisign or OpenSSL 3 linked in.
func verifierFarm(t *testing.T) string {
	t.Helper()
	farm := toolFarm(t)
	if p, err := exec.LookPath("minisign"); err == nil {
		if err := os.Symlink(p, filepath.Join(farm, "minisign")); err != nil {
			t.Fatal(err)
		}
	} else if o := openssl3(); o != "" {
		if err := os.Symlink(o, filepath.Join(farm, "openssl")); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Skip("neither minisign nor OpenSSL 3 is installed")
	}
	return farm
}

// TestInstallScriptPackage: `install.sh --package` downloads the platform
// package instead of the archive and verifies it exactly as the archive
// (signed checksum file, then the package's SHA-256). As a user other than
// root it saves the verified package and prints the package manager
// command; a modified package, a checksum file signed by another key and a
// release without the package are refused with nothing saved, so the
// package manager never sees an unverified file (E-35, FR-20.23). The root
// path, which installs and upgrades with the package manager, runs on a
// CI runner (TestInstallScriptPackageUpgradeOnHost).
func TestInstallScriptPackage(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root install.sh would run the package manager")
	}
	formats := []string{"deb", "rpm"}
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		formats = append(formats, "pkg")
	}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			farm := verifierFarm(t)
			name := packageName(format)
			body := []byte("package " + format + " test bytes\n")
			pub, priv, err := minisign.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			sums := []byte(sumLine(body, name) + sumLine([]byte("archive"), archiveName))
			rel := release{name: body, sumsName: sums, sumsName + ".minisig": signPrehashed(priv, sums, "smcp "+version+" file:"+sumsName)}
			pk := pub.String()

			r := runInstall(t, rel, pk, farm, "--package="+format)
			if r.err != nil {
				t.Fatalf("install.sh --package=%s: %v\n%s", format, r.err, r.out)
			}
			got, err := os.ReadFile(filepath.Join(r.dir, name))
			if err != nil || string(got) != string(body) {
				t.Fatalf("verified package not saved as %s: %v\n%s", name, err, r.out)
			}
			want := map[string]string{"deb": "sudo apt-get install -y ", "rpm": " " + filepath.Join(r.dir, name), "pkg": "sudo installer -pkg "}[format]
			if !strings.Contains(r.out, "install it as root: sudo") || !strings.Contains(r.out, want) {
				t.Fatalf("no package manager command in the output:\n%s", r.out)
			}
			if _, err := os.Stat(filepath.Join(r.dir, archiveName)); err == nil {
				t.Fatal("--package also saved the archive")
			}

			// A modified package: refused, nothing saved.
			bad := clone(rel)
			bad[name] = append(bad[name], 0)
			r = runInstall(t, bad, pk, farm, "--package="+format)
			installedNothing(t, r)
			if !strings.Contains(r.out, "checksum mismatch for "+name) {
				t.Fatalf("modified package:\n%s", r.out)
			}

			// The checksum file signed by another key.
			_, other, _ := minisign.GenerateKey(rand.Reader)
			forged := clone(rel)
			forged[sumsName+".minisig"] = signPrehashed(other, rel[sumsName], "smcp "+version+" file:"+sumsName)
			r = runInstall(t, forged, pk, farm, "--package="+format)
			installedNothing(t, r)
			if !strings.Contains(r.out, "does not verify") {
				t.Fatalf("checksum file signed by another key:\n%s", r.out)
			}

			// A release whose checksum file does not list the package.
			unlisted := clone(rel)
			unlisted[sumsName] = []byte(sumLine([]byte("archive"), archiveName))
			unlisted[sumsName+".minisig"] = signPrehashed(priv, unlisted[sumsName], "smcp "+version+" file:"+sumsName)
			r = runInstall(t, unlisted, pk, farm, "--package="+format)
			installedNothing(t, r)
			if !strings.Contains(r.out, name+" is not listed") {
				t.Fatalf("unlisted package:\n%s", r.out)
			}
		})
	}
	t.Run("unknown format", func(t *testing.T) {
		farm := verifierFarm(t)
		rel, _, pk := newRelease(t, false)
		r := runInstall(t, rel, pk, farm, "--package=msi")
		installedNothing(t, r)
		if !strings.Contains(r.out, "--package takes deb, rpm or pkg") {
			t.Fatal(r.out)
		}
	})
}
