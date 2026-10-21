package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const reviewPath = "../../packaging/sbom-review.json"

func TestExpressions(t *testing.T) {
	reviewed := map[string]bool{"licenseref-x": true}
	for _, c := range []struct {
		expr string
		want bool
	}{
		{"MIT", true},
		{"Apache-2.0 AND BSD-3-Clause", true},
		{"(MIT OR CC-BY-4.0)", true},
		{"MIT AND CC-BY-4.0", false},
		{"CC-BY-4.0", false},
		{"GPL-2.0-or-later WITH Classpath-exception-2.0", true},
		{"CC0-1.0", true},
		{"MIT AND LicenseRef-x", true},
		{"MIT AND LicenseRef-y", false},
		{"Apache-2.0 AND (MIT OR SSPL-1.0)", true},
		{"Apache-2.0 AND (BUSL-1.1 OR SSPL-1.0)", false},
		{"MIT AND", false},
		{"(MIT", false},
		{"MIT WITH", false},
		{"", false},
	} {
		if got := exprAccepted(c.expr, reviewed); got != c.want {
			t.Errorf("exprAccepted(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
	if ids := identifiers("(GPL-2.0-only WITH Classpath-exception-2.0) OR MIT"); strings.Join(ids, " ") != "GPL-2.0-only MIT" {
		t.Fatalf("identifiers: %v", ids)
	}
}

func writeSBOM(t *testing.T, packages string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(p, []byte(`{"spdxVersion":"SPDX-2.3","packages":[`+packages+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestReviewsArePerPackage checks that a reviewed identifier is accepted
// only for the package named in the review, that a package without any
// license value is refused, and that the document root is not a component.
func TestReviewsArePerPackage(t *testing.T) {
	reqtest.Partial(t, "FR-12.1")
	p := writeSBOM(t, `
		{"SPDXID":"SPDXRef-DocumentRoot-File-x","name":"x.tar.gz","licenseConcluded":"NOASSERTION"},
		{"SPDXID":"SPDXRef-a","name":"github.com/modelcontextprotocol/go-sdk","versionInfo":"v1","licenseConcluded":"Apache-2.0 AND CC-BY-4.0 AND MIT"},
		{"SPDXID":"SPDXRef-b","name":"example.com/docs","versionInfo":"v1","licenseConcluded":"Apache-2.0 AND CC-BY-4.0"},
		{"SPDXID":"SPDXRef-c","name":"example.com/none","versionInfo":"v1","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION"},
		{"SPDXID":"SPDXRef-d","name":"stdlib","versionInfo":"go1.26","licenseConcluded":"NOASSERTION","licenseDeclared":"BSD-3-Clause"}`)
	var out bytes.Buffer
	code, err := run([]string{"-review", reviewPath, p}, &out)
	if code != 1 || err == nil {
		t.Fatalf("exit %d, %v\n%s", code, err, out.String())
	}
	s := out.String()
	for _, want := range []string{
		"reviewed " + p + ": github.com/modelcontextprotocol/go-sdk v1: CC-BY-4.0 accepted as Apache-2.0 AND MIT",
		"REFUSED " + p + `: example.com/docs v1: "Apache-2.0 AND CC-BY-4.0" (CC-BY-4.0)`,
		"REFUSED " + p + `: example.com/none v1: "NOASSERTION" (license)`,
		p + ": 2 packages accepted, 2 refused",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "x.tar.gz") {
		t.Errorf("the document root was checked:\n%s", s)
	}
}

func TestReviewFileRules(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"incomplete.json": `{"reviews":[{"package":"p","identifier":"X"}]}`,
		"not-osi.json":    `{"reviews":[{"package":"p","identifier":"X","license":"CC-BY-4.0","reason":"r"}]}`,
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadReviews(p, false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := loadReviews(reviewPath, false); err != nil {
		t.Fatal(err)
	}
}

// TestReleaseSBOMs runs the check on the license fields of real SBOMs: the
// per-archive SBOM of the v1.0.0 release (accepted with the reviewed
// exceptions), the SBOM inside the v1.0.0 archives (refused: syft did not
// read the Go modules' license files, so 45 entries carry no license
// value), and the SBOM scripts/release-sbom.sh writes now that it searches
// the module licenses (accepted). FR-12.1 stays partial until the SBOMs of
// a release built with this check are inspected.
func TestReleaseSBOMs(t *testing.T) {
	reqtest.Partial(t, "FR-12.1")
	reviews, err := loadReviews(reviewPath, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		file    string
		refused int
	}{
		{"testdata/v1.0.0-linux-amd64-archive.spdx.json", 0},
		{"testdata/v1.0.0-embedded.spdx.json", 45},
		{"testdata/embedded-module-licenses.spdx.json", 0},
	} {
		findings, err := checkFile(c.file, reviews, false)
		if err != nil {
			t.Fatal(err)
		}
		var refused []string
		for _, f := range findings {
			if !f.OK() {
				refused = append(refused, f.Package)
			}
		}
		if len(refused) != c.refused {
			t.Errorf("%s: %d refused, want %d: %v", c.file, len(refused), c.refused, refused)
		}
		if len(findings) < 40 {
			t.Errorf("%s: only %d packages", c.file, len(findings))
		}
	}
}

// TestIdentifiers is the FR-22.21 mode used for the ContextForge SBOMs
// (scripts/contextforge-release-assets.sh): a component with any
// well-formed SPDX license expression passes, one without a license value
// fails unless a review establishes it, and a malformed expression fails.
// The Inspection of a release candidate's SBOM set is recorded separately.
func TestIdentifiers(t *testing.T) {
	reqtest.Partial(t, "FR-22.21")
	review := filepath.Join(t.TempDir(), "review.json")
	if err := os.WriteFile(review, []byte(`{"reviews":[{"package":"jinja2","identifier":"license","license":"BSD-3-Clause","reason":"LICENSE.txt read"},
{"package":"pywin32","identifier":"license","license":"PSF-2.0","reason":"declared PSF"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ok := writeSBOM(t, `{"SPDXID":"SPDXRef-DocumentRoot-Image-x","name":"root","licenseConcluded":"NOASSERTION"},
{"SPDXID":"a","name":"mcp-contextforge-gateway","versionInfo":"1.0.11","licenseConcluded":"NOASSERTION","licenseDeclared":"Apache-2.0"},
{"SPDXID":"b","name":"libgcc","licenseDeclared":"GPL-3.0-or-later WITH GCC-exception-3.1 AND LicenseRef-Fedora-Public-Domain"},
{"SPDXID":"c","name":"jinja2","licenseDeclared":"NOASSERTION"},
{"SPDXID":"d","name":"pywin32","licenseDeclared":""}`)
	var out bytes.Buffer
	if code, err := run([]string{"-identifiers", "-review", review, ok}, &out); code != 0 {
		t.Fatalf("%d %v\n%s", code, err, out.String())
	}
	// The OSI check of FR-12.1 would refuse the same document.
	if code, _ := run([]string{"-review", "../../packaging/sbom-review.json", ok}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("FR-12.1 mode accepted a non-OSI license: %d", code)
	}
	for name, pkg := range map[string]string{
		"no value":  `{"SPDXID":"e","name":"markdown-it-py","versionInfo":"4.2.0","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION"}`,
		"NONE":      `{"SPDXID":"e","name":"x","licenseDeclared":"NONE"}`,
		"malformed": `{"SPDXID":"e","name":"x","licenseDeclared":"MIT AND"}`,
	} {
		out.Reset()
		code, err := run([]string{"-identifiers", "-review", review, writeSBOM(t, pkg)}, &out)
		if code != 1 || err == nil || !strings.Contains(err.Error(), "without an SPDX license identifier") || !strings.Contains(out.String(), "REFUSED") {
			t.Errorf("%s: %d %v\n%s", name, code, err, out.String())
		}
	}
	// A review must still name a well-formed expression.
	bad := filepath.Join(t.TempDir(), "review.json")
	_ = os.WriteFile(bad, []byte(`{"reviews":[{"package":"x","identifier":"license","license":"MIT OR","reason":"r"}]}`), 0o600)
	if code, _ := run([]string{"-identifiers", "-review", bad, ok}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("malformed review accepted: %d", code)
	}
}
