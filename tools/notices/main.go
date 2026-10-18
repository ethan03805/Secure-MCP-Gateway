// Command notices writes the license notices and build information that
// every release archive carries (SRS FR-12.8, FR-12.1):
//
//   - THIRD_PARTY_NOTICES.txt: for each Go module linked into a release
//     binary (go list -deps over cmd/... for every release GOOS with
//     CGO_ENABLED=0) and each npm package embedded in smcpd as the built
//     console (the non-dev packages of console/package-lock.json), its
//     version and the full text of its license and notice files. Go
//     license files are read from the module cache; npm packages are
//     downloaded from the lock file's resolved URL and checked against its
//     integrity digest before their license files are read. A component
//     without a license file is an error.
//   - BUILDINFO.txt: the source commit, the version, the Go toolchain, and
//     where the build recipe and dependency lock files are in the archive.
//
// GoReleaser runs it as a before hook:
//
//	go run ./tools/notices -version 1.1.0 -commit <sha> -out build/notices
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// releaseGOOS are the operating systems of the release builds
// (.goreleaser.yaml builds.goos).
var releaseGOOS = []string{"linux", "darwin"}

// licenseName matches license and notice file names at a package root.
var licenseName = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice|patents|unlicense)([._-].*)?$`)

// component is one third-party component and its license texts.
type component struct {
	Kind    string // "go" or "npm"
	Name    string
	Version string
	Files   []licenseFile
}

type licenseFile struct {
	Name string
	Text string
}

// osiLicenses recognizes the OSI-approved licenses found among the
// Gateway's dependencies by phrases of their standard texts. A license
// file that matches none stops the release, so a dependency under another
// license is reviewed first (FR-12.1).
var osiLicenses = []struct {
	id      string
	phrases []string
}{
	{"Apache-2.0", []string{"Apache License", "Version 2.0"}},
	{"MIT", []string{"Permission is hereby granted, free of charge, to any person obtaining a copy"}},
	{"BSD-3-Clause", []string{"Redistribution and use in source and binary forms", "Neither the name"}},
	{"BSD-2-Clause", []string{"Redistribution and use in source and binary forms", "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS"}},
	{"ISC", []string{"Permission to use, copy, modify, and/or distribute this software for any"}},
	{"MPL-2.0", []string{"Mozilla Public License", "Version 2.0"}},
	{"OFL-1.1", []string{"SIL OPEN FONT LICENSE", "Version 1.1"}},
}

// classify returns the SPDX identifiers of the OSI-approved licenses whose
// phrases all occur in text (case- and whitespace-insensitive). A
// BSD-3-Clause text also matches the BSD-2-Clause phrases; only
// BSD-3-Clause is returned then.
func classify(text string) []string {
	norm := strings.ToLower(strings.Join(strings.Fields(text), " "))
	var ids []string
	for _, l := range osiLicenses {
		all := true
		for _, p := range l.phrases {
			if !strings.Contains(norm, strings.ToLower(p)) {
				all = false
				break
			}
		}
		if all && !(l.id == "BSD-2-Clause" && contains(ids, "BSD-3-Clause")) {
			ids = append(ids, l.id)
		}
	}
	return ids
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// isGrant reports a file that grants additional rights (Go's PATENTS) or
// gives notices rather than licensing the code; it needs no
// classification.
func isGrant(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "patents") || strings.HasPrefix(n, "notice")
}

// licenses checks that every license file of c is recognized as an
// OSI-approved license and that there is at least one; it returns the
// identifiers found.
func (c component) licenses() ([]string, error) {
	var ids []string
	for _, f := range c.Files {
		if isGrant(f.Name) {
			continue
		}
		got := classify(f.Text)
		if len(got) == 0 {
			return nil, fmt.Errorf("%s %s@%s: %s is not a recognized OSI-approved license; review it, and extend osiLicenses only for an OSI-approved license", c.Kind, c.Name, c.Version, f.Name)
		}
		for _, id := range got {
			if !contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%s %s@%s: no license file, only notice or patent files", c.Kind, c.Name, c.Version)
	}
	return ids, nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("notices", flag.ContinueOnError)
	out := fs.String("out", "build/notices", "output directory")
	version := fs.String("version", "dev", "release version")
	commit := fs.String("commit", "", "source commit ID (full SHA)")
	root := fs.String("root", ".", "repository root")
	lock := fs.String("lock", "console/package-lock.json", "console npm lock file, relative to -root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	goComps, err := goModules(*root)
	if err != nil {
		return err
	}
	npmComps, err := npmPackages(filepath.Join(*root, *lock), http.DefaultClient)
	if err != nil {
		return err
	}
	comps := append(goComps, npmComps...)
	for _, c := range comps {
		if _, err := c.licenses(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "THIRD_PARTY_NOTICES.txt"), []byte(renderNotices(comps)), 0o644); err != nil {
		return err
	}
	toolchain, _ := goToolchain(filepath.Join(*root, "go.mod"))
	if err := os.WriteFile(filepath.Join(*out, "BUILDINFO.txt"), []byte(renderBuildInfo(*version, *commit, toolchain)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "notices: %d Go modules, %d npm packages -> %s\n", len(goComps), len(npmComps), *out)
	return nil
}

// goModules lists the non-main modules linked into the release binaries
// and reads their license files from the module cache.
func goModules(root string) ([]component, error) {
	type mod struct{ path, version, dir string }
	seen := map[string]mod{}
	for _, goos := range releaseGOOS {
		cmd := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}", "./cmd/...")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		b, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list (GOOS=%s): %w: %s", goos, err, stderr.String())
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.Split(sc.Text(), "\t")
			if len(f) != 3 || f[0] == "" {
				continue
			}
			seen[f[0]+"@"+f[1]] = mod{f[0], f[1], f[2]}
		}
	}
	var out []component
	for _, m := range seen {
		if m.dir == "" {
			return nil, fmt.Errorf("%s@%s is not in the module cache (run go mod download)", m.path, m.version)
		}
		files, err := dirLicenses(m.dir)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("%s@%s: no license file in %s", m.path, m.version, m.dir)
		}
		out = append(out, component{Kind: "go", Name: m.path, Version: m.version, Files: files})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	// The Go standard library and runtime are linked into every binary.
	env, err := exec.Command("go", "env", "GOROOT", "GOVERSION").Output()
	if err != nil {
		return nil, fmt.Errorf("go env: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(env)), "\n")
	if len(lines) != 2 {
		return nil, fmt.Errorf("go env: %q", env)
	}
	std, err := dirLicenses(lines[0])
	if err != nil {
		return nil, fmt.Errorf("standard library license: %w", err)
	}
	if len(std) == 0 {
		return nil, fmt.Errorf("no Go standard library license in %s", lines[0])
	}
	return append([]component{{Kind: "go", Name: "std (Go standard library and runtime)", Version: lines[1], Files: std}}, out...), nil
}

// dirLicenses reads the license files at the top of dir.
func dirLicenses(dir string) ([]licenseFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []licenseFile
	for _, e := range entries {
		if e.IsDir() || !licenseName.MatchString(e.Name()) || strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, licenseFile{Name: e.Name(), Text: string(b)})
	}
	return out, nil
}

// lockFile is the part of package-lock.json (lockfileVersion 3) read here.
type lockFile struct {
	Packages map[string]struct {
		Version   string `json:"version"`
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
		License   string `json:"license"`
		Dev       bool   `json:"dev"`
	} `json:"packages"`
}

// npmPackages downloads each non-dev package of the lock file, checks its
// integrity digest and reads the license files of its package root.
func npmPackages(lockPath string, client *http.Client) ([]component, error) {
	b, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	var lf lockFile
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("%s: %w", lockPath, err)
	}
	var out []component
	for key, p := range lf.Packages {
		if key == "" || p.Dev {
			continue
		}
		name := strings.TrimPrefix(key, "node_modules/")
		if i := strings.LastIndex(name, "/node_modules/"); i >= 0 {
			name = name[i+len("/node_modules/"):]
		}
		tgz, err := fetch(client, p.Resolved)
		if err != nil {
			return nil, fmt.Errorf("%s@%s: %w", name, p.Version, err)
		}
		if err := checkIntegrity(tgz, p.Integrity); err != nil {
			return nil, fmt.Errorf("%s@%s: %w", name, p.Version, err)
		}
		files, err := tarLicenses(tgz)
		if err != nil {
			return nil, fmt.Errorf("%s@%s: %w", name, p.Version, err)
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("%s@%s: no license file in the package (declared license %q)", name, p.Version, p.License)
		}
		out = append(out, component{Kind: "npm", Name: name, Version: p.Version, Files: files})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func fetch(client *http.Client, url string) ([]byte, error) {
	if url == "" {
		return nil, errors.New("no resolved URL in the lock file")
	}
	ctxClient := *client
	if ctxClient.Timeout == 0 {
		ctxClient.Timeout = 60 * time.Second
	}
	resp, err := ctxClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// checkIntegrity compares the tarball with the lock file's sha512 SRI
// digest.
func checkIntegrity(b []byte, sri string) error {
	want, ok := strings.CutPrefix(sri, "sha512-")
	if !ok {
		return fmt.Errorf("integrity %q is not a sha512 digest", sri)
	}
	sum := sha512.Sum512(b)
	if base64.StdEncoding.EncodeToString(sum[:]) != want {
		return errors.New("tarball does not match the lock file's integrity digest")
	}
	return nil
}

// tarLicenses reads the license files at the package root (package/) of
// an npm tarball.
func tarLicenses(tgz []byte) ([]licenseFile, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	var out []licenseFile
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		dir, base := path.Split(h.Name)
		if h.Typeflag != tar.TypeReg || strings.Count(strings.Trim(dir, "/"), "/") != 0 || dir == "" || !licenseName.MatchString(base) {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return nil, err
		}
		out = append(out, licenseFile{Name: base, Text: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func renderNotices(comps []component) string {
	var b strings.Builder
	b.WriteString("Secure MCP Gateway: third-party license notices\n\n")
	b.WriteString("The release binaries link the Go modules below, and smcpd embeds the npm packages\n")
	b.WriteString("below as the built console. Each component's license and notice files follow,\n")
	b.WriteString("unchanged. The Gateway's own license is LICENSE in this archive.\n\n")
	b.WriteString("Components:\n\n")
	for _, c := range comps {
		names := []string{}
		for _, f := range c.Files {
			names = append(names, f.Name)
		}
		ids, _ := c.licenses()
		fmt.Fprintf(&b, "  %-4s %s %s: %s (%s)\n", c.Kind, c.Name, c.Version, strings.Join(ids, " AND "), strings.Join(names, ", "))
	}
	for _, c := range comps {
		for _, f := range c.Files {
			fmt.Fprintf(&b, "\n%s\n%s %s %s: %s\n%s\n\n", strings.Repeat("=", 78), c.Kind, c.Name, c.Version, f.Name, strings.Repeat("=", 78))
			b.WriteString(strings.TrimRight(f.Text, "\n"))
			b.WriteString("\n")
		}
	}
	return b.String()
}

func goToolchain(gomod string) (string, error) {
	b, err := os.ReadFile(gomod)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "toolchain "); ok {
			return v, nil
		}
	}
	return "", nil
}

func renderBuildInfo(version, commit, toolchain string) string {
	var b strings.Builder
	b.WriteString("Secure MCP Gateway: build information\n\n")
	fmt.Fprintf(&b, "Version:        %s\n", version)
	fmt.Fprintf(&b, "Source commit:  %s\n", commit)
	b.WriteString("Repository:     https://github.com/ethan03805/Secure-MCP-Gateway\n")
	fmt.Fprintf(&b, "Go toolchain:   %s (CGO_ENABLED=0, -trimpath)\n\n", toolchain)
	b.WriteString("Each binary also records the commit: go version -m <binary> shows vcs.revision.\n")
	b.WriteString("Artifact digests are in smcp_<version>_checksums.txt beside the archives, signed\n")
	b.WriteString("with the release minisign key and a Sigstore bundle.\n\n")
	b.WriteString("Build recipe (in source/ in this archive):\n\n")
	b.WriteString("  .goreleaser.yaml                GoReleaser configuration: builds, archives, SBOM, signing\n")
	b.WriteString("  release.yml                     the GitHub Actions release workflow that runs GoReleaser\n")
	b.WriteString("  scripts/release-sbom.sh         writes sbom.spdx.json\n\n")
	b.WriteString("Dependency lock files (in source/):\n\n")
	b.WriteString("  go.mod, go.sum                  Go modules\n")
	b.WriteString("  console/package.json,\n")
	b.WriteString("  console/package-lock.json       npm packages of the embedded console\n\n")
	b.WriteString("To rebuild: check out the source commit and run\n\n")
	b.WriteString("  GORELEASER_CURRENT_TAG=v" + strings.TrimPrefix(version, "v") + " goreleaser release --snapshot --clean --skip=sign\n\n")
	b.WriteString("License notices: LICENSE (the Gateway) and THIRD_PARTY_NOTICES.txt (dependencies).\n")
	b.WriteString("SBOM: sbom.spdx.json (SPDX 2.3).\n")
	return b.String()
}
