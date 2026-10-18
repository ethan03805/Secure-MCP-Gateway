package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const mitText = `MIT License

Copyright (c) 2026 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.`

const bsd3Text = `Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   * Neither the name of Google Inc. nor the names of its contributors may be
used to endorse or promote products derived from this software.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"`

func tgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sri(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

func TestClassify(t *testing.T) {
	for text, want := range map[string]string{
		mitText:  "MIT",
		bsd3Text: "BSD-3-Clause",
		"Apache License\n  Version 2.0, January 2004":                                                                               "Apache-2.0",
		"SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007":                                                                      "OFL-1.1",
		"Redistribution and use in source and binary forms ... THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS": "BSD-2-Clause",
		"All rights reserved. You may not redistribute this software.":                                                              "",
		"Creative Commons Attribution 4.0 International":                                                                            "",
	} {
		if got := strings.Join(classify(text), " "); got != want {
			t.Errorf("classify(%.40q) = %q, want %q", text, got, want)
		}
	}
	// A component needs a recognized license file; PATENTS alone is not one,
	// and an unrecognized license file is refused even beside a known one.
	for _, c := range []struct {
		files []licenseFile
		ok    bool
	}{
		{[]licenseFile{{"LICENSE", bsd3Text}, {"PATENTS", "Additional IP Rights Grant (Patents)"}}, true},
		{[]licenseFile{{"PATENTS", "Additional IP Rights Grant (Patents)"}}, false},
		{[]licenseFile{{"LICENSE", mitText}, {"LICENSE-DOCS", "Creative Commons Attribution 4.0"}}, false},
	} {
		if _, err := (component{Kind: "go", Name: "x", Version: "v1", Files: c.files}).licenses(); (err == nil) != c.ok {
			t.Errorf("%v: err %v", c.files, err)
		}
	}
}

// TestNPMPackages: only the lock file's non-dev packages are fetched; each
// tarball is checked against the lock file's integrity digest, and the
// license files of the package root are kept.
func TestNPMPackages(t *testing.T) {
	good := tgz(t, map[string]string{"package/LICENSE": mitText, "package/index.js": "x", "package/sub/LICENSE": "nested, ignored"})
	bare := tgz(t, map[string]string{"package/index.js": "x"})
	mux := http.NewServeMux()
	mux.HandleFunc("/good.tgz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(good) })
	mux.HandleFunc("/bare.tgz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bare) })
	mux.HandleFunc("/dev.tgz", func(w http.ResponseWriter, _ *http.Request) { t.Error("dev package fetched") })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	write := func(pkgs map[string]any) string {
		p := filepath.Join(t.TempDir(), "package-lock.json")
		b, _ := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": pkgs})
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	lock := write(map[string]any{
		"":                              map[string]any{"name": "console"},
		"node_modules/react":            map[string]any{"version": "1.0.0", "resolved": srv.URL + "/good.tgz", "integrity": sri(good), "license": "MIT"},
		"node_modules/a/node_modules/b": map[string]any{"version": "2.0.0", "resolved": srv.URL + "/good.tgz", "integrity": sri(good)},
		"node_modules/vite":             map[string]any{"version": "9.0.0", "resolved": srv.URL + "/dev.tgz", "dev": true},
	})
	comps, err := npmPackages(lock, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 2 || comps[0].Name != "b" || comps[1].Name != "react" || len(comps[1].Files) != 1 || comps[1].Files[0].Text != mitText {
		t.Fatalf("components %+v", comps)
	}
	if _, err := npmPackages(write(map[string]any{"node_modules/react": map[string]any{"version": "1.0.0", "resolved": srv.URL + "/good.tgz", "integrity": sri(bare)}}), srv.Client()); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("tampered tarball: %v", err)
	}
	if _, err := npmPackages(write(map[string]any{"node_modules/x": map[string]any{"version": "1.0.0", "resolved": srv.URL + "/bare.tgz", "integrity": sri(bare)}}), srv.Client()); err == nil || !strings.Contains(err.Error(), "no license file") {
		t.Fatalf("package without a license: %v", err)
	}
}

// TestGoModulesLicensed runs the Go half against this repository: every
// module linked into a release binary, and the standard library, has a
// license file recognized as OSI-approved (FR-12.1 for the Go
// dependencies). The npm half needs the network and runs at release.
func TestGoModulesLicensed(t *testing.T) {
	reqtest.Partial(t, "FR-12.1")
	// Partial: the Go modules of the release builds are checked here; the
	// console's npm packages are checked by the same code at release (the
	// before hook in .goreleaser.yaml), and the SBOM license fields of a
	// release are inspected in a record.
	if testing.Short() {
		t.Skip("runs go list twice")
	}
	comps, err := goModules(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range comps {
		names[c.Name] = true
		if _, err := c.licenses(); err != nil {
			t.Error(err)
		}
	}
	for _, want := range []string{"std (Go standard library and runtime)", "github.com/modelcontextprotocol/go-sdk", "golang.org/x/crypto", "github.com/google/nftables"} {
		if !names[want] {
			t.Errorf("%s not among the linked modules", want)
		}
	}
	if names["github.com/duckdb/duckdb-go/v2"] {
		t.Error("duckdb is not linked with CGO_ENABLED=0 but was listed")
	}
	out := renderNotices(comps)
	if !strings.Contains(out, "golang.org/x/crypto") || !strings.Contains(out, "BSD-3-Clause") {
		t.Fatal("notices text")
	}
}

// TestReleaseArchiveProvenance: the GoReleaser configuration generates the
// notices and build information before the build and puts them, the build
// recipe and the dependency lock files into every archive (FR-12.8).
func TestReleaseArchiveProvenance(t *testing.T) {
	reqtest.Partial(t, "FR-12.8")
	// Partial: the configuration is checked here and a one-target snapshot
	// archive was listed by hand; the Inspection of a published release
	// bundle is a record made after the next release.
	b, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(b)
	for _, want := range []string{
		"go run ./tools/notices -version {{ .Version }} -commit {{ .FullCommit }} -out build/notices",
		"- src: build/notices/*.txt",
		"dst: source/.goreleaser.yaml", "dst: source/go.mod", "dst: source/go.sum",
		"- src: console/package*.json\n        dst: source/console",
		"- src: .github/workflows/release.yml\n        dst: source",
		"- src: scripts/release-sbom.sh\n        dst: source/scripts",
		"- src: build/sbom/*.spdx.json", "- src: LICENSE*",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf(".goreleaser.yaml lacks %q", want)
		}
	}
	info := renderBuildInfo("1.1.0", "0123456789abcdef0123456789abcdef01234567", "go1.26.9")
	for _, want := range []string{"Source commit:  0123456789abcdef0123456789abcdef01234567", "source/", "go.sum", "package-lock.json", ".goreleaser.yaml", "THIRD_PARTY_NOTICES.txt", "checksums.txt"} {
		if !strings.Contains(info, want) {
			t.Errorf("BUILDINFO lacks %q", want)
		}
	}
	sbom, err := os.ReadFile(filepath.Join("..", "..", "scripts", "release-sbom.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sbom), "SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true") {
		t.Error("release-sbom.sh does not fill Go license fields")
	}
}
