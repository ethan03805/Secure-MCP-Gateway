package bundle

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// fakeTools answers cosign and the engine as a registry holding the image
// signed by signer would.
func fakeTools(signer, localDigest string) func(context.Context, string, ...string) (string, error) {
	return func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == "cosign":
			if !strings.Contains(joined, "--certificate-identity "+signer+" ") {
				return "Error: no matching signatures: none of the expected identities matched", errors.New("exit status 1")
			}
			return "Verification for ... The cosign claims were validated", nil
		case args[0] == "pull":
			return "pulled", nil
		case args[0] == "image" && strings.Contains(joined, "RepoDigests"):
			return `["ghcr.io/ibm/mcp-context-forge@` + localDigest + `"]`, nil
		case args[0] == "image":
			if strings.HasSuffix(joined, localDigest) {
				return "sha256:id", nil
			}
			return "Error: No such image", errors.New("exit status 1")
		}
		return "", errors.New("unexpected " + name + " " + joined)
	}
}

// FR-22.19 and SR-3.2-2 (part): only the pinned image signed by the lock's
// workflow at its tag verifies; another signer identity or a local image
// with another digest is refused with CONTEXTFORGE_UNVERIFIED. The record
// names the tag, workflow and digests.
func TestVerifier(t *testing.T) {
	reqtest.Partial(t, "FR-22.19", "SR-3.2-2")
	r := contextforge.ReleaseLock().ContextForge
	pd := r.Image.Platforms["linux/arm64"]
	ok := &Verifier{Cosign: "cosign", Engine: Engine{Path: "docker"}, exec: fakeTools(r.Signer.Subject, pd)}
	ver, err := ok.Verify(context.Background(), &r, "linux/arm64", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ver.SourceTag != "v1.0.11" || ver.Workflow != ".github/workflows/docker-multiplatform.yml" || ver.PlatformDigest != pd || !ver.Matches(&r, "linux/arm64") {
		t.Fatalf("record %+v", ver)
	}
	dir := t.TempDir()
	if err := ver.Save(dir); err != nil {
		t.Fatal(err)
	}
	back, err := LoadVerification(dir)
	if err != nil || !back.Matches(&r, "linux/arm64") || back.Matches(&r, "linux/amd64") {
		t.Fatalf("saved record %+v %v", back, err)
	}
	cases := map[string]*Verifier{
		"another workflow":  {Cosign: "cosign", Engine: Engine{Path: "docker"}, exec: fakeTools("https://github.com/evil/fork/.github/workflows/x.yml@refs/tags/v1.0.11", pd)},
		"another digest":    {Cosign: "cosign", Engine: Engine{Path: "docker"}, exec: fakeTools(r.Signer.Subject, "sha256:"+strings.Repeat("0", 64))},
		"no cosign":         {Engine: Engine{Path: "docker"}, exec: fakeTools(r.Signer.Subject, pd)},
		"unpinned platform": nil,
	}
	for name, v := range cases {
		var err error
		if v == nil {
			_, err = ok.Verify(context.Background(), &r, "linux/s390x", time.Now())
		} else {
			_, err = v.Verify(context.Background(), &r, "linux/arm64", time.Now())
		}
		if packaging.ReasonOf(err) != ReasonUnverified {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ok.LocalDigestOK(context.Background(), ver, r.Image.Reference); err != nil {
		t.Fatal(err)
	}
	gone := &Verifier{Engine: Engine{Path: "docker"}, exec: fakeTools(r.Signer.Subject, "sha256:"+strings.Repeat("1", 64))}
	if err := gone.LocalDigestOK(context.Background(), ver, r.Image.Reference); packaging.ReasonOf(err) != ReasonUnverified {
		t.Fatalf("missing local image: %v", err)
	}
}

// TestVerifierNetwork verifies the real pinned image with cosign (network;
// SMCP_CONTEXTFORGE_IMAGE=1).
func TestVerifierNetwork(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to verify the pinned image over the network")
	}
	reqtest.Partial(t, "FR-22.19", "SR-3.2-2")
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign not installed")
	}
	eng, err := FindEngine()
	if err != nil {
		t.Skip(err)
	}
	r := contextforge.ReleaseLock().ContextForge
	v := &Verifier{Cosign: cosign, Engine: eng}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := v.Verify(ctx, &r, "linux/"+runtime.GOARCH, time.Now()); err != nil {
		t.Fatal(err)
	}
	bad := r
	bad.Signer.Subject = "https://github.com/IBM/mcp-context-forge/.github/workflows/docker-multiplatform.yml@refs/tags/v1.0.10"
	if _, err := v.Verify(ctx, &bad, "linux/"+runtime.GOARCH, time.Now()); packaging.ReasonOf(err) != ReasonUnverified {
		t.Fatalf("signature from another tag accepted: %v", err)
	}
}
