package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// TestVerifierNetwork verifies real images with cosign and the engine
// (network; SMCP_CONTEXTFORGE_IMAGE=1; the contextforge job), FR-22.19 and
// SR-3.2-2: the pinned image verifies, its record names the source tag,
// the workflow and the digests that the image_verified binding event
// carries, and it starts and answers /health; refused with
// CONTEXTFORGE_UNVERIFIED are the ContextForge image of another tag
// (v1.0.10, signed by the same workflow at refs/tags/v1.0.10), an image
// signed by another repository's workflow (aquasecurity/trivy 0.56.2,
// keyless-signed by its release workflow, which the test confirms), a
// signature identity of another workflow of the ContextForge repository,
// a platform digest that differs from the image, and the pinned image
// pushed unsigned to a local registry.
func TestVerifierNetwork(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_IMAGE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_IMAGE=1 to verify the pinned image over the network")
	}
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign not installed")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not installed")
	}
	eng := Engine{Path: docker}
	r := contextforge.ReleaseLock().ContextForge
	plat := "linux/" + runtime.GOARCH
	v := &Verifier{Cosign: cosign, Engine: eng}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	ver, err := v.Verify(ctx, &r, plat, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ver.SourceTag != r.Source.Tag || ver.SourceCommit != r.Source.Commit || ver.Workflow != ".github/workflows/docker-multiplatform.yml" ||
		ver.IndexDigest != r.Image.IndexDigest || ver.PlatformDigest != r.Image.Platforms[plat] || ver.SBOM != "spdxjson" {
		t.Fatalf("binding record %+v", ver)
	}
	refused := func(name string, l contextforge.LockedRelease) {
		t.Helper()
		if _, err := v.Verify(ctx, &l, plat, time.Now()); packaging.ReasonOf(err) != ReasonUnverified {
			t.Errorf("%s: %v", name, err)
		} else {
			t.Logf("%s refused: %s", name, firstLine(err.Error()))
		}
	}
	// The image of another tag, signed by the same workflow at that tag.
	otherTag := r
	otherTag.Image.IndexDigest = "sha256:31cf1d45ab56d83fc109ac0de1ada7b359df2497a52765af73421f013fa76b4d" // v1.0.10
	otherTag.Image.Platforms = map[string]string{"linux/amd64": "sha256:fb3c1b89e8f934b4975c17edf4b28b605b3ccf1f8830e4c6953d54757fb46a1e",
		"linux/arm64": "sha256:98dfab27a38b8aa1c1d3bc02c1e911d5a3dfc230559fea22ccdffad2cfd58b6a"}
	refused("the image of tag v1.0.10", otherTag)
	// An image signed by another repository's release workflow.
	trivy, err := ghcrDigest(ctx, "aquasecurity/trivy", "0.56.2")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(ctx, cosign, "verify", "--certificate-identity-regexp", "^https://github.com/aquasecurity/trivy/",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", "ghcr.io/aquasecurity/trivy@"+trivy).CombinedOutput(); err != nil {
		t.Fatalf("the other repository's image is not keyless-signed by its workflow: %v %s", err, firstLine(string(out)))
	}
	otherRepo := r
	otherRepo.Image.Reference, otherRepo.Image.IndexDigest = "ghcr.io/aquasecurity/trivy", trivy
	refused("an image signed by aquasecurity/trivy", otherRepo)
	// Another workflow identity of the ContextForge repository.
	otherWF := r
	otherWF.Signer.Subject = r.Source.Repository + "/.github/workflows/release.yml@refs/tags/" + r.Version
	refused("another workflow identity", otherWF)
	// A platform digest that is not the image's.
	otherDigest := r
	otherDigest.Image.Platforms = map[string]string{plat: "sha256:" + strings.Repeat("0", 64)}
	refused("another platform digest", otherDigest)
	// The pinned image, unsigned, in a local registry.
	out, err := exec.CommandContext(ctx, docker, "run", "-d", "--rm", "-p", "127.0.0.1::5000", "--label", "smcp.component=contextforge", "registry:2").CombinedOutput()
	if err != nil {
		t.Fatalf("local registry: %v %s", err, out)
	}
	reg := lastLine(string(out))
	t.Cleanup(func() { _ = exec.Command(docker, "rm", "-f", reg).Run() })
	pout, err := exec.CommandContext(ctx, docker, "port", reg, "5000/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("registry port: %v %s", err, pout)
	}
	hostPort := strings.TrimSpace(strings.Split(strings.TrimSpace(string(pout)), "\n")[0])
	local := strings.Replace(hostPort, "127.0.0.1", "localhost", 1) + "/mcp-context-forge"
	if out, err := exec.CommandContext(ctx, docker, "tag", r.ImageRef(plat), local+":"+r.Version).CombinedOutput(); err != nil {
		t.Fatalf("tag: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(docker, "rmi", local+":"+r.Version).Run() })
	var pushed string
	for range 3 {
		pctx, pcancel := context.WithTimeout(ctx, 3*time.Minute)
		out, err := exec.CommandContext(pctx, docker, "push", local+":"+r.Version).CombinedOutput()
		pcancel()
		if err == nil {
			for _, f := range strings.Fields(string(out)) {
				if strings.HasPrefix(f, "sha256:") && len(f) == 71 {
					pushed = f
				}
			}
			break
		}
		t.Logf("push: %v %s", err, lastLine(string(out)))
		time.Sleep(time.Second)
	}
	if pushed == "" {
		t.Fatal("pushing the pinned image to the local registry gave no digest")
	}
	t.Logf("pinned %s pushed unsigned as %s@%s", r.Image.Platforms[plat], local, pushed)
	unsigned := r
	unsigned.Image.Reference, unsigned.Image.IndexDigest = local, pushed
	unsigned.Image.Platforms = map[string]string{plat: pushed}
	refused("the pinned image unsigned in a local registry", unsigned)

	// Only the pinned image starts.
	creds, _ := NewCredentials()
	in, err := New(Options{Engine: eng, Image: r.ImageRef(plat), Name: "smcp-cf-test-verified",
		Settings:    Settings{Limits: Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}},
		Credentials: func() (Credentials, error) { return creds, nil }, HealthWait: 120 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Stop(context.Background()); _ = in.RemoveVolume(context.Background()) })
	if err := in.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for !in.Healthy() {
		if time.Now().After(deadline) {
			t.Fatalf("the verified image did not become healthy: %+v", in.Status())
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !t.Failed() {
		reqtest.Verifies(t, "FR-22.19", "SR-3.2-2")
	}
}

// ghcrDigest resolves a tag of a public ghcr.io repository to its manifest
// (index) digest.
func ghcrDigest(ctx context.Context, repo, tag string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ghcr.io/token?scope=repository:"+repo+":pull", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	var tok struct {
		Token string `json:"token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodHead, "https://ghcr.io/v2/"+repo+"/manifests/"+tag, nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	d := resp.Header.Get("Docker-Content-Digest")
	if !strings.HasPrefix(d, "sha256:") {
		return "", fmt.Errorf("%s:%s: no digest (HTTP %d)", repo, tag, resp.StatusCode)
	}
	return d, nil
}
