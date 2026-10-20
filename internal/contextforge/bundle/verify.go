package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// ReasonUnverified: the local image's digest, signature or SBOM attestation
// does not match the release lock (FR-22.19).
const ReasonUnverified = "CONTEXTFORGE_UNVERIFIED"

// Verification is the record of a successful image verification, kept in
// <state>/contextforge/verified.json so that the network check of the
// signature runs before the first start and after a change of image only
// (FR-22.19). The source-to-image binding it carries is journaled at each
// start after a change of image (SR-3.2-2).
type Verification struct {
	Version        string `json:"version"`
	SourceTag      string `json:"source_tag"`
	SourceCommit   string `json:"source_commit"`
	Workflow       string `json:"workflow"`
	Issuer         string `json:"issuer"`
	IndexDigest    string `json:"index_digest"`
	Platform       string `json:"platform"`
	PlatformDigest string `json:"platform_digest"`
	// WheelPlatform is the wheel set's platform of the managed-process
	// form, whose PlatformDigest is the wheel-set digest (FR-22.20).
	WheelPlatform string    `json:"wheel_platform,omitempty"`
	SBOM          string    `json:"sbom"`
	VerifiedAt    time.Time `json:"verified_at"`
}

// Verifier checks the bundled image against the release lock: cosign's
// keyless signature and SPDX SBOM attestation for the lock's signer
// identity on the image index, then the engine's local copy of the
// platform image by digest.
type Verifier struct {
	Cosign string
	Engine Engine
	// exec runs a command and returns its combined output; tests replace
	// it.
	exec func(ctx context.Context, name string, args ...string) (string, error)
}

func (v *Verifier) run(ctx context.Context, name string, args ...string) (string, error) {
	if v.exec != nil {
		return v.exec(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: configured cosign or engine binary; arguments from the release lock
	out, err := cmd.CombinedOutput()
	if len(out) > 8<<10 { // an attestation payload is large; keep the head
		out = out[:8<<10]
	}
	return strings.TrimSpace(string(out)), err
}

// Verify verifies the release lock's image for platform and returns the
// verification record.
func (v *Verifier) Verify(ctx context.Context, r *contextforge.LockedRelease, platform string, now time.Time) (*Verification, error) {
	fail := func(format string, args ...any) (*Verification, error) {
		return nil, packaging.Errf(ReasonUnverified, format, args...)
	}
	pd := r.Image.Platforms[platform]
	if pd == "" {
		return fail("the release lock pins no image for %s", platform)
	}
	if v.Cosign == "" {
		return fail("cosign is not installed; it verifies the image signature (FR-22.19)")
	}
	index := r.Image.Reference + "@" + r.Image.IndexDigest
	ident := []string{"--certificate-identity", r.Signer.Subject, "--certificate-oidc-issuer", r.Signer.Issuer}
	if out, err := v.run(ctx, v.Cosign, append(append([]string{"verify"}, ident...), index)...); err != nil {
		return fail("signature of %s does not verify for %s: %v: %s", index, r.Signer.Subject, err, firstLine(out))
	}
	if out, err := v.run(ctx, v.Cosign, append(append([]string{"verify-attestation", "--type", "spdxjson"}, ident...), index)...); err != nil {
		return fail("SPDX SBOM attestation of %s does not verify for %s: %v: %s", index, r.Signer.Subject, err, firstLine(out))
	}
	img := r.Image.Reference + "@" + pd
	if out, err := v.run(ctx, v.Engine.Path, "pull", img); err != nil {
		return fail("pull %s: %v: %s", img, err, firstLine(out))
	}
	out, err := v.run(ctx, v.Engine.Path, "image", "inspect", "--format", "{{json .RepoDigests}}", img)
	if err != nil {
		return fail("inspect %s: %v: %s", img, err, firstLine(out))
	}
	var digests []string
	_ = json.Unmarshal([]byte(out), &digests)
	found := false
	for _, d := range digests {
		if strings.HasSuffix(d, "@"+pd) && strings.HasPrefix(d, strings.TrimPrefix(r.Image.Reference, "docker.io/")) {
			found = true
		}
	}
	if !found {
		return fail("the local image does not carry the pinned digest %s (found %v)", pd, digests)
	}
	wf, _, _ := strings.Cut(strings.TrimPrefix(r.Signer.Subject, r.Source.Repository+"/"), "@")
	return &Verification{Version: r.Version, SourceTag: r.Source.Tag, SourceCommit: r.Source.Commit, Workflow: wf, Issuer: r.Signer.Issuer,
		IndexDigest: r.Image.IndexDigest, Platform: platform, PlatformDigest: pd, SBOM: "spdxjson", VerifiedAt: now.UTC()}, nil
}

// LocalDigestOK checks, without the network, that the engine's local
// image still carries the verified digest.
func (v *Verifier) LocalDigestOK(ctx context.Context, ver *Verification, reference string) error {
	img := reference + "@" + ver.PlatformDigest
	if out, err := v.run(ctx, v.Engine.Path, "image", "inspect", "--format", "{{.Id}}", img); err != nil {
		return packaging.Errf(ReasonUnverified, "the verified image %s is not present: %s", img, firstLine(out))
	}
	return nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// LoadVerification reads the verification record in dir ("" when none).
func LoadVerification(dir string) (*Verification, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "verified.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v Verification
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("verified.json: %w", err)
	}
	return &v, nil
}

// Save writes the verification record into dir.
func (v *Verification) Save(dir string) error {
	return packaging.WriteJSON(filepath.Join(dir, "verified.json"), v, 0o600)
}

// Matches reports whether the record verified the lock's image for
// platform, or, for the managed-process form, its wheel set.
func (v *Verification) Matches(r *contextforge.LockedRelease, platform string) bool {
	if v != nil && platform == ManagedPlatform {
		return v.Platform == platform && v.Version == r.Version && v.WheelPlatform != "" &&
			v.PlatformDigest == r.WheelSetDigest(v.WheelPlatform) && v.Issuer == r.Signer.Issuer
	}
	return v != nil && v.Version == r.Version && v.IndexDigest == r.Image.IndexDigest && v.Platform == platform &&
		v.PlatformDigest == r.Image.Platforms[platform] && v.Issuer == r.Signer.Issuer
}
