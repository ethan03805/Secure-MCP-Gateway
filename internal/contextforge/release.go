package contextforge

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// Reason codes of the ContextForge Connector (E-36). They are documented in
// docs/troubleshooting.md.
const (
	// ReasonCatalogDigestMismatch: a catalog file's SHA-256 differs from the
	// release lock, or an operator-supplied file has no confirmed digest or
	// a different one (FR-22.1).
	ReasonCatalogDigestMismatch = "CATALOG_DIGEST_MISMATCH"
	// ReasonCatalogInvalid: a catalog file breaks a parsing bound or rule
	// (FR-22.2).
	ReasonCatalogInvalid = "CATALOG_INVALID"
	// ReasonLockInvalid: the release lock is malformed (FR-22.18).
	ReasonLockInvalid = "CONTEXTFORGE_LOCK_INVALID"
	// ReasonToolNameCollision: two tools of a hosted package map to the
	// same manifest name (FR-22.10).
	ReasonToolNameCollision = "TOOL_NAME_COLLISION"
	// ReasonContextForgeDisabled: a hosted import or enablement while
	// [contextforge] bundled is false (FR-22.22).
	ReasonContextForgeDisabled = "CONTEXTFORGE_DISABLED"
)

// The release lock and the catalog file of the pinned ContextForge
// release are compiled into the Gateway, so the pinned catalog is read
// without any network access (FR-22.1). release/contextforge.lock.json is
// a copy of packaging/contextforge.lock.json; a test keeps the two equal.
var (
	//go:embed release/contextforge.lock.json
	lockJSON []byte
	//go:embed release/mcp-catalog-v1.0.11.yml
	pinnedCatalogYAML []byte
)

// Lock is the ContextForge release lock of a Gateway release
// (packaging/contextforge.lock.json, FR-22.18).
type Lock struct {
	LockVersion  int           `json:"lock_version"`
	ContextForge LockedRelease `json:"contextforge"`
}

// LockedRelease is the one pinned ContextForge release.
type LockedRelease struct {
	Version  string       `json:"version"`
	Released string       `json:"released"`
	License  string       `json:"license"`
	Source   LockedSource `json:"source"`
	Image    LockedImage  `json:"image"`
	Signer   LockedSigner `json:"signer"`
	// Python is the CPython minor version the wheel set is built for.
	Python string `json:"python"`
	// Wheels is the wheel set of the managed-process form for each
	// platform (FR-22.18, FR-22.20): every wheel that installs the pinned
	// release, with its SHA-256 and PyPI URL.
	Wheels     map[string][]LockedFile `json:"wheels"`
	Catalog    LockedCatalog           `json:"catalog"`
	StarterSet []string                `json:"starter_set"`
}

// LockedSource is the source tag and commit the image was built from.
type LockedSource struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Commit     string `json:"commit"`
}

// LockedImage pins the OCI image by index and per-platform digest.
type LockedImage struct {
	Reference   string            `json:"reference"`
	IndexDigest string            `json:"index_digest"`
	Platforms   map[string]string `json:"platforms"`
}

// LockedSigner is the expected cosign keyless signer identity.
type LockedSigner struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// LockedFile is one wheel of the managed-process form.
type LockedFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

// WheelPlatforms are the platforms whose wheel set every release lock
// pins (FR-22.20). Windows on arm64 runs the windows/amd64 set under an
// x64 interpreter: four of the dependencies publish no win_arm64 wheel.
var WheelPlatforms = []string{"darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64"}

// LockedCatalog pins the catalog file of the release.
type LockedCatalog struct {
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
	Entries int    `json:"entries"`
}

var (
	ociDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex40     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	semverTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	wheelName = regexp.MustCompile(`^[A-Za-z0-9_.+-]+\.whl$`)
)

// ParseLock decodes and checks a release lock: every digest is a full
// SHA-256, the version is an exact tag equal to the source tag, the signer
// subject names the source repository's workflow at that tag, and both
// Linux platforms are pinned.
func ParseLock(raw []byte) (*Lock, error) {
	var l Lock
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, packaging.Wrap(ReasonLockInvalid, "release lock is not valid JSON", err)
	}
	bad := func(format string, args ...any) error {
		return packaging.Errf(ReasonLockInvalid, "release lock: "+format, args...)
	}
	r := l.ContextForge
	switch {
	case l.LockVersion != 1:
		return nil, bad("lock_version %d is not supported", l.LockVersion)
	case !semverTag.MatchString(r.Version):
		return nil, bad("version %q is not an exact release tag", r.Version)
	case r.Source.Tag != r.Version:
		return nil, bad("source tag %q differs from version %q", r.Source.Tag, r.Version)
	case !hex40.MatchString(r.Source.Commit):
		return nil, bad("source commit %q is not a full commit ID", r.Source.Commit)
	case !strings.HasPrefix(r.Source.Repository, "https://github.com/"):
		return nil, bad("source repository %q is not a GitHub https URL", r.Source.Repository)
	case r.License == "":
		return nil, bad("license is missing")
	case !ociDigest.MatchString(r.Image.IndexDigest):
		return nil, bad("image index digest %q is not a sha256 digest", r.Image.IndexDigest)
	case !hex64.MatchString(r.Catalog.SHA256):
		return nil, bad("catalog sha256 %q is not a SHA-256", r.Catalog.SHA256)
	case r.Signer.Issuer != "https://token.actions.githubusercontent.com":
		return nil, bad("signer issuer %q is not the GitHub Actions issuer", r.Signer.Issuer)
	case !strings.HasPrefix(r.Signer.Subject, r.Source.Repository+"/.github/workflows/") ||
		!strings.HasSuffix(r.Signer.Subject, "@refs/tags/"+r.Version):
		return nil, bad("signer subject %q does not name a workflow of %s at tag %s", r.Signer.Subject, r.Source.Repository, r.Version)
	}
	for _, p := range []string{"linux/amd64", "linux/arm64"} {
		if !ociDigest.MatchString(r.Image.Platforms[p]) {
			return nil, bad("image digest for %s is missing or not a sha256 digest", p)
		}
	}
	for p, d := range r.Image.Platforms {
		if !ociDigest.MatchString(d) {
			return nil, bad("image digest for %s is not a sha256 digest", p)
		}
	}
	if r.Python != "3.12" {
		return nil, bad("python %q is not the supported CPython version 3.12", r.Python)
	}
	if len(r.Wheels) != len(WheelPlatforms) {
		return nil, bad("the wheel set must list exactly the platforms %v", WheelPlatforms)
	}
	own := "mcp_contextforge_gateway-" + strings.TrimPrefix(r.Version, "v") + "-"
	for _, p := range WheelPlatforms {
		set, ok := r.Wheels[p]
		if !ok || len(set) == 0 {
			return nil, bad("the wheel set for %s is missing", p)
		}
		seen, owns := map[string]bool{}, 0
		for _, w := range set {
			if !wheelName.MatchString(w.File) || !hex64.MatchString(w.SHA256) || seen[w.File] ||
				!strings.HasPrefix(w.URL, "https://files.pythonhosted.org/") || !strings.HasSuffix(w.URL, "/"+w.File) {
				return nil, bad("wheel %q of %s is malformed or listed twice", w.File, p)
			}
			seen[w.File] = true
			if strings.HasPrefix(w.File, own) {
				owns++
			}
		}
		if owns != 1 {
			return nil, bad("the wheel set for %s holds %d wheels of ContextForge %s", p, owns, r.Version)
		}
	}
	if !slices.IsSorted(r.StarterSet) || len(slices.Compact(slices.Clone(r.StarterSet))) != len(r.StarterSet) {
		return nil, bad("starter_set must be sorted and without duplicates")
	}
	return &l, nil
}

// ReleaseLock returns the release lock compiled into this Gateway.
func ReleaseLock() *Lock {
	l, err := ParseLock(lockJSON)
	if err != nil {
		panic("embedded ContextForge release lock: " + err.Error())
	}
	return l
}

// ReleaseLockJSON returns the raw release lock compiled into this Gateway.
func ReleaseLockJSON() []byte { return append([]byte(nil), lockJSON...) }

// ImageRef is the digest-pinned image reference for a platform, for
// example ghcr.io/ibm/mcp-context-forge@sha256:... ("" when the platform
// is not pinned).
func (r *LockedRelease) ImageRef(platform string) string {
	d := r.Image.Platforms[platform]
	if d == "" {
		return ""
	}
	return r.Image.Reference + "@" + d
}

// CheckStarterSet confirms that every starter-set entry is in the catalog,
// is a hosted entry and has auth type Open (FR-22.17). Whether its tools
// are read-only is confirmed by its probe at import.
func (l *Lock) CheckStarterSet(c *Catalog) error {
	for _, id := range l.ContextForge.StarterSet {
		e := c.Entry(id)
		if e == nil {
			return packaging.Errf(ReasonLockInvalid, "starter-set entry %q is not in the catalog", id)
		}
		if class, _ := e.Classify(); class != ClassHosted {
			return packaging.Errf(ReasonLockInvalid, "starter-set entry %q is %s, not hosted", id, class)
		}
		if e.AuthType != "Open" {
			return packaging.Errf(ReasonLockInvalid, "starter-set entry %q has auth type %q, not Open", id, e.AuthType)
		}
	}
	return nil
}

// String names the release, for messages.
func (r *LockedRelease) String() string {
	return fmt.Sprintf("ContextForge %s (%s)", r.Version, r.Image.IndexDigest)
}

// WheelSetDigest identifies a platform's wheel set ("" when the lock pins
// none): "sha256:" and the SHA-256 of the lines "<sha256>  <file>\n" of its
// wheels sorted by file name, the form of a checksum file. It stands for
// the image digest of the managed-process form in verification records,
// provenance and evidence (FR-22.11, SR-3.8-2).
func (r *LockedRelease) WheelSetDigest(platform string) string {
	set := r.Wheels[platform]
	if len(set) == 0 {
		return ""
	}
	lines := make([]string, 0, len(set))
	for _, w := range set {
		lines = append(lines, w.SHA256+"  "+w.File+"\n")
	}
	slices.SortFunc(lines, func(a, b string) int { return strings.Compare(a[66:], b[66:]) })
	return "sha256:" + packaging.SHA256Hex([]byte(strings.Join(lines, "")))
}
