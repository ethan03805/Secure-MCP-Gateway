package packaging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriteHosted writes an unsigned hosted package (manifest_version 2,
// SRS FR-22.10) into out, which must not exist. m carries the server, the
// upstream member, the tools with their backend names, the risk class,
// capabilities and secret slots; WriteHosted fills in the artifact (the
// canonical JSON of the upstream member), the tool-list digest, the
// manifest's provenance member and the index. prov carries the probe
// environment and the ContextForge origin; its server, artifact and source
// are filled in here.
func WriteHosted(out string, m *Manifest, prov Provenance, tool, toolVersion string, now time.Time) (*Package, error) {
	if m.Upstream == nil {
		return nil, Errf(ReasonManifestSchema, "a hosted package needs its upstream member")
	}
	if err := os.Mkdir(out, 0o755); err != nil {
		return nil, fmt.Errorf("output directory: %w", err)
	}
	if err := os.Mkdir(filepath.Join(out, ArtifactDir), 0o755); err != nil {
		return nil, err
	}
	up, err := m.Upstream.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	art := filepath.Join(out, ArtifactDir, HostedArtifact)
	if err := writeFileAtomic(art, up, 0o644); err != nil {
		return nil, err
	}
	sum := SHA256Hex(up)
	m.ManifestVersion = ManifestVersionHosted
	m.Artifact = ArtifactInfo{Type: ArtifactHosted, Reference: m.Upstream.URL, Version: m.Server.Revision, SHA256: sum, SizeBytes: int64(len(up))}
	m.Launch = Launch{Runtime: ArtifactHosted, Argv: []string{}}
	m.InstanceScope = []string{"shared"}
	if m.ToolsListSHA256, err = ToolsDigest(m.CanonicalTools()); err != nil {
		return nil, err
	}
	src := Source{Kind: "hosted-endpoint", URI: m.Upstream.URL, SHA256: sum}
	licenses := prov.Licenses
	if len(licenses) == 0 {
		licenses = []string{"NOASSERTION"} // a hosted server has no inspectable code or license
	}
	prov.ProvenanceVersion, prov.ServerID, prov.Revision, prov.Artifact, prov.Source, prov.Licenses = 1, m.Server.ID, m.Server.Revision, m.Artifact, src, licenses
	prov.BuiltAt = now.UTC().Format(time.RFC3339)
	if err := WriteJSON(filepath.Join(out, ProvenanceFile), prov, 0o644); err != nil {
		return nil, err
	}
	provSum, provSize, err := FileSHA256(filepath.Join(out, ProvenanceFile))
	if err != nil {
		return nil, err
	}
	m.Provenance = ManifestProvenance{Source: src, Licenses: licenses, StatementSHA256: provSum}
	m.Packaging = PackagingInfo{Tool: tool, ToolVersion: toolVersion, BuiltAt: now.UTC().Format(time.RFC3339), OperatorNote: m.Packaging.OperatorNote}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if _, err := ParseManifest(raw); err != nil {
		return nil, fmt.Errorf("generated hosted manifest is not valid: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(out, ManifestFile), raw, 0o644); err != nil {
		return nil, err
	}
	manSum, manSize, err := FileSHA256(filepath.Join(out, ManifestFile))
	if err != nil {
		return nil, err
	}
	ix := Index{IndexVersion: IndexVersion, ServerID: m.Server.ID, Revision: m.Server.Revision, RiskClass: m.RiskClass,
		Artifact:   FileRef{Path: ArtifactDir + "/" + HostedArtifact, SHA256: sum, Size: int64(len(up))},
		Manifest:   FileRef{Path: ManifestFile, SHA256: manSum, Size: manSize},
		Provenance: FileRef{Path: ProvenanceFile, SHA256: provSum, Size: provSize},
		CreatedAt:  now.UTC().Format(time.RFC3339)}
	if err := WriteJSON(filepath.Join(out, IndexFile), ix, 0o644); err != nil {
		return nil, err
	}
	return &Package{Dir: out, Index: ix, Manifest: m, ManifestRaw: raw, Provenance: prov}, nil
}
