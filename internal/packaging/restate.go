package packaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Restate applies mutate to the provenance statement of an unsigned
// package directory written by Build, then rewrites the statement, the
// manifest's statement digest and the index's manifest and provenance
// references so the package stays consistent. A signed package is refused:
// its signature covers the index. The ContextForge Connector uses it to add
// the catalog origin and the operator's trust decision before signing
// (FR-22.11, FR-22.12).
func Restate(dir string, mutate func(*Provenance) error) error {
	if _, err := os.Stat(filepath.Join(dir, SignatureFile)); err == nil {
		return errors.New("restate: the package is already signed")
	}
	ixPath := filepath.Join(dir, IndexFile)
	raw, err := os.ReadFile(ixPath)
	if err != nil {
		return Wrap(ReasonIndexMissing, "package index", err)
	}
	var ix Index
	if err := decodeStrict(raw, &ix); err != nil {
		return Wrap(ReasonIndexInvalid, "package index", err)
	}
	for _, p := range []string{ix.Manifest.Path, ix.Provenance.Path} {
		if err := safeRel(p); err != nil {
			return Wrap(ReasonIndexInvalid, "package index", err)
		}
	}
	provPath := filepath.Join(dir, filepath.FromSlash(ix.Provenance.Path))
	raw, err = os.ReadFile(provPath)
	if err != nil {
		return Wrap(ReasonProvenanceMissing, "provenance statement", err)
	}
	var pv Provenance
	if err := decodeStrict(raw, &pv); err != nil {
		return Wrap(ReasonProvenanceBinding, "provenance statement", err)
	}
	if err := mutate(&pv); err != nil {
		return err
	}
	if err := WriteJSON(provPath, pv, 0o644); err != nil {
		return err
	}
	provSum, provSize, err := FileSHA256(provPath)
	if err != nil {
		return err
	}
	manPath := filepath.Join(dir, filepath.FromSlash(ix.Manifest.Path))
	raw, err = os.ReadFile(manPath)
	if err != nil {
		return Wrap(ReasonManifestMissing, "manifest", err)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return err
	}
	m.Provenance.StatementSHA256 = provSum
	raw, err = json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := ParseManifest(raw); err != nil {
		return fmt.Errorf("restated manifest is not valid: %w", err)
	}
	if err := writeFileAtomic(manPath, raw, 0o644); err != nil {
		return err
	}
	manSum, manSize, err := FileSHA256(manPath)
	if err != nil {
		return err
	}
	ix.Manifest.SHA256, ix.Manifest.Size = manSum, manSize
	ix.Provenance.SHA256, ix.Provenance.Size = provSum, provSize
	return WriteJSON(ixPath, ix, 0o644)
}
