package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Exporter copies closed journal segments and the anchor (the checkpoint)
// to a local export directory (FR-7.14, X-09). The export directory has the
// journal's own layout, so `smcpctl journal verify --dir <export>/journal`
// verifies the copy with the anchor next to it:
//
//	<export>/journal/segment-NNNNNN.jsonl
//	<export>/journal.anchor
//	<export>/keys/<name>.pub   (the evidence public keys given in PublicKeys)
//
// Sync is idempotent: a segment already present with the same content is
// not copied again, so each closed segment, and therefore each event, is
// exported exactly once across restarts (SR-6.10-1 for the export side). A
// present copy whose content differs is reported as an error and never
// overwritten, because the export is the off-journal reference for
// tamper detection.
type Exporter struct {
	JournalDir string
	AnchorPath string // default DefaultAnchorPath(JournalDir)
	ExportDir  string
	// PublicKeys maps a file name under <export>/keys to a source path.
	PublicKeys map[string]string
}

// ExportResult reports one Sync.
type ExportResult struct {
	Copied        []string // segment files copied in this run
	AnchorSegment int      // segment named by the exported anchor; 0 when none
	AnchorUpdated bool
}

// Sync copies every closed segment up to the segment the anchor names, then
// the anchor. The anchor is read first so that the exported anchor never
// names a segment that has not been exported.
func (e *Exporter) Sync() (ExportResult, error) {
	var res ExportResult
	if e.ExportDir == "" || e.JournalDir == "" {
		return res, errors.New("export: journal and export directories are required")
	}
	anchorPath := e.AnchorPath
	if anchorPath == "" {
		anchorPath = DefaultAnchorPath(e.JournalDir)
	}
	dstJournal := filepath.Join(e.ExportDir, "journal")
	if err := os.MkdirAll(dstJournal, 0o700); err != nil {
		return res, err
	}
	for name, src := range e.PublicKeys {
		if err := os.MkdirAll(filepath.Join(e.ExportDir, "keys"), 0o700); err != nil {
			return res, err
		}
		b, err := os.ReadFile(src)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return res, err
		}
		if err := writeIfChanged(filepath.Join(e.ExportDir, "keys", filepath.Base(name)), b, 0o644); err != nil {
			return res, err
		}
	}
	anchorBytes, err := os.ReadFile(anchorPath)
	if errors.Is(err, os.ErrNotExist) {
		return res, nil // no segment has closed yet
	} else if err != nil {
		return res, err
	}
	a, err := parseAnchor(anchorPath)
	if err != nil {
		return res, err
	}
	segs, err := listSegments(e.JournalDir)
	if err != nil {
		return res, err
	}
	for _, s := range segs {
		if s.seq > a.Segment {
			break
		}
		src := filepath.Join(e.JournalDir, s.name)
		ft, err := readFooter(src)
		if err != nil {
			return res, err
		}
		if ft == nil {
			return res, fmt.Errorf("export: %s is not closed but the anchor names segment %d", s.name, a.Segment)
		}
		copied, err := copyOnce(src, filepath.Join(dstJournal, s.name))
		if err != nil {
			return res, err
		}
		if copied {
			res.Copied = append(res.Copied, s.name)
		}
	}
	res.AnchorSegment = a.Segment
	dstAnchor := DefaultAnchorPath(dstJournal)
	if cur, err := os.ReadFile(dstAnchor); err != nil || !bytes.Equal(cur, anchorBytes) {
		if err := writeFileAtomic(dstAnchor, anchorBytes, 0o600); err != nil {
			return res, err
		}
		res.AnchorUpdated = true
	}
	return res, nil
}

// copyOnce copies src to dst unless dst already holds the same bytes. It
// refuses to overwrite a different dst.
func copyOnce(src, dst string) (bool, error) {
	want, err := fileSHA256(src)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(dst); err == nil {
		have, err := fileSHA256(dst)
		if err != nil {
			return false, err
		}
		if have != want {
			return false, fmt.Errorf("export: %s differs from the journal segment; investigate before exporting again", dst)
		}
		return false, nil
	}
	in, err := os.Open(src)
	if err != nil {
		return false, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if got, err := fileSHA256(tmp.Name()); err != nil || got != want {
		return false, fmt.Errorf("export: copy of %s did not verify", src)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return false, err
	}
	return true, syncDir(filepath.Dir(dst))
}

func writeIfChanged(path string, b []byte, mode os.FileMode) error {
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, b) {
		return nil
	}
	return writeFileAtomic(path, b, mode)
}
