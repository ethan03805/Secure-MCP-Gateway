package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// importRecord is one revision imported from a catalog entry.
type importRecord struct {
	EntryID       string `json:"entry_id"`
	EntrySHA256   string `json:"entry_sha256"`
	CatalogSHA256 string `json:"catalog_sha256"`
	Class         string `json:"class"`
	ServerID      string `json:"server_id"`
	Revision      string `json:"revision"`
	Actor         string `json:"actor"`
	Time          string `json:"time"`
}

// importsDoc is <state>/contextforge/imports.json: what was imported from
// which entry digest. It is a convenience index for the import state
// (FR-22.16); the signed provenance of each revision is the record.
type importsDoc struct {
	Version int            `json:"version"`
	Imports []importRecord `json:"imports"`
	path    string
}

func loadImports(path string) (*importsDoc, error) {
	d := &importsDoc{Version: 1, path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

// add appends a record and saves; the caller holds the Connector's mu.
func (d *importsDoc) add(r importRecord) error {
	d.Imports = append(d.Imports, r)
	return packaging.WriteJSON(d.path, d, 0o600)
}

// forEntry returns the records of one entry in import order.
func (d *importsDoc) forEntry(id string) []importRecord {
	var out []importRecord
	for _, r := range d.Imports {
		if r.EntryID == id {
			out = append(out, r)
		}
	}
	return out
}
