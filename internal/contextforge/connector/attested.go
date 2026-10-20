package connector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// The bundled instance digest each hosted revision was checked against
// (SR-3.8-2): the image or wheel-set digest of its probe, recorded in its
// provenance statement, until an upgrade checks its tool list against a
// new release and records that release's digest in
// <state>/contextforge/attested.json. A revision whose recorded digest
// differs from the running instance's is suspended for drift instead of
// being registered: its tools are served by code it was not checked
// against.

const attestedFile = "attested.json"

func (c *Connector) loadAttested() map[string]string {
	m := map[string]string{}
	raw, err := os.ReadFile(filepath.Join(c.dir, attestedFile))
	if err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

// recordedDigest is the instance digest rev was last checked against
// ("" when none is known).
func (c *Connector) recordedDigest(rev library.Revision) string {
	c.attMu.Lock()
	d := c.loadAttested()[rev.Key()]
	c.attMu.Unlock()
	if d != "" {
		return d
	}
	raw, err := os.ReadFile(filepath.Join(c.o.Library.Dir(), rev.ServerID, rev.Revision, packaging.ProvenanceFile))
	if err != nil {
		return ""
	}
	var pv packaging.Provenance
	if json.Unmarshal(raw, &pv) != nil || pv.ContextForge == nil {
		return ""
	}
	return pv.ContextForge.InstanceDigest
}

// attest records that rev's tool list was checked against the instance
// with digest.
func (c *Connector) attest(key, digest string) error {
	if digest == "" {
		return errors.New("no instance digest to record")
	}
	c.attMu.Lock()
	defer c.attMu.Unlock()
	m := c.loadAttested()
	m[key] = digest
	return packaging.WriteJSON(filepath.Join(c.dir, attestedFile), m, 0o600)
}

// checkInstanceDigest refuses, and suspends for drift, a hosted revision
// whose recorded instance digest differs from the running instance's
// (SR-3.8-2).
func (c *Connector) checkInstanceDigest(rev library.Revision) error {
	want, got := c.recordedDigest(rev), c.instanceDigest()
	if want == "" || got == "" || want == got || want == "managed-process" {
		return nil
	}
	err := packaging.Errf(ReasonDrift, "%s was checked against the bundled instance %s, which now runs %s", rev.Key(), want, got)
	if c.o.Recorder != nil {
		ev := c.instanceEvent("drift", ReasonDrift, map[string]any{"package": rev.Key(), "kind": "instance_digest", "object": rev.Key(),
			"detail": err.Error(), "removed": false, "recorded_digest": want, "running_digest": got})
		ev.Class, ev.ServerRevision = ClassDrift, rev.Key()
		_ = c.o.Recorder.Commit(ev)
	}
	if c.o.Suspend != nil {
		_ = c.o.Suspend(rev.ServerID, rev.Revision, err)
	}
	return err
}
