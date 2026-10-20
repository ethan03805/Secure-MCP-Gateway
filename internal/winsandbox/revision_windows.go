//go:build windows

package winsandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Placements keeps the placement records of the enabled revisions in Dir
// (one JSON file per AppContainer profile) and applies them. Ensure and
// Remove are the elevated enable and disable steps of the machine mode:
// creating the profile and the access entries works for the account that
// owns the paths, the WFP filters and the loopback exemption need an
// administrator. Lookup is what the Gateway reads at launch.
type Placements struct {
	Dir string
}

func (p Placements) file(profile string) string { return filepath.Join(p.Dir, profile+".json") }

// Lookup returns the placement of a revision, if it was set up.
func (p Placements) Lookup(serverID, revision string) (Placement, bool) {
	b, err := os.ReadFile(p.file(ProfileName(serverID, revision)))
	if err != nil {
		return Placement{}, false
	}
	var pl Placement
	if json.Unmarshal(b, &pl) != nil || pl.Profile == "" {
		return Placement{}, false
	}
	return pl, true
}

// List returns every recorded placement.
func (p Placements) List() ([]Placement, error) {
	ents, err := os.ReadDir(p.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Placement
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(p.Dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var pl Placement
		if err := json.Unmarshal(b, &pl); err == nil && pl.Profile != "" {
			out = append(out, pl)
		}
	}
	return out, nil
}

func (p Placements) save(pl Placement) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(pl, "", "  ")
	if err != nil {
		return err
	}
	tmp := p.file(pl.Profile) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.file(pl.Profile))
}

// Ensure sets up or updates the placement of one revision: the profile,
// the access entries (changed grants are applied, removed ones revoked),
// the WFP filters and loopback exemption for the broker port, and the
// record. It is idempotent.
func (p Placements) Ensure(req PlacementRequest) (Placement, error) {
	name := ProfileName(req.ServerID, req.Revision)
	old, had := p.Lookup(req.ServerID, req.Revision)
	c, err := CreateProfile(name, ProfileDisplayName(req.ServerID, req.Revision))
	if err != nil {
		return Placement{}, err
	}
	pl := Placement{ServerID: req.ServerID, Revision: req.Revision, Profile: name, SID: c.SID.String(),
		Tree: req.Tree, Scratch: req.Scratch, Roots: req.Roots, BrokerPort: old.BrokerPort}
	type grant struct {
		path  string
		write bool
	}
	want := map[string]bool{} // path -> write
	var order []grant
	add := func(path string, write bool) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if w, ok := want[path]; !ok || (write && !w) {
			if !ok {
				order = append(order, grant{path, write})
			}
			want[path] = w || write
		}
	}
	if req.Tree != "" {
		add(req.Tree, false)
	}
	if req.Scratch != "" {
		if err := os.MkdirAll(req.Scratch, 0o700); err != nil {
			return Placement{}, err
		}
		add(req.Scratch, true)
	}
	for _, r := range req.Roots {
		add(r.Path, r.Write)
	}
	if had {
		for _, path := range grantedPaths(old) {
			if _, keep := want[filepath.Clean(path)]; !keep {
				if err := Revoke(path, c.SID); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
					return Placement{}, err
				}
			}
		}
	}
	for _, g := range order {
		a := ReadExecute
		if want[g.path] {
			a = Modify
		}
		if err := EnsureGrant(g.path, c.SID, a); err != nil {
			return Placement{}, err
		}
	}
	if pl.BrokerPort == 0 {
		if pl.BrokerPort, err = freeLoopbackPort(); err != nil {
			return Placement{}, err
		}
	}
	e, err := OpenEngine()
	if err != nil {
		return Placement{}, fmt.Errorf("the egress filters need an administrator (run the enable step elevated): %w", err)
	}
	defer e.Close()
	if err := e.AddBackendFilters(c.SID, pl.BrokerPort); err != nil {
		return Placement{}, err
	}
	return pl, p.save(pl)
}

func grantedPaths(pl Placement) []string {
	out := []string{pl.Tree, pl.Scratch}
	for _, r := range pl.Roots {
		out = append(out, r.Path)
	}
	return slicesCompact(out)
}

func slicesCompact(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// EnsureGrant writes the grant unless path already carries exactly that
// explicit entry for sid, so an unchanged grant costs one DACL read and no
// walk of the tree.
func EnsureGrant(path string, sid *windows.SID, a Access) error {
	es, err := Entries(path, sid)
	if err != nil {
		return err
	}
	explicit := 0
	ok := false
	for _, e := range es {
		if e.Inherited {
			continue
		}
		explicit++
		ok = e.Allowed && e.Mask == uint32(a.mask())
	}
	if explicit == 1 && ok {
		return nil
	}
	return Grant(path, sid, a)
}

// Remove undoes the placement of one revision: the WFP filters and the
// loopback exemption, every access entry of its SID on the recorded paths,
// the profile and the record. A revision without a record is not an error.
func (p Placements) Remove(serverID, revision string) error {
	name := ProfileName(serverID, revision)
	c, err := OpenProfile(name)
	if err != nil {
		return err
	}
	var errs []error
	if e, err := OpenEngine(); err == nil {
		errs = append(errs, e.RemoveBackendFilters(c.SID))
		e.Close()
	} else {
		errs = append(errs, fmt.Errorf("the egress filters need an administrator (run the disable step elevated): %w", err))
	}
	if pl, ok := p.Lookup(serverID, revision); ok {
		for _, path := range grantedPaths(pl) {
			if err := Revoke(path, c.SID); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
				errs = append(errs, err)
			}
		}
	}
	errs = append(errs, DeleteProfile(name))
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := os.Remove(p.file(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// RemoveAll removes every recorded placement and then the Gateway's WFP
// provider and sublayer (smcpctl uninstall, SR-4.5-3).
func (p Placements) RemoveAll() error {
	pls, err := p.List()
	if err != nil {
		return err
	}
	var errs []error
	var sids []*windows.SID
	for _, pl := range pls {
		if c, err := OpenProfile(pl.Profile); err == nil {
			sids = append(sids, c.SID)
		}
		errs = append(errs, p.Remove(pl.ServerID, pl.Revision))
	}
	e, err := OpenEngine()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	defer e.Close()
	errs = append(errs, e.Uninstall(sids))
	return errors.Join(errs...)
}

// SID returns the placement's AppContainer SID.
func (pl Placement) Container() (*Container, error) {
	return OpenProfile(pl.Profile)
}

func freeLoopbackPort() (uint16, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}
