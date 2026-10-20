//go:build !windows

package winsandbox

// Placements keeps the AppContainer placements of the Windows machine mode;
// off Windows every method fails with ErrUnsupported.
type Placements struct {
	Dir string
}

// Lookup reports no placement.
func (Placements) Lookup(string, string) (Placement, bool) { return Placement{}, false }

// List returns nothing.
func (Placements) List() ([]Placement, error) { return nil, nil }

// Ensure returns ErrUnsupported.
func (Placements) Ensure(PlacementRequest) (Placement, error) { return Placement{}, ErrUnsupported }

// Remove returns ErrUnsupported.
func (Placements) Remove(string, string) error { return ErrUnsupported }

// RemoveAll returns ErrUnsupported.
func (Placements) RemoveAll() error { return ErrUnsupported }
