package secrets

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// ComponentPrefix starts the names of credentials that belong to a Gateway
// component rather than to a server: the bundled ContextForge instance's
// generated credentials (SRS FR-22.28, SR-2.13-5). They are created,
// delivered and retired only through the functions below, never through
// the control API's create route, a Secret Use Policy binding or a server
// launch.
const ComponentPrefix = "component."

var componentID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,23}$`)

// ComponentName is the vault name of a component credential.
func ComponentName(component, name string) string {
	return ComponentPrefix + component + "." + name
}

func checkComponent(component, name string) error {
	if !componentID.MatchString(component) {
		return fmt.Errorf("secrets: component %q is not a component ID", component)
	}
	if !namePattern.MatchString(ComponentName(component, name)) {
		return ErrInvalidName
	}
	return nil
}

// EnsureComponent creates the component credential name with the value
// gen returns when it does not exist yet, and reports whether it did. The
// value is wiped after it is stored.
func (b *Broker) EnsureComponent(component, name string, gen func() ([]byte, error)) (bool, error) {
	if err := checkComponent(component, name); err != nil {
		return false, err
	}
	full := ComponentName(component, name)
	if _, err := b.vault.Get(full); err == nil {
		return false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return false, err
	}
	v, err := gen()
	if err != nil {
		return false, err
	}
	if _, err := b.vault.create(component, CreateParams{Name: full, Type: "generic", Owner: component,
		Description: "generated credential of the Gateway component " + component, Value: v}); err != nil {
		return false, err
	}
	return true, nil
}

// DeliverComponent opens the named credentials of a component for that
// component, registers their leak fingerprints and records one secret_use
// event naming the credentials and their references (never values). It
// refuses a credential another component owns.
func (b *Broker) DeliverComponent(component string, names []string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(names))
	refs := make([]string, 0, len(names))
	fail := func(err error) (map[string][]byte, error) {
		for _, v := range out {
			wipe(v)
		}
		return nil, err
	}
	for _, n := range names {
		if err := checkComponent(component, n); err != nil {
			return fail(err)
		}
		full := ComponentName(component, n)
		m, err := b.vault.Get(full)
		if err != nil {
			return fail(fmt.Errorf("component credential %s: %w", full, err))
		}
		if m.Owner != component {
			return fail(fmt.Errorf("component credential %s belongs to %s", full, m.Owner))
		}
		op, err := b.vault.openAny(full, 0)
		if err != nil {
			return fail(fmt.Errorf("component credential %s: %w", full, err))
		}
		b.fp.Register(op.Ref, op.Version, op.Value)
		out[n] = op.Value
		refs = append(refs, fmt.Sprintf("%s@%d", op.Ref, op.Version))
	}
	b.mu.Lock()
	rec := b.rec
	b.mu.Unlock()
	if rec == nil {
		return fail(ErrNoEvidence)
	}
	slices.Sort(refs)
	if err := rec.Commit(audit.Event{Class: "secret_use", Origin: "E-20", Outcome: "delivered", PolicyStatus: "not_evaluated",
		Detail: map[string]any{"component": component, "secrets": names, "secret_refs": refs, "mode": "component"}}); err != nil {
		return fail(fmt.Errorf("evidence unavailable: %w", err))
	}
	return out, nil
}

// RotateComponent replaces a component credential with the value gen
// returns, with no overlap (an upgrade, FR-22.28).
func (b *Broker) RotateComponent(component, name string, gen func() ([]byte, error)) error {
	if err := checkComponent(component, name); err != nil {
		return err
	}
	v, err := gen()
	if err != nil {
		return err
	}
	_, err = b.vault.Rotate(component, ComponentName(component, name), v, 0)
	return err
}

// RetireComponent removes every credential of a component (uninstall,
// FR-22.32) and returns how many it removed.
func (b *Broker) RetireComponent(component, actor string) (int, error) {
	if !componentID.MatchString(component) {
		return 0, fmt.Errorf("secrets: component %q is not a component ID", component)
	}
	prefix := ComponentName(component, "")
	n := 0
	for _, m := range b.vault.List() {
		if strings.HasPrefix(m.Name, prefix) {
			if err := b.vault.Remove(actor, m.Name); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}
