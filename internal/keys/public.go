package keys

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Public client view files (CP-46 public/; config.ClientView): a copy of
// the CA trust bundle and the client view, both mode 0644.
const (
	publicCAFile   = "ca.crt"
	publicViewFile = "client.json"
)

// PublishPublic writes the CA trust bundle of stateDir and view (encoded as
// JSON) to dir, each only when its content changed, and reports whether
// it wrote either. The directory must exist: it is created by the
// installation with an owner the Gateway can write as, and is not created
// here, so a missing directory is reported instead of being made with the
// wrong owner. The files hold no secret (the CA certificate and the
// listener addresses), so they are readable by every user.
func PublishPublic(stateDir, dir string, view any) (bool, error) {
	if dir == "" {
		return false, errors.New("no client view directory")
	}
	if fi, err := os.Stat(dir); err != nil {
		return false, err
	} else if !fi.IsDir() {
		return false, errors.New(dir + " is not a directory")
	}
	ca, err := os.ReadFile(filepath.Join(stateDir, CACertFile))
	if err != nil {
		return false, err
	}
	if _, err := loadBundle(filepath.Join(stateDir, CACertFile)); err != nil {
		return false, err
	}
	v, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		return false, err
	}
	v = append(v, '\n')
	wrote := false
	for _, f := range []struct {
		name string
		data []byte
	}{{publicCAFile, ca}, {publicViewFile, v}} {
		p := filepath.Join(dir, f.name)
		if cur, err := os.ReadFile(p); err == nil && bytes.Equal(cur, f.data) {
			// Windows has no POSIX modes (the view is an Enforced-profile,
			// Linux file); elsewhere a wrong mode is repaired.
			if fi, err := os.Stat(p); err == nil && (runtime.GOOS == "windows" || fi.Mode().Perm() == 0o644) {
				continue
			}
		}
		if err := WriteFileAtomic(p, f.data, 0o644); err != nil {
			return wrote, err
		}
		wrote = true
	}
	return wrote, nil
}
