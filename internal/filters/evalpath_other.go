//go:build !windows

package filters

import "path/filepath"

// evalPath resolves symbolic links in an existing path.
func evalPath(p string) (string, error) { return filepath.EvalSymlinks(p) }
