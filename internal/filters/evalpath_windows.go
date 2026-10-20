//go:build windows

package filters

import "github.com/ethan03805/secure-mcp-gateway/internal/winsec"

// evalPath resolves an existing path to its final path with
// GetFinalPathNameByHandle (FR-21.25): symbolic links, junctions and other
// mount points are followed, and short (8.3) names are expanded, which
// filepath.EvalSymlinks does not do for junctions.
func evalPath(p string) (string, error) { return winsec.FinalPath(p) }
