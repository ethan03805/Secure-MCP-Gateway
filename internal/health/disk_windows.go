//go:build windows

package health

import "github.com/ethan03805/secure-mcp-gateway/internal/winsec"

// freeBytes measures the space available to the Gateway's account on the
// volume holding path with GetDiskFreeSpaceEx (FR-21.26).
func freeBytes(path string) (uint64, error) { return winsec.FreeBytes(path) }
