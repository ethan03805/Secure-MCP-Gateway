//go:build windows

package durable

import "testing"

// TestWindowsDurableWrites runs TestReplaceAndCreateNew under a name the
// windows CI job collects for the requirement report (FR-21.23).
func TestWindowsDurableWrites(t *testing.T) { TestReplaceAndCreateNew(t) }
