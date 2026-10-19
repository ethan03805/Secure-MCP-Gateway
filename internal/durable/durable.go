// Package durable makes file replacement durable on every platform the
// Gateway runs on. On Linux and macOS a flushed temporary file is renamed
// over the target and the directory is synced. Windows refuses to sync a
// directory ("Access is denied"), so there the flushed file is renamed
// with MoveFileEx and MOVEFILE_WRITE_THROUGH and no directory is opened
// (SRS FR-21.23).
package durable

import (
	"sync"
)

// Op is one file-layer operation, recorded by an Observer.
type Op struct {
	// Kind is "replace", "create" or "syncdir".
	Kind string
	// Path is the target file, or the directory for "syncdir".
	Path string
	// WriteThrough is true when the rename used MOVEFILE_WRITE_THROUGH.
	WriteThrough bool
	// DirOpened is true when the operation opened a directory.
	DirOpened bool
}

var (
	obsMu    sync.Mutex
	observer func(Op)
)

// Observe installs f to receive every operation of this package (the
// FR-21.23 test hook) and returns a function that removes it.
func Observe(f func(Op)) (restore func()) {
	obsMu.Lock()
	defer obsMu.Unlock()
	prev := observer
	observer = f
	return func() {
		obsMu.Lock()
		defer obsMu.Unlock()
		observer = prev
	}
}

func record(op Op) {
	obsMu.Lock()
	f := observer
	obsMu.Unlock()
	if f != nil {
		f(op)
	}
}

// Replace renames tmp, a file the caller has written and flushed
// (File.Sync), over dst and makes the rename durable.
func Replace(tmp, dst string) error { return replace(tmp, dst) }

// CreateNew moves tmp, a flushed file, to dst when dst does not exist and
// makes the new name durable. It fails with an error satisfying
// errors.Is(err, fs.ErrExist) when dst exists, and never replaces it.
// tmp may remain afterwards; the caller removes it.
func CreateNew(tmp, dst string) error { return createNew(tmp, dst) }

// SyncDir makes the directory entries of dir durable. On Windows it does
// nothing: renames made by this package are already written through.
func SyncDir(dir string) error { return syncDir(dir) }
