//go:build !windows

package durable

import (
	"os"
	"path/filepath"
)

func replace(tmp, dst string) error {
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	record(Op{Kind: "replace", Path: dst})
	return syncDir(filepath.Dir(dst))
}

// createNew links tmp to dst: link refuses an existing target.
func createNew(tmp, dst string) error {
	if err := os.Link(tmp, dst); err != nil {
		return err
	}
	record(Op{Kind: "create", Path: dst})
	return syncDir(filepath.Dir(dst))
}

func syncDir(dir string) error {
	record(Op{Kind: "syncdir", Path: dir, DirOpened: true})
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
