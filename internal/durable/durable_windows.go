//go:build windows

package durable

import (
	"os"

	"golang.org/x/sys/windows"
)

func move(tmp, dst string, flags uint32) error {
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, flags|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: tmp, New: dst, Err: err}
	}
	return nil
}

func replace(tmp, dst string) error {
	if err := move(tmp, dst, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
		return err
	}
	record(Op{Kind: "replace", Path: dst, WriteThrough: true})
	return nil
}

// createNew moves without MOVEFILE_REPLACE_EXISTING, which fails with
// ERROR_ALREADY_EXISTS (errors.Is fs.ErrExist) when dst exists.
func createNew(tmp, dst string) error {
	if err := move(tmp, dst, 0); err != nil {
		return err
	}
	record(Op{Kind: "create", Path: dst, WriteThrough: true})
	return nil
}

func syncDir(dir string) error {
	record(Op{Kind: "syncdir", Path: dir})
	return nil
}
