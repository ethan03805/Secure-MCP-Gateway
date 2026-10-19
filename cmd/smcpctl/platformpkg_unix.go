//go:build !windows

package main

import "golang.org/x/sys/unix"

// canWritePath reports whether the real user may write p (access(2)).
func canWritePath(p string) bool { return unix.Access(p, unix.W_OK) == nil }
