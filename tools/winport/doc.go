// Package winport holds the Windows build-portability test of SRS FR-21.2:
// every command and test package builds and vets for windows/amd64 and
// windows/arm64 with CGO_ENABLED=0, and no security check in the code
// compiled for Windows reads a POSIX mode, a POSIX owner or a Unix signal
// result unless a Windows branch replaces it. The package has no code of
// its own; see winport_test.go.
package winport
