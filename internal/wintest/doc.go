// Package wintest gives Windows tests a second local account (SRS FR-21.6,
// FR-21.9, SR-2.8-6, SR-2.13-4): it creates a local standard user, and
// optionally a local group, on the test host, logs the user on with its
// profile loaded, and runs code under its token. It needs an elevated
// process, which GitHub's hosted Windows runners provide; elsewhere the
// helpers skip the test. The accounts are deleted when the test ends.
//
// Only test code imports this package.
package wintest
