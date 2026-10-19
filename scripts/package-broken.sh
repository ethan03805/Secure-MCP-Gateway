#!/usr/bin/env bash
# Broken-installer stop test (E-35; SRS FR-20.24):
#
#   scripts/package-broken.sh <package file> <expected version>
#
# Makes two broken copies of a good .deb, .rpm or .pkg (one truncated to
# half its size, one with a byte changed in the middle of the payload) and
# checks, for each, that
#
#  1. the package manager refuses to install it (dpkg, rpm, installer);
#  2. scripts/package-smoke.sh, which the release workflow runs before it
#     publishes, stops with a failure;
#  3. nothing of the package is installed afterwards.
#
# A truncated or altered package therefore never passes the installers
# workflow, and the release job, which needs that workflow, publishes
# nothing. Run it where scripts/package-smoke.sh runs (a fresh runner or
# container, with sudo or as root), before or after that script.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <package file> <expected version>" >&2; exit 2; }
good=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
want=$2
here=$(cd "$(dirname "$0")" && pwd)
fail() { echo "::error::package-broken: $*" >&2; exit 1; }
priv() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi; }
work=$(mktemp -d)
chmod 0755 "$work"
trap 'rm -rf "$work"' EXIT

case "$good" in
*.deb) format=deb ;;
*.rpm) format=rpm ;;
*.pkg) format=pkg ;;
*) fail "$good: not a .deb, .rpm or .pkg" ;;
esac
name=$(basename "$good")
size=$(wc -c <"$good" | tr -d ' ')

# Nothing of the package may be installed before or after.
nothing_installed() {
	local st
	case $format in
	# A refused dpkg -i can leave a database entry whose status is
	# not-installed; any other status means files were placed.
	deb)
		st=$(dpkg-query -W -f '${db:Status-Status}' smcp 2>/dev/null || true)
		{ [ -z "$st" ] || [ "$st" = not-installed ]; } && [ ! -e /usr/bin/smcpd ] && [ ! -e /usr/lib/smcp/package-format ]
		;;
	rpm) ! rpm -q smcp >/dev/null 2>&1 ;;
	pkg) ! pkgutil --pkg-info io.github.ethan03805.smcp >/dev/null 2>&1 && [ ! -e /usr/local/lib/smcp/smcpd ] ;;
	esac
}
nothing_installed || fail "smcp is installed before the test"
# Drops the not-installed database entry a refused dpkg -i leaves, so that
# the next step starts from a clean database.
forget() { [ "$format" != deb ] || priv dpkg --purge smcp >/dev/null 2>&1 || true; }

mkdir "$work/truncated" "$work/altered"
head -c $((size / 2)) "$good" >"$work/truncated/$name"
cp "$good" "$work/altered/$name"
# One byte in the middle of the file: inside the compressed payload of a
# .deb (data.tar), .rpm (cpio payload) or .pkg (xar Payload).
off=$((size / 2))
orig=$(od -An -tu1 -j "$off" -N1 "$good" | tr -d ' ')
printf '%b' "\\0$(printf '%03o' $(((orig + 1) % 256)))" | dd of="$work/altered/$name" bs=1 seek="$off" count=1 conv=notrunc 2>/dev/null
cmp -s "$good" "$work/altered/$name" && fail "the altered copy is identical"

for kind in truncated altered; do
	pkg=$work/$kind/$name
	echo "== $kind $name"
	case $format in
	deb) if priv dpkg -i "$pkg" >"$work/pm.log" 2>&1; then fail "dpkg installed the $kind package"; fi ;;
	rpm) if priv rpm -i "$pkg" >"$work/pm.log" 2>&1; then fail "rpm installed the $kind package"; fi ;;
	pkg) if priv installer -pkg "$pkg" -target / >"$work/pm.log" 2>&1; then fail "installer installed the $kind package"; fi ;;
	esac
	echo "package manager refused it: $(tail -n 2 "$work/pm.log" | tr '\n' ' ')"
	nothing_installed || fail "the $kind package left smcp installed"
	forget
	if bash "$here/package-smoke.sh" "$pkg" "$want" >"$work/smoke.log" 2>&1; then
		cat "$work/smoke.log" >&2
		fail "package-smoke.sh passed the $kind package"
	fi
	echo "package-smoke.sh stopped: $(grep -m1 -E '::error::|error|Error' "$work/smoke.log" || tail -n 1 "$work/smoke.log")"
	nothing_installed || fail "package-smoke.sh left smcp installed after the $kind package"
	forget
done
echo "package-broken: $format refused when truncated or altered"
