#!/usr/bin/env bash
# Smoke test of one Desktop Application installer (E-35; SRS FR-20.17 to
# FR-20.19, FR-20.24, FR-20.26):
#
#   scripts/desktop-smoke.sh <installer> <expected version> [<smcp package>]
#
#   .dmg       (macOS arm64) mount it, check the bundle, the /Applications
#              link and the ad-hoc signatures, copy the application out,
#              list its bundled commands, start it and quit it;
#   .deb       (Ubuntu, sudo) the smcp .deb is the third argument: refuse
#              the application without smcp and with an smcp of another
#              version, install both, list the commands, start the
#              application, remove both;
#   .rpm       (Fedora container, root) the same with the smcp .rpm, without
#              the other-version check (no rpmbuild in the container);
#   .AppImage  (Ubuntu) list the bundled commands and start it.
#
# "Start" runs the application for 10 seconds (under Xvfb on Linux) and
# requires it still to be running; `smcp-desktop --commands` must find the
# six commands, each reporting the expected version, and
# `smcp-desktop --version` must report it too: it is the version the
# application's update check compares with releases (FR-20.11), so an
# application built with the development version 0.1.0 would never be
# offered an update. The .dmg's Info.plist and the .deb's control version
# (the smcp package's, with "~" before a pre-release) are checked as well.
set -euo pipefail

[ $# -ge 2 ] || { echo "usage: $0 <installer> <expected version> [<smcp package>]" >&2; exit 2; }
file=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
want=$2
smcp=${3:-}
# Absolute paths: apt-get takes a bare relative path for a package name.
[ -z "$smcp" ] || smcp=$(cd "$(dirname "$smcp")" && pwd)/$(basename "$smcp")
[ -f "$file" ] || { echo "$file: no such file" >&2; exit 2; }
fail() { echo "::error::desktop-smoke: $*" >&2; exit 1; }
step() { echo "== $*"; }
priv() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi; }
work=$(mktemp -d)
cleanup() {
	pkill -f "$work/" 2>/dev/null || true
	[ -d "$work/mnt" ] && hdiutil detach -quiet "$work/mnt" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

# check_commands <smcp-desktop executable>
check_commands() {
	local out n
	out=$("$@" --commands) || { printf '%s\n' "$out" >&2; fail "smcp-desktop --commands did not find every command"; }
	printf '%s\n' "$out"
	n=$(printf '%s\n' "$out" | awk -F'\t' -v v="$want" '$3 == v' | wc -l | tr -d ' ')
	[ "$n" = 6 ] || fail "$n of 6 commands report version $want"
}

# check_version <command...>: the application reports the expected version.
check_version() {
	local v
	v=$("$@" --version) || fail "smcp-desktop --version failed"
	[ "$v" = "$want" ] || fail "the application reports version '$v', not $want"
	echo "the application reports version $v"
}

# start_app <command...>: runs the application for 10 seconds.
start_app() {
	"$@" >"$work/app.log" 2>&1 &
	local pid=$!
	sleep 10
	if ! kill -0 "$pid" 2>/dev/null; then
		cat "$work/app.log" >&2
		fail "the application exited within 10 seconds"
	fi
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	echo "the application ran for 10 seconds"
}

xvfb() {
	if command -v xvfb-run >/dev/null; then xvfb-run -a "$@"; else "$@"; fi
}

case "$file" in
*.dmg)
	step "dmg: contents and signatures (FR-20.17, FR-20.26)"
	sig=$(codesign -dv "$file" 2>&1 || true)
	grep -q 'not signed' <<<"$sig" || fail "the .dmg carries a signature: $sig"
	mkdir "$work/mnt"
	hdiutil attach -quiet -nobrowse -readonly -mountpoint "$work/mnt" "$file"
	app="$work/mnt/Secure MCP Gateway.app"
	[ -d "$app" ] || fail "the .dmg has no Secure MCP Gateway.app"
	[ "$(readlink "$work/mnt/Applications")" = /Applications ] || fail "the .dmg has no link to /Applications"
	for f in "$app"/Contents/MacOS/*; do
		cs=$(codesign -dv "$f" 2>&1 || true)
		grep -q 'Signature=adhoc' <<<"$cs" || fail "$(basename "$f") has no ad-hoc signature"
		file "$f" | grep -q arm64 || fail "$(basename "$f") is not arm64"
	done
	cs=$(codesign -dv "$app" 2>&1 || true)
	grep -q 'Signature=adhoc' <<<"$cs" || fail "the bundle has no ad-hoc signature"
	codesign --verify --deep --strict "$app" || fail "the bundle signature does not verify"
	for key in CFBundleShortVersionString CFBundleVersion; do
		v=$(plutil -extract "$key" raw "$app/Contents/Info.plist") || fail "Info.plist has no $key"
		[ "$v" = "$want" ] || fail "Info.plist $key is '$v', not $want"
	done
	step "dmg: copy the application out, list its commands, start it"
	mkdir "$work/Applications"
	ditto "$app" "$work/Applications/Secure MCP Gateway.app"
	hdiutil detach -quiet "$work/mnt"
	exe="$work/Applications/Secure MCP Gateway.app/Contents/MacOS/smcp-desktop"
	check_commands "$exe"
	check_version "$exe"
	start_app "$exe"
	;;
*.deb)
	[ -n "$smcp" ] || fail "pass the smcp .deb of the same build"
	debver=$(dpkg-deb -f "$smcp" Version)
	step "deb: metadata (FR-20.18)"
	[ "$(dpkg-deb -f "$file" Package)" = smcp-desktop ] || fail "not package smcp-desktop"
	# The same version as smcp: a pre-release keeps "~", so the release
	# (1.3.0) upgrades it; Tauri's own "1.3.0-beta.2" would order after it.
	[ "$(dpkg-deb -f "$file" Version)" = "$debver" ] || fail "version $(dpkg-deb -f "$file" Version), not the smcp package's $debver"
	n=$(dpkg-deb -f "$file" Depends | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sort | uniq -d | wc -l | tr -d ' ')
	[ "$n" = 0 ] || fail "Depends lists a package twice: $(dpkg-deb -f "$file" Depends)"
	dpkg-deb -f "$file" Depends | grep -qF "smcp (= $debver)" || fail "does not depend on smcp (= $debver)"
	if dpkg-deb -c "$file" | grep -Eq '/usr/bin/smcp(d|ctl|-session|-stdio|-connect|-refserver)$'; then
		fail "smcp-desktop carries Gateway commands"
	fi
	# FR-20.28: the desktop entry registers smcp:// links and passes the
	# link to the application (the .rpm carries the same file).
	dpkg-deb --fsys-tarfile "$file" | tar -xO --wildcards '*usr/share/applications/smcp-desktop.desktop' >"$work/entry" || fail "no desktop entry"
	grep -qx 'MimeType=x-scheme-handler/smcp;' "$work/entry" || fail "the desktop entry does not register smcp:// links: $(cat "$work/entry")"
	grep -qx 'Exec=smcp-desktop %u' "$work/entry" || fail "the desktop entry does not pass the link: $(grep '^Exec=' "$work/entry")"
	step "deb: refused without smcp and with smcp of another version"
	if priv dpkg -i "$file" >"$work/dpkg.log" 2>&1; then fail "smcp-desktop installed without smcp"; fi
	grep -q 'depends on smcp' "$work/dpkg.log" || { cat "$work/dpkg.log" >&2; fail "dpkg did not name the smcp dependency"; }
	priv dpkg --purge smcp-desktop >/dev/null 2>&1 || true
	mkdir -p "$work/other/DEBIAN"
	printf 'Package: smcp\nVersion: 0.0.1\nArchitecture: all\nMaintainer: test <test@example.invalid>\nDescription: other version (smoke test)\n' >"$work/other/DEBIAN/control"
	dpkg-deb -b "$work/other" "$work/smcp-other.deb" >/dev/null
	priv dpkg -i "$work/smcp-other.deb" >/dev/null
	if priv dpkg -i "$file" >"$work/dpkg.log" 2>&1; then fail "smcp-desktop installed with smcp 0.0.1"; fi
	grep -q 'smcp (= ' "$work/dpkg.log" || { cat "$work/dpkg.log" >&2; fail "dpkg did not name the required smcp version"; }
	priv dpkg --purge smcp-desktop smcp >/dev/null 2>&1 || true
	echo "refused: no smcp, smcp 0.0.1"
	step "deb: install with smcp, list the commands, start, remove"
	priv env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$smcp" "$file" >/dev/null
	check_commands /usr/bin/smcp-desktop
	check_version /usr/bin/smcp-desktop
	start_app xvfb /usr/bin/smcp-desktop
	priv env DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq smcp-desktop smcp >/dev/null
	[ ! -e /usr/bin/smcp-desktop ] || fail "/usr/bin/smcp-desktop is still there after removal"
	;;
*.rpm)
	[ -n "$smcp" ] || fail "pass the smcp .rpm of the same build"
	rpmver=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$smcp")
	step "rpm: metadata (FR-20.18)"
	[ "$(rpm -qp --qf '%{NAME}' "$file")" = smcp-desktop ] || fail "not package smcp-desktop"
	# Name, operator and version as rpm stores them: a requirement on a
	# package literally named "smcp = <version>" prints the same text with
	# --requires but is never satisfied.
	req=$(rpm -qp --qf '[%{REQUIRENAME}|%{REQUIREFLAGS:depflags}|%{REQUIREVERSION}\n]' "$file" | grep '^smcp|' | tr -d ' ' || true)
	[ "$req" = "smcp|=|$rpmver" ] || fail "requires '$req', not smcp = $rpmver"
	if rpm -qlp "$file" | grep -Eq '^/usr/bin/smcp(d|ctl|-session|-stdio|-connect|-refserver)$'; then
		fail "smcp-desktop carries Gateway commands"
	fi
	if rpm -i --test "$file" >"$work/rpm.log" 2>&1; then fail "smcp-desktop installs without smcp"; fi
	grep -qF "smcp = $rpmver is needed" "$work/rpm.log" || { cat "$work/rpm.log" >&2; fail "rpm did not name the smcp dependency"; }
	echo "refused without smcp"
	step "rpm: install with smcp, list the commands, start, remove"
	priv dnf install -y -q "$smcp" "$file" xorg-x11-server-Xvfb xorg-x11-xauth which >/dev/null
	check_commands /usr/bin/smcp-desktop
	check_version /usr/bin/smcp-desktop
	start_app xvfb /usr/bin/smcp-desktop
	priv dnf remove -y -q smcp-desktop smcp >/dev/null
	;;
*.AppImage)
	step "AppImage: list the bundled commands, start (FR-20.19)"
	cp "$file" "$work/app.AppImage"
	chmod 0755 "$work/app.AppImage"
	export APPIMAGE_EXTRACT_AND_RUN=1
	out=$("$work/app.AppImage" --commands) || { printf '%s\n' "$out" >&2; fail "--commands failed"; }
	printf '%s\n' "$out"
	# The commands come from inside the image, not from the host.
	n=$(printf '%s\n' "$out" | awk -F'\t' -v v="$want" '$3 == v && $2 !~ "^/usr/(local/)?bin/"' | wc -l | tr -d ' ')
	[ "$n" = 6 ] || fail "$n of 6 bundled commands found inside the AppImage with version $want"
	check_version "$work/app.AppImage"
	start_app xvfb "$work/app.AppImage"
	;;
*) fail "$file: not a .dmg, .deb, .rpm or .AppImage" ;;
esac
echo "desktop-smoke: $(basename "$file") passed"
