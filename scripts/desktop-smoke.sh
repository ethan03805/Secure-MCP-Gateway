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
#              version, install both over an installation of the previous
#              release's smcp package with a Gateway state, which must
#              stay byte-for-byte unchanged (FR-20.21), check that every
#              file of smcp-desktop is owned by root and not writable by
#              the user (SR-4.11-2), list the commands, start the
#              application, remove both;
#   .rpm       (Fedora container, root, with an unprivileged user for the
#              user's part) the same with the smcp .rpm;
#   .AppImage  (Ubuntu, Arch Linux) list the bundled commands, check that
#              setup offers the Standalone profile only, and start it.
#              With SMCP_SMOKE_SETUP=1 (Ubuntu with a systemd user session
#              and FUSE) also run setup's `smcpctl install` from the
#              mounted image: a systemd user unit that runs copies of the
#              commands outside the image, so the service starts again
#              after the image is unmounted (FR-20.19), and `smcpctl
#              doctor` reporting the AppImage and the copies as writable
#              by the user (SR-4.11-2).
#
# The .dmg copy's `smcpctl doctor` must report the user-writable bundle
# (SR-4.11-2). A pre-release's .deb and .rpm versions must order before
# the final release's (1.3.0~beta.2 before 1.3.0), so the release upgrades
# them.
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
# Resolved (macOS /var is a link), as smcpctl doctor prints paths.
work=$(cd "$(mktemp -d)" && pwd -P)
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

# before_final <package version> <deb|rpm>: a pre-release version orders
# before the final release's, which therefore upgrades it.
before_final() {
	case "$want" in *-*) ;; *) return 0 ;; esac
	local final=${want%%-*}
	case $2 in
	deb) dpkg --compare-versions "$1" lt "$final" || fail "package version $1 does not order before the release $final" ;;
	rpm)
		[ "$(rpm --eval "%{lua: print(rpm.vercmp('$1', '$final'))}")" = -1 ] ||
			fail "package version $1 does not order before the release $final"
		;;
	esac
	echo "package version $1 orders before the release $final"
}

# doctor_writable <smcpctl> <expected path>: smcpctl doctor, with a
# throwaway configuration, reports the path as writable by this user
# (SR-4.11-2).
doctor_writable() {
	local st=$work/doctor-st out
	if [ ! -f "$st/smcp.toml" ]; then
		(umask 077 && printf 'smoke-approver-password-1' >"$work/doctor-approver")
		"$1" bootstrap --dir "$st" --bootstrap-token --approver-password-file "$work/doctor-approver" \
			--port 28443 --admin-port 28444 </dev/null >/dev/null
	fi
	out=$("$1" doctor --config "$st/smcp.toml" 2>&1 || true)
	if ! grep -F "$2" <<<"$out" | grep -q 'binary-writable'; then
		printf '%s\n' "$out" >&2
		fail "smcpctl doctor does not report $2 as writable"
	fi
	echo "doctor reports $2 as writable by this user"
}

xvfb() {
	if command -v xvfb-run >/dev/null; then xvfb-run -a "$@"; else "$@"; fi
}

# The user's part: as root (Fedora container) a new unprivileged user.
if [ "$(id -u)" = 0 ]; then
	asuser() { runuser -u smcptest -- "$@"; }
else
	asuser() { "$@"; }
fi

# previous_release <deb|rpm>: installs the previous release's smcp package
# (SMCP_PREVIOUS_RELEASE, default v1.2.0, checked against its checksum
# file) and makes a Gateway state with its smcpctl in $work/prev-st, the
# existing installation the new packages are installed over (FR-20.21).
previous_release() {
	local prev=${SMCP_PREVIOUS_RELEASE:-v1.2.0} asset base sum got
	case $1 in
	deb) asset=smcp_${prev#v}_$(dpkg --print-architecture).deb ;;
	rpm) asset=smcp-${prev#v}-1.$(uname -m).rpm ;;
	esac
	if [ "$(id -u)" = 0 ]; then id smcptest >/dev/null 2>&1 || useradd -m smcptest; fi
	chmod 0755 "$work"
	mkdir -p "$work/prev"
	chmod 0755 "$work/prev"
	base=https://github.com/ethan03805/Secure-MCP-Gateway/releases/download/$prev
	curl -fsSL --proto '=https' --retry 3 -o "$work/prev/$asset" "$base/$asset"
	curl -fsSL --proto '=https' --retry 3 -o "$work/prev/checksums.txt" "$base/smcp_${prev#v}_checksums.txt"
	sum=$(awk -v a="$asset" '$2 == a {print $1}' "$work/prev/checksums.txt")
	got=$(sha256sum "$work/prev/$asset" | awk '{print $1}')
	[ -n "$sum" ] && [ "$got" = "$sum" ] || fail "$asset of $prev does not match its checksum file"
	case $1 in
	deb) priv env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$work/prev/$asset" >/dev/null ;;
	rpm) priv dnf install -y -q "$work/prev/$asset" >/dev/null ;;
	esac
	[ "$(asuser /usr/bin/smcpctl version --short)" = "${prev#v}" ] || fail "the previous release does not report version ${prev#v}"
	asuser sh -c "umask 077; printf 'smoke-approver-password-1' > '$work/prev-approver'"
	asuser /usr/bin/smcpctl bootstrap --dir "$work/prev-st" --bootstrap-token --approver-password-file "$work/prev-approver" \
		--port 28643 --admin-port 28644 </dev/null >/dev/null
	prev_digests=$(state_digests)
	echo "smcp ${prev#v} installed, with a Gateway state of $(printf '%s\n' "$prev_digests" | wc -l | tr -d ' ') files"
}

state_digests() {
	(cd "$work/prev-st" && find . -type f ! -path './state/log/*' -print0 | sort -z | xargs -0 sha256sum)
}

# over_previous: after installing this build's packages over the previous
# release, the state is unchanged, its journal verifies with the new
# smcpctl, and no Gateway configuration, unit or process was created
# (FR-20.21).
over_previous() {
	local now p uhome=$HOME
	if [ "$(id -u)" = 0 ]; then uhome=$(getent passwd smcptest | cut -d: -f6); fi
	now=$(state_digests)
	[ "$now" = "$prev_digests" ] || { diff <(echo "$prev_digests") <(echo "$now") >&2 || true; fail "installing over the previous release changed its Gateway state"; }
	asuser /usr/bin/smcpctl journal verify --dir "$work/prev-st/state/journal" --key "$work/prev-st/state/keys/evidence-genesis.pub" >/dev/null
	for p in /etc/smcp /var/lib/smcp /etc/systemd/system/smcpd.service "$uhome/.config/smcp-gateway" \
		"$uhome/.config/systemd/user/smcpd.service"; do
		[ ! -e "$p" ] || fail "installing the packages created $p"
	done
	if pgrep -x smcpd >/dev/null; then fail "installing the packages started smcpd"; fi
	echo "installed over the previous release: its state unchanged and verified, nothing created or started"
}

# no_gateway_objects: copying or starting the application created no
# Gateway configuration, state, unit or process (FR-20.21).
no_gateway_objects() {
	local p
	for p in "$HOME/Library/Application Support/smcp-gateway" "$HOME/Library/LaunchAgents/com.smcp.gateway.plist" \
		"$HOME/.config/smcp-gateway" "$HOME/.local/state/smcp-gateway" "$HOME/.config/systemd/user/smcpd.service"; do
		[ ! -e "$p" ] || fail "the application created $p"
	done
	if pgrep -x smcpd >/dev/null; then fail "the application started smcpd"; fi
	echo "no Gateway configuration, state, unit or process was created"
}

# check_package_files <deb|rpm>: every file and directory of smcp-desktop
# is owned by root and not writable by the user (SR-4.11-2).
check_package_files() {
	local list f n=0
	case $1 in
	deb) list=$(dpkg -L smcp-desktop) ;;
	rpm) list=$(rpm -ql smcp-desktop) ;;
	esac
	while IFS= read -r f; do
		case $f in */smcp-desktop*) ;; *) continue ;; esac
		[ -e "$f" ] || continue
		[ "$(stat -c %u "$f")" = 0 ] || fail "$f is not owned by root (SR-4.11-2)"
		if asuser test -w "$f"; then fail "$f is writable by the user (SR-4.11-2)"; fi
		n=$((n + 1))
	done <<<"$list"
	[ "$n" -gt 0 ] || fail "no smcp-desktop file found"
	echo "$n files of smcp-desktop: owned by root, not writable by the user"
}

# appimage_setup: what first-run setup runs, from the mounted image
# (desktop/src-tauri/src/setup.rs, install_argv), then the service after
# the image is unmounted, doctor, and uninstall.
appimage_setup() {
	local mnt pid unit copies ok
	step "AppImage: setup's smcpctl install from the mounted image (FR-20.19)"
	unset APPIMAGE_EXTRACT_AND_RUN
	"$work/app.AppImage" --appimage-mount >"$work/mount.txt" 2>"$work/mount.err" &
	pid=$!
	for _ in $(seq 1 50); do [ -s "$work/mount.txt" ] && break; sleep 0.2; done
	mnt=$(head -n1 "$work/mount.txt")
	[ -n "$mnt" ] && [ -x "$mnt/usr/bin/smcpctl" ] || { cat "$work/mount.err" >&2; fail "the AppImage could not be mounted"; }
	(umask 077 && printf 'smoke-admin-password-1' >"$work/admin.pw" && printf 'smoke-approver-password-1' >"$work/approver.pw")
	APPIMAGE="$work/app.AppImage" APPDIR="$mnt" "$mnt/usr/bin/smcpctl" install --profile standalone \
		--admin-password-file "$work/admin.pw" --approver-password-file "$work/approver.pw" \
		--metrics-port 9464 --notify off --health-timeout 90s
	unit=$HOME/.config/systemd/user/smcpd.service
	copies=$HOME/.local/share/smcp-gateway/bin
	grep -q "^ExecStart=$copies/smcpd " "$unit" || { cat "$unit" >&2; fail "the user unit does not run the copy in $copies"; }
	if grep -qF "$mnt" "$unit"; then fail "the user unit names the AppImage mount $mnt"; fi
	systemctl --user is-active --quiet smcpd.service || fail "the smcpd user unit is not active"
	echo "systemd user unit $unit runs $copies/smcpd and is active"
	step "AppImage: smcpctl doctor reports the AppImage and the copies as writable (SR-4.11-2)"
	APPIMAGE="$work/app.AppImage" APPDIR="$mnt" doctor_writable "$mnt/usr/bin/smcpctl" "$work/app.AppImage"
	doctor_writable "$copies/smcpctl" "$copies"
	step "AppImage: the service starts again after the image is unmounted"
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	for _ in $(seq 1 50); do [ -x "$mnt/usr/bin/smcpctl" ] || break; sleep 0.2; done
	[ ! -x "$mnt/usr/bin/smcpctl" ] || fail "the image is still mounted"
	systemctl --user restart smcpd.service
	ok=0
	for _ in $(seq 1 60); do
		if "$copies/smcpctl" health --config "$HOME/.config/smcp-gateway/smcp.toml" >/dev/null 2>&1; then ok=1; break; fi
		sleep 1
	done
	[ $ok = 1 ] || { systemctl --user status smcpd.service --no-pager >&2 || true; fail "smcpd did not answer health after a restart without the image"; }
	echo "smcpd restarted from $copies and answers health"
	"$copies/smcpctl" uninstall
	[ ! -e "$unit" ] || fail "uninstall left $unit"
	rm -rf "$HOME/.config/smcp-gateway" "$HOME/.local/state/smcp-gateway" "$HOME/.local/share/smcp-gateway"
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
	step "dmg: smcpctl doctor reports the copied bundle as writable (SR-4.11-2)"
	doctor_writable "$work/Applications/Secure MCP Gateway.app/Contents/MacOS/smcpctl" "$work/Applications/Secure MCP Gateway.app/Contents/MacOS"
	start_app "$exe"
	no_gateway_objects
	;;
*.deb)
	[ -n "$smcp" ] || fail "pass the smcp .deb of the same build"
	debver=$(dpkg-deb -f "$smcp" Version)
	step "deb: metadata (FR-20.18)"
	[ "$(dpkg-deb -f "$file" Package)" = smcp-desktop ] || fail "not package smcp-desktop"
	# The same version as smcp: a pre-release keeps "~", so the release
	# (1.3.0) upgrades it; Tauri's own "1.3.0-beta.2" would order after it.
	[ "$(dpkg-deb -f "$file" Version)" = "$debver" ] || fail "version $(dpkg-deb -f "$file" Version), not the smcp package's $debver"
	before_final "$debver" deb
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
	step "deb: over the previous release, install with smcp, list the commands, start, remove"
	previous_release deb
	priv env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$smcp" "$file" >/dev/null
	over_previous
	check_package_files deb
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
	before_final "$(rpm -qp --qf '%{VERSION}' "$file")" rpm
	if rpm -qlp "$file" | grep -Eq '^/usr/bin/smcp(d|ctl|-session|-stdio|-connect|-refserver)$'; then
		fail "smcp-desktop carries Gateway commands"
	fi
	if rpm -i --test "$file" >"$work/rpm.log" 2>&1; then fail "smcp-desktop installs without smcp"; fi
	grep -qF "smcp = $rpmver is needed" "$work/rpm.log" || { cat "$work/rpm.log" >&2; fail "rpm did not name the smcp dependency"; }
	echo "refused without smcp"
	step "rpm: refused with smcp of another version"
	priv dnf install -y -q rpm-build >/dev/null
	mkdir -p "$work/rpmtop"
	printf 'Name: smcp\nVersion: 0.0.1\nRelease: 1\nSummary: other version (smoke test)\nLicense: none\nBuildArch: noarch\n%%description\nother version\n%%files\n' >"$work/other.spec"
	rpmbuild --quiet -bb --define "_topdir $work/rpmtop" "$work/other.spec"
	priv rpm -i "$work"/rpmtop/RPMS/noarch/smcp-0.0.1-1.noarch.rpm
	if rpm -i --test "$file" >"$work/rpm.log" 2>&1; then fail "smcp-desktop installs with smcp 0.0.1"; fi
	grep -qF "smcp = $rpmver is needed" "$work/rpm.log" || { cat "$work/rpm.log" >&2; fail "rpm did not name the required smcp version"; }
	priv rpm -e smcp
	echo "refused: no smcp, smcp 0.0.1"
	step "rpm: over the previous release, install with smcp, list the commands, start, remove"
	previous_release rpm
	priv dnf install -y -q "$smcp" "$file" xorg-x11-server-Xvfb xorg-x11-xauth which >/dev/null
	over_previous
	check_package_files rpm
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
	step "AppImage: setup offers the Standalone profile only (FR-20.19)"
	profiles=$("$work/app.AppImage" --setup-profiles | awk -F'\t' '$1 == "profile" {print $2}' | paste -sd' ' -)
	[ "$profiles" = standalone ] || fail "setup offers '$profiles', not the Standalone profile only"
	echo "setup offers: $profiles"
	start_app xvfb "$work/app.AppImage"
	no_gateway_objects
	if [ "${SMCP_SMOKE_SETUP:-}" = 1 ]; then appimage_setup; fi
	;;
*) fail "$file: not a .dmg, .deb, .rpm or .AppImage" ;;
esac
echo "desktop-smoke: $(basename "$file") passed"
