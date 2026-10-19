#!/usr/bin/env bash
# Smoke test of one platform installer (E-35; SRS FR-20.17, FR-20.18,
# FR-20.21, FR-20.22, FR-20.24, FR-20.26, SR-4.11-2):
#
#   scripts/package-smoke.sh <package file> <expected version>
#
# The package is a .deb (Ubuntu), an .rpm (Fedora) or a .pkg (macOS). Run
# it on a fresh runner or container: as a user with passwordless sudo
# (GitHub runners), or as root, when it does the user's part as a new
# unprivileged user. It
#
#  1. checks the package metadata: no dependency, files only under the
#     package's own prefixes, no maintainer script but the pre-removal one;
#  2. installs the package and checks that installing created no Gateway
#     configuration, state, unit or account and started nothing (FR-20.21);
#  3. checks every binary: root-owned, not writable by the user
#     (SR-4.11-2), reports the expected version; on macOS ad-hoc signed
#     (FR-20.26) and linked from /usr/local/bin (FR-20.17);
#  4. runs smcpctl bootstrap, smcpd, a journal, a backup and smcpctl doctor
#     in the Standalone profile in a temporary directory; doctor must not
#     report the packaged binaries as writable, and must report a copy in a
#     user-writable directory;
#  5. on Linux with systemd, installs a stand-in system smcpd.service;
#  6. removes the package (Linux: the package manager; macOS: the steps of
#     docs/install.md) and checks that the binaries and the system service
#     are gone and that configuration, journal, keys and backups are
#     byte-for-byte unchanged (FR-20.22);
#  7. installs the package again, verifies the kept journal with the new
#     smcpctl, and removes it again.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <package file> <expected version>" >&2; exit 2; }
pkg=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
want=$2
[ -f "$pkg" ] || { echo "$pkg: no such file" >&2; exit 2; }

fail() { echo "::error::package-smoke: $*" >&2; exit 1; }
step() { echo "== $*"; }

binaries=(smcpd smcpctl smcp-session smcp-stdio smcp-connect smcp-refserver)
case "$pkg" in
# Every file and directory a package may list: its own files and the
# standard parent directories.
*.deb) format=deb bindir=/usr/bin libdir=/usr/bin
	prefixes='^\./(usr/((bin|lib|share|share/doc)/)?)?$|^\./usr/bin/smcp[a-z-]*$|^\./usr/lib/smcp/.*$|^\./usr/share/doc/smcp/.*$' ;;
*.rpm) format=rpm bindir=/usr/bin libdir=/usr/bin
	prefixes='^/usr/bin/smcp[a-z-]*$|^/usr/lib/smcp(/.*)?$|^/usr/share/doc/smcp(/.*)?$' ;;
*.pkg) format=pkg bindir=/usr/local/bin libdir=/usr/local/lib/smcp
	prefixes='^\.(/usr(/local(/(bin|lib|share|share/doc))?)?)?$|^\./usr/local/bin/smcp[a-z-]*$|^\./usr/local/lib/smcp(/.*)?$|^\./usr/local/share/doc/smcp(/.*)?$|^\./Applications$|^\./Applications/Secure MCP Gateway\.app(/.*)?$' ;;
*) fail "$pkg: not a .deb, .rpm or .pkg" ;;
esac

# Who does the user's part.
# (Functions rather than arrays: macOS bash 3.2 rejects an empty array
# under set -u.)
if [ "$(id -u)" = 0 ]; then
	id smcptest >/dev/null 2>&1 || useradd -m smcptest
	asuser() { runuser -u smcptest -- "$@"; }
	priv() { "$@"; }
	uhome=$(getent passwd smcptest | cut -d: -f6)
else
	asuser() { "$@"; }
	priv() { sudo -n "$@"; }
	uhome=$HOME
fi
work=$(mktemp -d)
chmod 0755 "$work"
[ "$(id -u)" = 0 ] && chown smcptest "$work"
cleanup() {
	pkill -f "smcpd --config $work/" 2>/dev/null || true
	rm -rf "$work" 2>/dev/null || priv rm -rf "$work"
}
trap cleanup EXIT

have_systemd() { [ "$format" != pkg ] && [ -d /run/systemd/system ]; }

install_pkg() {
	case $format in
	deb) priv env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" ;;
	rpm) priv dnf install -y -q "$pkg" ;;
	pkg) priv installer -pkg "$pkg" -target / ;;
	esac
}

# The macOS removal is the documented one (docs/install.md, "Remove the
# macOS package"); the Linux removal is the package manager's.
remove_pkg() {
	case $format in
	deb) priv env DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq smcp ;;
	rpm) priv dnf remove -y -q smcp ;;
	pkg)
		priv rm -f /usr/local/bin/smcpd /usr/local/bin/smcpctl /usr/local/bin/smcp-session \
			/usr/local/bin/smcp-stdio /usr/local/bin/smcp-connect /usr/local/bin/smcp-refserver
		priv rm -rf /usr/local/lib/smcp /usr/local/share/doc/smcp "/Applications/Secure MCP Gateway.app"
		priv pkgutil --forget io.github.ethan03805.smcp
		;;
	esac
}

# Gateway objects that only `smcpctl install` or bootstrap may create
# (CP-46 directories, units, accounts) and smcpd processes.
host_objects() {
	local p
	for p in /etc/smcp /var/lib/smcp /var/log/smcp \
		/etc/systemd/system/smcpd.service /etc/systemd/system/smcp-nftables.service \
		"$uhome/.config/smcp-gateway" "$uhome/.local/state/smcp-gateway" "$uhome/.local/share/smcp-gateway" \
		"$uhome/.config/systemd/user/smcpd.service" "$uhome/Library/Application Support/smcp-gateway" \
		"$uhome/Library/Logs/smcp-gateway" "$uhome/Library/LaunchAgents/com.smcp.gateway.plist"; do
		[ -e "$p" ] && echo "exists $p"
	done
	for a in smcp-core smcp-evidence smcp-keys smcp-vault smcp-data smcp-console smcp-srv; do
		id "$a" >/dev/null 2>&1 && echo "account $a"
	done
	pgrep -x smcpd >/dev/null 2>&1 && echo "process smcpd"
	true
}

step "1. package metadata ($format)"
case $format in
deb)
	deps=$(dpkg-deb -f "$pkg" Depends Pre-Depends Recommends)
	[ -z "$deps" ] || fail "the .deb declares dependencies: $deps"
	files=$(dpkg-deb -c "$pkg" | awk '{print $6}')
	dpkg-deb -e "$pkg" "$work/control"
	scripts=$(find "$work/control" -type f ! -name control ! -name md5sums -exec basename {} \; | sort | tr '\n' ' ')
	[ "$scripts" = "prerm " ] || fail "control files besides control and md5sums are '$scripts', not only prerm (no conffiles)"
	notroot=$(dpkg-deb -c "$pkg" | awk '$2 != "root/root"')
	[ -z "$notroot" ] || fail "files not owned by root/root: $notroot"
	;;
rpm)
	reqs=$(rpm -qp --requires "$pkg" | grep -v -e '^rpmlib(' -e '^/bin/sh$' || true)
	[ -z "$reqs" ] || fail "the .rpm requires: $reqs"
	files=$(rpm -qlp "$pkg")
	scripts=$(rpm -qp --scripts "$pkg" | grep -o '^[a-z]* scriptlet' | sort -u | tr '\n' ' ')
	[ "$scripts" = "preuninstall scriptlet " ] || fail "scriptlets are '$scripts', not only preuninstall"
	notroot=$(rpm -qlvp "$pkg" | awk '$3 != "root" || $4 != "root"')
	[ -z "$notroot" ] || fail "files not owned by root:root: $notroot"
	;;
pkg)
	files=$(pkgutil --payload-files "$pkg")
	# pkgutil exits 1 for an unsigned package.
	sig=$(pkgutil --check-signature "$pkg" 2>&1 || true)
	grep -q 'Status: no signature' <<<"$sig" || fail "the .pkg carries a signature (FR-20.26: none until FR-20.29): $sig"
	x=$work/expanded
	pkgutil --expand "$pkg" "$x"
	if [ -n "$(find "$x" -name Scripts)" ]; then fail "the .pkg has install scripts"; fi
	;;
esac
bad=$(grep -Ev "$prefixes" <<<"$files" || true)
[ -z "$bad" ] || fail "files outside the package prefixes: $bad"
for b in "${binaries[@]}"; do
	grep -Eq "/$b\$" <<<"$files" || fail "$b is not in the package"
done

step "2. install creates no Gateway state and starts nothing (FR-20.21)"
before=$(host_objects)
install_pkg
after=$(host_objects)
[ "$before" = "$after" ] || fail "installing changed Gateway host objects: before '$before' after '$after'"
echo "host objects unchanged: ${after:-none}"

step "3. binaries"
for b in "${binaries[@]}"; do
	link=$bindir/$b
	[ -e "$link" ] || fail "$link missing"
	real=$libdir/$b
	if [ "$format" = pkg ]; then
		[ "$(readlink "$link")" = "../lib/smcp/$b" ] || fail "$link is not a link to ../lib/smcp/$b"
		cs=$(codesign -dv "$real" 2>&1 || true)
		grep -q 'Signature=adhoc' <<<"$cs" || fail "$real has no ad-hoc signature (FR-20.26)"
		owner=$(stat -f %u "$real")
	else
		owner=$(stat -c %u "$real")
	fi
	[ "$owner" = 0 ] || fail "$real is owned by uid $owner, not root (SR-4.11-2)"
	if asuser test -w "$real"; then fail "$real is writable by the user (SR-4.11-2)"; fi
	if [ "$b" = smcpctl ]; then
		got=$(asuser "$link" version --short)
		[ "$got" = "$want" ] || fail "smcpctl version --short printed '$got', not '$want'"
	else
		got=$(asuser "$link" --version 2>&1)
		[ "$got" = "$b $want" ] || fail "$b --version printed '$got', not '$b $want'"
	fi
	echo "$link: uid 0, not writable by the user, version $want"
done
if asuser test -w "$libdir"; then fail "$libdir is writable by the user (SR-4.11-2)"; fi
if [ "$format" = pkg ] && grep -q '^\./Applications/Secure MCP Gateway\.app/Contents/MacOS/smcp-desktop$' <<<"$files"; then
	# The Desktop Application (FR-20.17, FR-20.26, SR-4.11-2).
	app="/Applications/Secure MCP Gateway.app"
	[ -x "$app/Contents/MacOS/smcp-desktop" ] || fail "$app was not installed"
	[ "$(stat -f %u "$app")" = 0 ] || fail "$app is not owned by root (SR-4.11-2)"
	if asuser test -w "$app/Contents/MacOS/smcp-desktop"; then fail "$app is writable by the user (SR-4.11-2)"; fi
	for f in "$app" "$app"/Contents/MacOS/*; do
		cs=$(codesign -dv "$f" 2>&1 || true)
		grep -q 'Signature=adhoc' <<<"$cs" || fail "$f has no ad-hoc signature (FR-20.26)"
	done
	out=$(asuser "$app/Contents/MacOS/smcp-desktop" --commands) || { printf '%s\n' "$out" >&2; fail "the application does not find its commands"; }
	printf '%s\n' "$out"
	echo "$app: root-owned, ad-hoc signed, finds its commands"
fi
if [ "$format" = pkg ]; then
	pkgs=$(pkgutil --pkgs || true)
	grep -qx io.github.ethan03805.smcp <<<"$pkgs" || fail "pkgutil does not know io.github.ethan03805.smcp"
fi

step "4. Standalone bootstrap, smcpd, journal, backup, doctor (temporary state)"
st=$work/st
asuser sh -c "umask 077; printf 'smoke-approver-password-1\n' > '$work/approver'; printf 'smoke-backup-passphrase-1\n' > '$work/backup-pass'"
asuser "$bindir/smcpctl" bootstrap --dir "$st" --bootstrap-token --approver-password-file "$work/approver" \
	--port 28443 --admin-port 28444 </dev/null >/dev/null
# The Standalone profile also on a runner that happens to have Podman.
asuser sh -c "printf '\n[profile]\nmode = \"standalone\"\n' >> '$st/smcp.toml'"
asuser sh -c "'$bindir/smcpd' --config '$st/smcp.toml' > '$work/smcpd.log' 2>&1 &"
ok=0
for _ in $(seq 1 60); do
	if asuser "$bindir/smcpctl" health --config "$st/smcp.toml" >/dev/null 2>&1; then ok=1; break; fi
	sleep 1
done
[ $ok = 1 ] || { cat "$work/smcpd.log" >&2; fail "smcpd did not answer health"; }
out=$(asuser "$bindir/smcpctl" health --config "$st/smcp.toml")
echo "${out%%$'\n'*}"
out=$(asuser "$bindir/smcpctl" backup --config "$st/smcp.toml" --passphrase-file "$work/backup-pass")
echo "${out%%$'\n'*}"
doctor=$(asuser "$bindir/smcpctl" doctor --config "$st/smcp.toml" 2>&1 || true)
if grep -q 'binary-writable' <<<"$doctor"; then
	printf '%s\n' "$doctor" >&2
	fail "doctor reports the packaged binaries as writable"
fi
grep -q 'not writable by this user (SR-4.11-2)' <<<"$doctor" || { printf '%s\n' "$doctor" >&2; fail "doctor did not check the binaries"; }
echo "doctor: packaged binaries not writable"
asuser mkdir "$work/userbin"
asuser cp "$libdir/smcpctl" "$work/userbin/smcpctl"
doctor=$(asuser "$work/userbin/smcpctl" doctor --config "$st/smcp.toml" 2>&1 || true)
grep -q "binary-writable" <<<"$doctor" || { printf '%s\n' "$doctor" >&2; fail "doctor did not report a user-writable smcpctl"; }
echo "doctor: a user-writable copy is reported (binary-writable)"
up=$(asuser "$bindir/smcpctl" upgrade --config "$st/smcp.toml" --release "$work/none" 2>&1 || true)
grep -q "installed by the smcp $format package" <<<"$up" || fail "smcpctl upgrade did not refuse packaged binaries: $up"
pkill -f "smcpd --config $st/" || true
for _ in $(seq 1 30); do pgrep -f "smcpd --config $st/" >/dev/null || break; sleep 1; done
ls "$st/state/journal"/segment-*.jsonl >/dev/null || fail "no journal segment"
ls "$st/backups"/*.age >/dev/null || fail "no backup"

if have_systemd; then
	step "5. stand-in system smcpd.service"
	printf '[Unit]\nDescription=smcpd stand-in (package smoke test)\n[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n' |
		priv tee /etc/systemd/system/smcpd.service >/dev/null
	priv systemctl daemon-reload
	priv systemctl enable --now smcpd.service
	systemctl is-active --quiet smcpd.service || fail "stand-in smcpd.service did not start"
else
	step "5. no systemd: system service check skipped"
fi

if [ "$format" = pkg ]; then
	step "6a. smcpctl uninstall (documented first step) keeps the packaged binaries"
	out=$(asuser "$bindir/smcpctl" uninstall --config "$st/smcp.toml" 2>&1)
	printf '%s\n' "$out"
	grep -q "kept: binaries in .*installed by the smcp pkg package" <<<"$out" || fail "uninstall did not keep the packaged binaries"
	[ -x "$libdir/smcpctl" ] || fail "uninstall removed $libdir/smcpctl"
fi

step "6. remove the package; evidence stays (FR-20.22)"
digests() {
	local h=(shasum -a 256)
	command -v sha256sum >/dev/null && h=(sha256sum)
	(cd "$st" && find . -type f ! -path './state/log/*' -print0 | sort -z | xargs -0 "${h[@]}")
}
kept=$(asuser bash -c "$(declare -f digests); st='$st'; digests")
remove_pkg
for b in "${binaries[@]}"; do
	[ ! -e "$bindir/$b" ] && [ ! -L "$bindir/$b" ] || fail "$bindir/$b still exists after removal"
	[ ! -e "$libdir/$b" ] || fail "$libdir/$b still exists after removal"
done
for m in /usr/lib/smcp/package-format /usr/local/lib/smcp/package-format; do
	[ ! -e "$m" ] || fail "the package marker $m is still there"
done
if have_systemd; then
	[ ! -e /etc/systemd/system/smcpd.service ] || fail "the system smcpd.service is still installed"
	if systemctl is-active --quiet smcpd.service; then fail "smcpd.service still runs"; fi
	echo "system smcpd.service stopped and removed"
fi
now=$(asuser bash -c "$(declare -f digests); st='$st'; digests")
[ "$kept" = "$now" ] || { diff <(echo "$kept") <(echo "$now") >&2 || true; fail "configuration, journal, keys or backups changed on removal"; }
echo "kept unchanged: $(printf '%s\n' "$now" | wc -l | tr -d ' ') files (configuration, journal, keys, backups)"

step "7. reinstall, verify the kept journal, remove"
install_pkg
now=$(asuser bash -c "$(declare -f digests); st='$st'; digests")
[ "$kept" = "$now" ] || fail "installing over the kept state changed it (FR-20.21)"
asuser "$bindir/smcpctl" journal verify --dir "$st/state/journal" --key "$st/state/keys/evidence-genesis.pub"
remove_pkg
echo "package-smoke: $format passed"
