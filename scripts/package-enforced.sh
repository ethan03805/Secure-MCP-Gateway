#!/usr/bin/env bash
# The Enforced profile from the smcp .deb (SRS FR-13.5 with FR-20.18,
# FR-20.21 and FR-20.22):
#
#   scripts/package-enforced.sh <smcp .deb> <expected version>
#
# Run it on a disposable Ubuntu 24.04 host with systemd, AppArmor and the
# Enforced prerequisites (Podman, crun, uidmap, nftables), as a user with
# passwordless sudo: the installers workflow runs it on a GitHub-hosted
# runner after scripts/package-smoke.sh. It
#
#  1. installs the package and runs `smcpctl install --profile enforced`
#     from it;
#  2. checks that the installation uses the package's binaries in place:
#     nothing is copied into /usr/local/bin (a copy there would never be
#     updated by apt), smcpd.service runs /usr/bin/smcpd as smcp-core under
#     the AppArmor profile smcpd, and the Gateway is healthy (its example
#     server was packaged from the package's smcp-refserver);
#  3. runs the install again: every step present, none created or updated;
#  4. reinstalls the package (what an upgrade does to the files), restarts
#     the service and checks that it runs the package's new file;
#  5. removes the package: the system service is stopped and removed by the
#     pre-removal script, the binaries are gone, and configuration, keys
#     and journal are kept;
#  6. installs the package again over the kept state, which it leaves
#     byte-for-byte unchanged, and verifies the kept journal.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <smcp .deb> <expected version>" >&2; exit 2; }
pkg=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
want=$2
[ -f "$pkg" ] || { echo "$pkg: no such file" >&2; exit 2; }
case "$pkg" in *.deb) ;; *) echo "$pkg: not a .deb" >&2; exit 2 ;; esac

step() { echo "== $*"; }
fail() {
	echo "::error::package-enforced: $*" >&2
	sudo -n systemctl status smcpd.service --no-pager -l >&2 || true
	sudo -n journalctl -u smcpd.service -n 60 --no-pager >&2 || true
	sudo -n tail -n 60 /var/log/smcp/smcpd.log >&2 || true
	exit 1
}
as_core() { sudo -n -u smcp-core "$@"; }
healthy() {
	local _
	for _ in $(seq 1 60); do
		as_core /usr/bin/smcpctl health --config /etc/smcp/smcp.toml >/dev/null 2>&1 && return 0
		sleep 1
	done
	return 1
}
service_exe() {
	local pid
	pid=$(systemctl show -p MainPID --value smcpd.service)
	[ -n "$pid" ] && [ "$pid" != 0 ] || return 1
	sudo -n readlink "/proc/$pid/exe"
}
# Configuration, keys and journal (the state smcpd writes besides its log
# is checked by `smcpctl journal verify`).
kept_digests() {
	sudo -n find /etc/smcp /var/lib/smcp/state/keys /var/lib/smcp/state/journal -type f -exec sha256sum {} + | sort
}

for b in smcpd smcpctl smcp-refserver; do
	[ ! -e "/usr/local/bin/$b" ] || fail "/usr/local/bin/$b exists before the test; run on a clean host"
done
[ ! -e /etc/smcp ] || fail "/etc/smcp exists before the test; run on a clean host"

step "0. Enforced prerequisites"
sudo -n apt-get install -y -qq podman crun uidmap nftables >/dev/null
podman --version
# GitHub's Ubuntu image adds XDG_CONFIG_HOME=/home/runner/.config to
# /etc/environment, which stock Ubuntu does not have (see
# scripts/ci-install-guide.sh); restore the stock file.
if grep -q '^XDG_CONFIG_HOME=' /etc/environment 2>/dev/null; then
	sudo -n sed -i '/^XDG_CONFIG_HOME=/d' /etc/environment
fi

step "1. install the package and the Enforced profile from it"
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg"
[ "$(/usr/bin/smcpctl version --short)" = "$want" ] || fail "smcpctl is not version $want"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(umask 077 && openssl rand -hex 16 >"$work/admin.pw" && openssl rand -hex 16 >"$work/approver.pw")
# An unused port block above the runner's usual services.
port=$((20000 + RANDOM % 20000))
sudo -n /usr/bin/smcpctl install --profile enforced --admin-password-file "$work/admin.pw" \
	--approver-password-file "$work/approver.pw" --port "$port" --admin-port $((port + 1)) \
	--metrics-port $((port + 2)) --notify off | tee "$work/install.txt" || fail "smcpctl install --profile enforced"
grep -q "^present binaries in /usr/bin from the smcp deb package, used in place$" "$work/install.txt" ||
	fail "install did not use the packaged binaries in place"

step "2. the service runs the package's binaries"
for b in smcpd smcpctl smcp-refserver; do
	[ ! -e "/usr/local/bin/$b" ] || fail "install copied $b into /usr/local/bin, where apt never updates it"
done
grep -qx 'ExecStart=/usr/bin/smcpd --config /etc/smcp/smcp.toml' /etc/systemd/system/smcpd.service ||
	fail "smcpd.service does not run /usr/bin/smcpd: $(grep '^ExecStart=' /etc/systemd/system/smcpd.service)"
healthy || fail "the Enforced Gateway did not answer health"
exe=$(service_exe) || fail "smcpd.service has no main process"
[ "$exe" = /usr/bin/smcpd ] || fail "smcpd.service runs $exe, not /usr/bin/smcpd"
[ "$(dpkg -S /usr/bin/smcpd | cut -d: -f1)" = smcp ] || fail "/usr/bin/smcpd does not belong to the smcp package"
pid=$(systemctl show -p MainPID --value smcpd.service)
[ "$(ps -o user= -p "$pid" | tr -d ' ')" = smcp-core ] || fail "smcpd does not run as smcp-core"
if [ -d /sys/kernel/security/apparmor ]; then
	label=$(sudo -n cat "/proc/$pid/attr/current")
	[ "$label" = "smcpd (enforce)" ] || fail "smcpd runs under AppArmor label '$label', not 'smcpd (enforce)'"
fi
as_core /usr/bin/smcpctl health --config /etc/smcp/smcp.toml | head -n 3
echo "smcpd.service: /usr/bin/smcpd from the smcp package, as smcp-core, healthy"

step "3. a second install changes nothing"
sudo -n /usr/bin/smcpctl install --profile enforced --admin-password-file "$work/admin.pw" \
	--approver-password-file "$work/approver.pw" --port "$port" --admin-port $((port + 1)) \
	--metrics-port $((port + 2)) --notify off 2>&1 | tee "$work/install2.txt" >/dev/null || { cat "$work/install2.txt" >&2; fail "second install"; }
if grep -E '^(created|updated) ' "$work/install2.txt"; then fail "the second install changed the host"; fi

step "4. a package upgrade replaces the file the service runs"
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall "$pkg"
sudo -n dpkg --verify smcp || fail "dpkg --verify smcp reports changed files"
sudo -n systemctl restart smcpd.service
healthy || fail "the Gateway did not answer health after the restart"
exe=$(service_exe) || fail "smcpd.service has no main process after the restart"
[ "$exe" = /usr/bin/smcpd ] || fail "after the upgrade smcpd.service runs $exe"

step "5. remove the package: the system service goes, the evidence stays (FR-20.22)"
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq smcp | tee "$work/remove.txt"
for b in smcpd smcpctl smcp-refserver smcp-session smcp-stdio smcp-connect; do
	[ ! -e "/usr/bin/$b" ] || fail "/usr/bin/$b is still there after removal"
done
[ ! -e /etc/systemd/system/smcpd.service ] || fail "smcpd.service is still installed after removal"
if systemctl is-active --quiet smcpd.service; then fail "smcpd.service still runs after removal"; fi
pgrep -x smcpd >/dev/null && fail "an smcpd process is still running after removal"
kept=$(kept_digests)
[ "$(printf '%s\n' "$kept" | grep -c /journal/)" -ge 1 ] || fail "no journal file was kept"
sudo -n test -f /etc/smcp/smcp.toml || fail "the configuration was not kept"
echo "kept: $(printf '%s\n' "$kept" | wc -l | tr -d ' ') files of configuration, keys and journal"

step "6. install again over the kept state and verify the journal"
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg"
[ ! -e /etc/systemd/system/smcpd.service ] || fail "installing the package created smcpd.service (FR-20.21)"
[ "$(kept_digests)" = "$kept" ] || fail "installing the package changed configuration, keys or journal (FR-20.21)"
sudo -n /usr/bin/smcpctl journal verify --dir /var/lib/smcp/state/journal --key /var/lib/smcp/state/keys/evidence-genesis.pub
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq smcp >/dev/null
echo "package-enforced: passed"
