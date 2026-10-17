#!/usr/bin/env bash
# Enforced profile under real systemd: installs packaging/linux with
# install-enforced.sh, bootstraps an instance as smcp-core, starts
# smcpd.service, checks health, makes a tool call that runs in a rootless
# Podman container started by the service, stops the service and verifies
# the evidence journal. When AppArmor is enabled it also checks that smcpd
# runs confined by the shipped profile.
#
# Called by the enforced section of scripts/ci-integration.sh (CI job
# linux-integration on ubuntu-24.04); runs standalone on a Linux host with
# systemd and passwordless sudo. It changes the host (users, /etc/smcp,
# /var/lib/smcp, systemd units): run it on a disposable machine.
#
#   scripts/ci-systemd.sh BIN_DIR STATIC_DIR WORK_DIR
#
#   BIN_DIR     smcpd, smcpctl and itest-client
#   STATIC_DIR  statically linked smcp-refserver (it runs in an empty root)
#   WORK_DIR    scratch directory (passwords, logs)
#
# Environment:
#   SMCP_SYSTEMD_PORT  harness listener port (admin: +1, metrics: +2;
#                      default 8643)
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bin=${1:?usage: ci-systemd.sh BIN_DIR STATIC_DIR WORK_DIR}
sbin=${2:?usage: ci-systemd.sh BIN_DIR STATIC_DIR WORK_DIR}
work=${3:?usage: ci-systemd.sh BIN_DIR STATIC_DIR WORK_DIR}
port=${SMCP_SYSTEMD_PORT:-8643}
mkdir -p "$work"

say() { printf '==> systemd: %s\n' "$*"; }
fail() {
  printf 'FAIL: systemd: %s\n' "$*" >&2
  sudo -n systemctl status smcpd.service --no-pager -l >&2 || true
  sudo -n journalctl -u smcpd.service -n 200 --no-pager >&2 || true
  if [ -d /sys/kernel/security/apparmor ]; then
    sudo -n journalctl -k -n 50 --no-pager -g 'apparmor="DENIED"' >&2 || true
  fi
  exit 1
}

state_root=/var/lib/smcp/state
inst=$state_root/gw
cfg=/etc/smcp/smcp.toml
share=/srv/smcp-itest-share
as_core() { sudo -n -u smcp-core env XDG_RUNTIME_DIR=/run/smcp HOME=/var/lib/smcp/home/smcp-core "$@"; }

say "installing packaging/linux (install-enforced.sh --bin-dir)"
stage="$work/systemd-bin"
mkdir -p "$stage"
cp "$bin/smcpd" "$bin/smcpctl" "$stage/"
cp "$sbin/smcp-refserver" "$stage/"
sudo -n "$root/packaging/linux/install-enforced.sh" --bin-dir "$stage" | tee "$work/systemd-install.log" | grep -v '^present' || true
grep -q '^created file /etc/systemd/system/smcpd.service\|^present file /etc/systemd/system/smcpd.service\|^updated file /etc/systemd/system/smcpd.service' "$work/systemd-install.log" \
  || fail "the installer did not install smcpd.service"
if [ -d /sys/kernel/security/apparmor ]; then
  sudo -n aa-status 2>/dev/null | grep -qx '   smcpd' || sudo -n aa-status 2>/dev/null | grep -q ' smcpd$' || fail "AppArmor profile smcpd is not loaded"
  echo "AppArmor profile smcpd is loaded"
fi

say "bootstrapping $inst as smcp-core"
marker="smcp-systemd-$(date +%s)"
sudo -n install -d -o root -g root -m 0755 "$share"
printf '%s\n' "$marker" | sudo -n tee "$share/hello.txt" >/dev/null
sudo -n chmod 0644 "$share/hello.txt"
sudo -n install -o smcp-core -g smcp -m 0600 "$work/admin.pw" "$state_root/admin.pw"
sudo -n install -o smcp-core -g smcp -m 0600 "$work/approver.pw" "$state_root/approver.pw"
sudo -n rm -rf "$inst"
as_core /usr/local/bin/smcpctl bootstrap --dir "$inst" --port "$port" --admin-port "$((port + 1))" --notify off \
  --refserver /usr/local/bin/smcp-refserver --sandbox "$share" \
  --admin-password-file "$state_root/admin.pw" --approver-password-file "$state_root/approver.pw" >/dev/null
sudo -n rm -f "$state_root/admin.pw" "$state_root/approver.pw"

# The unit reads /etc/smcp/smcp.toml; relative paths of the bootstrap
# configuration resolve against /etc/smcp, so they become absolute.
sudo -n cat "$inst/smcp.toml" | sed \
  -e "s|^dir = \"state\"|dir = \"$inst/state\"|" \
  -e "s|^file = \"policy.json\"|file = \"$inst/policy.json\"|" > "$work/smcp.toml"
grep -q "^dir = \"$inst/state\"" "$work/smcp.toml" || fail "the bootstrap configuration has no relative state directory to rewrite"
cat >> "$work/smcp.toml" <<EOF

[profile]
mode = "enforced"

[runtime]
sandbox = "podman"
cgroup_manager = "cgroupfs"

[[runtime.server]]
alias = "ref"
[[runtime.server.mount]]
source = "$share"
EOF
sudo -n install -o root -g smcp -m 0640 "$work/smcp.toml" "$cfg"
as_core /usr/local/bin/smcpctl config validate --config "$cfg" || fail "config validate"

say "starting smcpd.service"
sudo -n systemctl daemon-reload
sudo -n systemctl start smcpd.service || fail "systemctl start smcpd.service"
ready=""
for _ in $(seq 1 120); do
  if ! sudo -n systemctl is-active --quiet smcpd.service; then
    fail "smcpd.service is not active"
  fi
  if as_core /usr/local/bin/smcpctl health --config "$cfg" >"$work/systemd-health.json" 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done
[ -n "$ready" ] || { cat "$work/systemd-health.json" >&2; fail "smcpd.service did not become healthy within 60 s"; }
head -n 1 "$work/systemd-health.json"
grep -q '"profile": *"enforced"' "$work/systemd-health.json" || fail "health does not report the enforced profile"
grep -q '"launcher": *"podman"' "$work/systemd-health.json" || fail "health does not report the podman launcher"

mainpid=$(systemctl show -p MainPID --value smcpd.service)
echo "smcpd.service main PID $mainpid, user $(ps -o user= -p "$mainpid")"
[ "$(ps -o user= -p "$mainpid" | tr -d ' ')" = smcp-core ] || fail "smcpd does not run as smcp-core"
if [ -d /sys/kernel/security/apparmor ]; then
  label=$(sudo -n cat "/proc/$mainpid/attr/current")
  echo "smcpd AppArmor label: $label"
  [ "$label" = "smcpd (enforce)" ] || fail "smcpd is not confined by the smcpd AppArmor profile (label: $label)"
fi

say "a tool call through the sandbox"
# shellcheck disable=SC2024 # the copy belongs to the runner, only the read needs root
sudo -n cat "$inst/state/tls/ca.crt" > "$work/systemd-ca.crt"
SMCP_SIGNIN_PASSWORD=$(cat "$work/approver.pw")
export SMCP_SIGNIN_PASSWORD
"$bin/itest-client" -url "https://127.0.0.1:$port" -ca "$work/systemd-ca.crt" \
  -call ref_read_file -args '{"path":"hello.txt"}' -expect "$marker" || fail "tool call through smcpd.service"
as_core podman ps --filter label=smcp.managed=1 --format '{{.Names}} {{.Status}}' | tee "$work/systemd-containers.txt"
grep -q '^smcp-ref-' "$work/systemd-containers.txt" || fail "the reference server does not run in a Podman container of smcp-core"
as_core /usr/local/bin/smcpctl runtime instances --config "$cfg" | grep -q '"alias": *"ref"' || fail "runtime instances lacks ref"

say "unit hardening in effect"
systemctl show smcpd.service -p User -p ProtectSystem -p ProtectHome -p PrivateTmp -p NoNewPrivileges \
  -p RestrictSUIDSGID -p ProtectKernelTunables -p ProtectControlGroups -p AppArmorProfile -p Delegate --no-pager
if command -v systemd-analyze >/dev/null 2>&1; then
  sudo -n systemd-analyze security smcpd.service --no-pager 2>/dev/null | tail -n 1 || true
fi

say "stopping smcpd.service"
sudo -n systemctl stop smcpd.service
if sudo -n systemctl is-active --quiet smcpd.service; then fail "smcpd.service still active after stop"; fi
as_core /usr/local/bin/smcpctl journal verify --config "$cfg" || fail "journal verify after stop"
sudo -n grep -rqs '"instance_launched"' "$inst/state/journal" || fail "no instance_launched evidence in the journal"
sudo -n systemctl disable --quiet smcpd.service
say "passed"
