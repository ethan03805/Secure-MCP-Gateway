#!/usr/bin/env bash
# Enforced profile under real systemd: installs packaging/linux with
# install-enforced.sh, bootstraps an instance as smcp-core, starts
# smcpd.service with runtime.run_as = "smcp-srv", checks health, makes tool
# calls that run in rootless Podman containers of the separate server
# identity smcp-srv (CP-46), delivers an S3 secret file to a server in an
# auto user namespace, stops the service and verifies the evidence journal.
# When AppArmor is enabled it also checks that smcpd runs confined by the
# shipped profile and that the servers run confined by smcp-server, which
# denies a read their own permissions allow.
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
probe_bin=/srv/smcp-itest-bin

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

say "server identity smcp-srv (CP-46)"
srv_uid=$(id -u smcp-srv)
as_srv() {
  sudo -n -u smcp-srv env XDG_RUNTIME_DIR="/run/user/$srv_uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$srv_uid/bus" \
    HOME=/var/lib/smcp/home/smcp-srv "$@"
}
[ "$(id -gn smcp-srv)" = smcp-srv ] || fail "smcp-srv's primary group is $(id -gn smcp-srv), not smcp-srv"
if id -nG smcp-srv | tr ' ' '\n' | grep -qx smcp; then fail "smcp-srv is a member of group smcp (it could read /etc/smcp)"; fi
[ -e /var/lib/systemd/linger/smcp-srv ] || fail "lingering is not enabled for smcp-srv"
sudo -n test -S "/run/user/$srv_uid/bus" || fail "smcp-srv has no user manager bus"
sudo -n test -f /etc/sudoers.d/smcp-srv || fail "no sudoers rule for smcp-srv"
sudo -n test -f /etc/systemd/system/smcpd.service.d/smcp-srv.conf || fail "no smcpd.service drop-in for smcp-srv"
podman_path=$(command -v podman)
sudo -n -u smcp-core env -i PATH=/usr/bin:/bin XDG_RUNTIME_DIR="/run/user/$srv_uid" HOME=/var/lib/smcp/home/smcp-srv \
  sudo -n -E -u smcp-srv -- "$podman_path" --version || fail "smcp-core cannot run Podman as smcp-srv"
if sudo -n -u smcp-core sudo -n -u smcp-srv -- /bin/true 2>/dev/null; then fail "the sudoers rule lets smcp-core run more than Podman as smcp-srv"; fi
if sudo -n -u smcp-srv test -r /etc/smcp; then fail "smcp-srv can read /etc/smcp"; fi
echo "smcp-srv: uid $srv_uid, group $(id -gn smcp-srv), subuid $(grep '^smcp-srv:' /etc/subuid)"

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
# The sandbox probe (statically linked) as a second server.
sudo -n install -d -o root -g root -m 0755 "$probe_bin"
sudo -n install -o root -g root -m 0755 "$sbin/sandbox-probe" "$probe_bin/sandbox-probe"
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$work/vault-pass"
sudo -n install -o smcp-core -g smcp -m 0600 "$work/vault-pass" "$inst/vault-pass"
secret_value="s3-secret-$(date +%s)-$RANDOM"
secret_sum="sha256:$(printf '%s' "$secret_value" | sha256sum | cut -d' ' -f1)"
cat > "$work/systemd-policy.json" <<'EOF'
{
  "revision": "r1",
  "framework_profiles": { "dev": { "templates": ["sandbox"], "default_template": "sandbox" } },
  "templates": {
    "sandbox": {
      "description": "Reference server and the sandbox probe",
      "rules": [
        { "id": "ref", "server": "ref", "tools": ["echo", "time_now", "list_files", "read_file"] },
        { "id": "probe", "server": "probe", "tools": ["read_file", "file_sha256", "identity"] }
      ]
    }
  }
}
EOF
sudo -n install -o smcp-core -g smcp -m 0600 "$work/systemd-policy.json" "$inst/policy.json"
cat > "$work/secret-use.json" <<'EOF'
{
  "revision": "ci-1",
  "slots": [ { "server": "probe", "name": "token", "modes": ["S3"], "file_env": "PROBE_TOKEN_FILE" } ],
  "policies": [ { "id": "probe-token", "secret": "probe-token", "server": "probe", "slot": "token", "mode": "S3", "tools": ["*"], "purpose": "ci secret file" } ]
}
EOF
sudo -n install -o smcp-core -g smcp -m 0600 "$work/secret-use.json" "$inst/secret-use.json"

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
run_as = "smcp-srv"
shared_dir = "/var/lib/smcp/srv"

[[runtime.server]]
alias = "ref"
[[runtime.server.mount]]
source = "$share"

[[server]]
alias = "probe"
command = "$probe_bin/sandbox-probe"

[[runtime.server]]
alias = "probe"

[secrets]
key_source = "passphrase"
passphrase_file = "$inst/vault-pass"
EOF
sudo -n install -o root -g smcp -m 0640 "$work/smcp.toml" "$cfg"
as_core /usr/local/bin/smcpctl config validate --config "$cfg" || fail "config validate"
as_core /usr/local/bin/smcpctl secrets init --key-source passphrase --passphrase-file "$inst/vault-pass" --config "$cfg" >/dev/null || fail "secrets init"

wait_healthy() {
  local ready=""
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
}

say "starting smcpd.service"
sudo -n systemctl daemon-reload
sudo -n systemctl start smcpd.service || fail "systemctl start smcpd.service"
wait_healthy

say "an S3 secret for the probe (userns = \"auto\", run as smcp-srv)"
printf '%s' "$secret_value" | as_core /usr/local/bin/smcpctl secrets set probe-token --value-file - --config "$cfg" >/dev/null || fail "secrets set"
printf 'use_policy_file = "%s"\n' "$inst/secret-use.json" >> "$work/smcp.toml"
sudo -n install -o root -g smcp -m 0640 "$work/smcp.toml" "$cfg"
as_core /usr/local/bin/smcpctl config validate --config "$cfg" || fail "config validate with the Secret Use Policy"
sudo -n systemctl restart smcpd.service || fail "systemctl restart smcpd.service"
wait_healthy
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
as_srv podman ps --filter label=smcp.managed=1 --format '{{.Names}} {{.Status}}' | tee "$work/systemd-containers.txt"
grep -q '^smcp-ref-' "$work/systemd-containers.txt" || fail "the reference server does not run in a Podman container of smcp-srv"
grep -q '^smcp-probe-' "$work/systemd-containers.txt" || fail "the probe does not run in a Podman container of smcp-srv"
if [ -n "$(as_core podman ps -a -q --filter label=smcp.managed=1 2>/dev/null)" ]; then
  fail "server containers run under smcp-core's Podman"
fi
as_core /usr/local/bin/smcpctl runtime instances --config "$cfg" | grep -q '"alias": *"ref"' || fail "runtime instances lacks ref"

say "server processes run under smcp-srv's subordinate UIDs, not smcp-core"
read -r srv_start srv_count < <(awk -F: '$1 == "smcp-srv" { print $2, $3; exit }' /etc/subuid)
core_uid=$(id -u smcp-core)
while read -r name _ <&3; do
  cpid=$(as_srv podman inspect --format '{{.State.Pid}}' "$name")
  cuid=$(ps -o uid= -p "$cpid" | tr -d ' ')
  echo "$name: main PID $cpid, host UID $cuid"
  [ "$cuid" != "$core_uid" ] || fail "$name runs as smcp-core"
  [ "$cuid" -ge "$srv_start" ] && [ "$cuid" -lt "$((srv_start + srv_count))" ] || fail "$name runs as UID $cuid, outside smcp-srv's range $srv_start+$srv_count"
  if [ -d /sys/kernel/security/apparmor ]; then
    clabel=$(sudo -n cat "/proc/$cpid/attr/current")
    echo "$name: AppArmor label $clabel"
    [ "$clabel" = "smcp-server (enforce)" ] || fail "$name is not confined by the smcp-server AppArmor profile (label: $clabel)"
  fi
done 3< "$work/systemd-containers.txt"
conmon_users=$(ps -o user= -C conmon | sort -u | tr '\n' ' ')
echo "conmon processes run as: $conmon_users"
case " $conmon_users" in *" smcp-core "*) fail "a container monitor runs as smcp-core" ;; esac

probe_call() { # tool, args, expected substring
  "$bin/itest-client" -url "https://127.0.0.1:$port" -ca "$work/systemd-ca.crt" -call "$1" -args "$2" -expect "$3" \
    || fail "probe_$1 $2 (expected \"$3\")"
}
say "the probe reads its S3 secret file as a subordinate UID of smcp-srv"
probe_call probe_file_sha256 '{"path":"/smcp/secrets/token"}' "$secret_sum"
sudo -n find /run/smcp -maxdepth 3 -name 'probe-*' -exec getfacl -p {} + 2>/dev/null || true
if [ -d /sys/kernel/security/apparmor ]; then
  say "the AppArmor profile smcp-server denies a read the container allows"
  probe_call probe_read_file '{"path":"/proc/self/environ"}' "permission denied"
  probe_call probe_read_file '{"path":"/proc/self/status"}' "NoNewPrivs:"
  sudo -n journalctl -k --no-pager -g 'apparmor="DENIED".*profile="smcp-server"' | tail -n 3 || true
fi

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
