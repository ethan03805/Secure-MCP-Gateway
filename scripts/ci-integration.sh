#!/usr/bin/env bash
# End-to-end check of the built binaries, as an operator would run them:
# bootstrap a fresh instance in a temporary directory, start smcpd, drive a
# real MCP client through OAuth (PKCE, sign-in form) and a tool call, stop
# the daemon and verify the evidence journal. On Linux with Podman it then
# runs a second instance in the enforced profile and proves that a sandboxed
# backend cannot open network sockets or write outside its mount.
#
# Used by the "linux-integration" CI job; runs locally too:
#   scripts/ci-integration.sh
#
# Environment:
#   SMCP_ITEST_DIR        work directory (default: a new temporary directory)
#   SMCP_REQUIRE_PREREQS  1 to fail when Podman or nftables is missing (CI on Linux)
#   SMCP_FS_SERVER_PKG    npm package for the example filesystem server
#                         (default @modelcontextprotocol/server-filesystem)
#   SMCP_ENFORCED_MODE    profile mode of the sandboxed instance (default
#                         enforced; "auto" on hosts without systemd or an LSM)
#   SMCP_ENFORCED_CGROUP_MANAGER  runtime.cgroup_manager for that instance
#   SMCP_RUN_INSTALLER    1 to run packaging/linux/install-enforced.sh twice
#                         with sudo (default: SMCP_REQUIRE_PREREQS)
#
# Features that the current build does not provide are reported under
# "Skipped" and do not fail the run.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=${SMCP_ITEST_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/smcp-itest.XXXXXX")}
mkdir -p "$work"
bin="$work/bin"
inst="$work/instance"
log="$work/smcpd.log"
skipped=()
pid=""

say() { printf '==> %s\n' "$*"; }
skip() { skipped+=("$1"); printf 'SKIP: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

say "Building smcpd, smcpctl and the test client into $bin"
mkdir -p "$bin"
(cd "$root" && go build -trimpath -o "$bin/" ./cmd/smcpd ./cmd/smcpctl ./scripts/itest-client)
if [ -d "$root/cmd/smcp-refserver" ]; then
  (cd "$root" && go build -trimpath -o "$bin/" ./cmd/smcp-refserver)
else
  skip "smcp-refserver: cmd/smcp-refserver does not exist yet"
fi

new_password() {
  local p
  p=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
  [ "${#p}" -ge 12 ] || p="itest-password-$RANDOM$RANDOM"
  printf '%s' "$p"
}

say "Bootstrapping a new instance in $inst (non-interactive)"
mkdir -p "$inst"
# Builds that take passwords from files (and sign harnesses in with a
# separate Session Approver account) are bootstrapped through password
# files; older builds read SMCP_ADMIN_PASSWORD and sign in as the admin.
bootstrap_help=$("$bin/smcpctl" bootstrap -h 2>&1 || true)
if grep -q -- '-admin-password-file' <<<"$bootstrap_help"; then
  (umask 077 && new_password > "$work/admin.pw" && new_password > "$work/approver.pw")
  "$bin/smcpctl" bootstrap --dir "$inst" \
    --admin-password-file "$work/admin.pw" --approver-password-file "$work/approver.pw"
  signin_user="approver"
  signin_password=$(cat "$work/approver.pw")
else
  signin_user="admin"
  signin_password=$(new_password)
  SMCP_ADMIN_PASSWORD="$signin_password" "$bin/smcpctl" bootstrap --dir "$inst"
fi
cfg="$inst/smcp.toml"
[ -f "$cfg" ] || fail "bootstrap did not write $cfg"
"$bin/smcpctl" config validate --config "$cfg"

sandbox="$inst/sandbox"
marker="smcp-itest-$(date +%s)"
printf '%s\n' "$marker" > "$sandbox/hello.txt"

# Pin the example server package when requested; older bootstrap templates
# launch it through npx.
if [ -n "${SMCP_FS_SERVER_PKG:-}" ]; then
  sed -i.bak "s#\"@modelcontextprotocol/server-filesystem\"#\"$SMCP_FS_SERVER_PKG\"#" "$cfg" && rm -f "$cfg.bak"
fi

address=$(sed -n 's/^address *= *"\(.*\)"/\1/p' "$cfg" | head -n1)
public_url=$(sed -n 's/^public_url *= *"\(.*\)"/\1/p' "$cfg" | head -n1)
[ -n "$public_url" ] || fail "no public_url in $cfg"

say "Starting smcpd on $address"
"$bin/smcpd" --config "$cfg" >"$log" 2>&1 &
pid=$!
ready=""
for _ in $(seq 1 120); do
  if ! kill -0 "$pid" 2>/dev/null; then
    cat "$log" >&2
    fail "smcpd exited during startup"
  fi
  if "$bin/smcpctl" health --config "$cfg" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done
[ -n "$ready" ] || { cat "$log" >&2; fail "smcpd did not become healthy within 60 s"; }
"$bin/smcpctl" health --config "$cfg"

say "Driving an MCP client through OAuth and tool calls"
ca="$inst/state/tls/ca.crt"
[ -f "$ca" ] || fail "CA certificate not found at $ca"
# The bundled reference server (alias "ref") takes paths relative to its
# root; the npx filesystem server (alias "fs") takes absolute paths.
if grep -q '^alias = "ref"' "$cfg"; then
  read_tool=ref_read_file read_path=hello.txt
  list_tool=ref_list_files list_path=.
else
  read_tool=fs_read_text_file read_path="$sandbox/hello.txt"
  list_tool=fs_list_directory list_path="$sandbox"
fi
export SMCP_ADMIN_PASSWORD="$signin_password"
"$bin/itest-client" -url "$public_url" -ca "$ca" -username "$signin_user" \
  -call "$read_tool" -args "{\"path\":\"$read_path\"}" -expect "$marker" \
  || { cat "$log" >&2; fail "MCP client flow ($read_tool)"; }
"$bin/itest-client" -url "$public_url" -ca "$ca" -username "$signin_user" \
  -call "$list_tool" -args "{\"path\":\"$list_path\"}" -expect "hello.txt" \
  || { cat "$log" >&2; fail "MCP client flow ($list_tool)"; }

# Features the gateway does not provide yet: probe the CLI and report.
for sub in stop backup restore; do
  out=$("$bin/smcpctl" "$sub" --help 2>&1 || true)
  case "$out" in
    "usage: smcpctl <command>"*) skip "smcpctl $sub: not implemented in this build" ;;
    *) say "smcpctl $sub is available (not exercised by this script yet)" ;;
  esac
done

say "Stopping smcpd"
kill -TERM "$pid"
wait "$pid" || true
pid=""

say "Verifying the evidence journal"
"$bin/smcpctl" journal verify --config "$cfg"

say "Enforced-profile prerequisites"
if [ "$(uname -s)" = "Linux" ]; then
  if command -v podman >/dev/null 2>&1; then
    podman --version
  elif [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
    fail "podman is not installed"
  else
    skip "podman: not installed"
  fi
  if ! command -v nft >/dev/null 2>&1 && [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
    say "nft not found; installing nftables"
    sudo apt-get install -y -qq nftables >/dev/null
  fi
  if command -v nft >/dev/null 2>&1; then
    nft --version
    if sudo -n nft list ruleset >/dev/null; then
      echo "nftables: ruleset readable with sudo ($(sudo -n nft list ruleset | grep -c '^table') tables)"
    elif [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
      fail "sudo nft list ruleset failed"
    else
      skip "nftables: sudo nft list ruleset not permitted"
    fi
  elif [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
    fail "nft is not installed"
  else
    skip "nftables: nft not installed"
  fi
else
  skip "enforced-profile prerequisites: Podman and nftables are checked on Linux only"
fi

# --- Enforced profile: servers in rootless Podman (E-15, E-16, E-17) --------
# A second instance runs with [profile] mode = "enforced" and
# [runtime] sandbox = "podman". The reference server and a hostile probe
# server run in the sandbox; the probe must fail to open network sockets and
# to write outside its writable grant.
enforced_section() {
  local mode=${SMCP_ENFORCED_MODE:-enforced}
  local einst="$work/enforced" share="$work/enforced-share" rw="$work/enforced-rw" sbin="$bin/static"
  local elog="$work/smcpd-enforced.log"
  say "Enforced profile: building statically linked servers into $sbin"
  mkdir -p "$sbin"
  (cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$sbin/" ./cmd/smcp-refserver ./scripts/sandbox-probe)

  # Rootless Podman delegates cgroup controllers through the user's systemd
  # instance. A CI runner may have no user session; lingering starts one.
  if [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ] && ! podman info --format '{{.Host.CgroupControllers}}' 2>/dev/null | grep -q memory; then
    say "Enforced profile: no delegated memory controller; enabling a systemd user session for $(id -un)"
    sudo -n loginctl enable-linger "$(id -un)" || true
    for _ in $(seq 1 20); do [ -S "/run/user/$(id -u)/bus" ] && break; sleep 0.5; done
    XDG_RUNTIME_DIR="/run/user/$(id -u)"
    DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
    export XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS
    podman system migrate >/dev/null 2>&1 || true
    podman info --format 'cgroup manager {{.Host.CgroupManager}}, controllers {{.Host.CgroupControllers}}' || true
  fi

  say "Enforced profile: smcpctl runtime doctor"
  if ! "$bin/smcpctl" runtime doctor; then
    podman info >&2 || true
    [ "$mode" = enforced ] && fail "enforced-profile prerequisites missing"
  fi

  say "Enforced profile: Go integration tests against real Podman"
  local strict=0
  [ "$mode" = enforced ] && strict=1
  (cd "$root" && CGO_ENABLED=0 SMCP_SANDBOX_IT=1 SMCP_SANDBOX_IT_STRICT=$strict \
    SMCP_SANDBOX_IT_CGROUP_MANAGER="${SMCP_ENFORCED_CGROUP_MANAGER:-}" \
    go test -count=1 -run Integration -v ./internal/sandbox/) || fail "sandbox integration tests"

  if [ "${SMCP_RUN_INSTALLER:-${SMCP_REQUIRE_PREREQS:-0}}" = 1 ] && sudo -n true 2>/dev/null; then
    say "Enforced profile: packaging/linux/install-enforced.sh (twice; the second run changes nothing)"
    sudo -n "$root/packaging/linux/install-enforced.sh" --no-start | tee "$work/install1.log"
    sudo -n "$root/packaging/linux/install-enforced.sh" --no-start | tee "$work/install2.log"
    if grep -q '^created\|^updated' "$work/install2.log"; then
      fail "second installer run changed the host"
    fi
  else
    skip "enforced installer: set SMCP_RUN_INSTALLER=1 with passwordless sudo to exercise it"
  fi

  mkdir -p "$einst" "$share" "$rw"
  # Instances run under subordinate UIDs: granted paths must be readable
  # (and the writable grant writable) by other users.
  chmod 755 "$share"
  chmod 777 "$rw"
  local emarker
  emarker="smcp-enforced-$(date +%s)"
  printf '%s\n' "$emarker" > "$share/hello.txt"
  chmod 644 "$share/hello.txt"
  if [ -f "$work/admin.pw" ]; then
    "$bin/smcpctl" bootstrap --dir "$einst" --port 8543 --admin-port 8544 --refserver "$sbin/smcp-refserver" --sandbox "$share" \
      --admin-password-file "$work/admin.pw" --approver-password-file "$work/approver.pw"
  else
    SMCP_ADMIN_PASSWORD="$signin_password" "$bin/smcpctl" bootstrap --dir "$einst" --port 8543 --admin-port 8544 \
      --refserver "$sbin/smcp-refserver" --sandbox "$share"
  fi
  local ecfg="$einst/smcp.toml" cgm_line=""
  if [ -n "${SMCP_ENFORCED_CGROUP_MANAGER:-}" ]; then
    cgm_line="cgroup_manager = \"$SMCP_ENFORCED_CGROUP_MANAGER\""
  fi
  cat >> "$ecfg" <<EOF

# Every itest-client run signs in again and opens a session.
[limits]
sessions_per_principal = 32

[profile]
mode = "$mode"

[runtime]
sandbox = "podman"
$cgm_line

[[runtime.server]]
alias = "ref"
[[runtime.server.mount]]
source = "$share"

[[server]]
alias = "probe"
command = "$sbin/sandbox-probe"
risk_classes = ["code-execution"]

[[runtime.server]]
alias = "probe"
[[runtime.server.mount]]
source = "$rw"
target = "/rw"
write = true
EOF
  cat > "$einst/policy.json" <<'EOF'
{
  "revision": "r1",
  "framework_profiles": { "dev": { "templates": ["sandbox"], "default_template": "sandbox" } },
  "templates": {
    "sandbox": {
      "description": "Reference server and the hostile sandbox probe",
      "rules": [
        { "id": "ref", "server": "ref", "tools": ["echo", "time_now", "list_files", "read_file"] },
        { "id": "probe", "server": "probe", "tools": ["echo", "net_connect", "write_file", "read_file", "identity"] }
      ]
    }
  }
}
EOF
  "$bin/smcpctl" config validate --config "$ecfg"
  "$bin/smcpctl" runtime spec --config "$ecfg" > "$work/launch-specs.json"
  grep -q '"--network=none"' "$work/launch-specs.json" || fail "launch specification lacks --network=none"
  grep -q '"--cap-drop=all"' "$work/launch-specs.json" || fail "launch specification lacks --cap-drop=all"

  local epublic
  epublic=$(sed -n 's/^public_url *= *"\(.*\)"/\1/p' "$ecfg" | head -n1)
  say "Enforced profile: starting smcpd ($mode)"
  "$bin/smcpd" --config "$ecfg" >"$elog" 2>&1 &
  pid=$!
  local up=""
  for _ in $(seq 1 120); do
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$elog" >&2
      fail "enforced smcpd exited during startup"
    fi
    if "$bin/smcpctl" health --config "$ecfg" >/dev/null 2>&1; then up=1; break; fi
    sleep 0.5
  done
  [ -n "$up" ] || { cat "$elog" >&2; fail "enforced smcpd did not become healthy within 60 s"; }
  "$bin/smcpctl" health --config "$ecfg" | tee "$work/enforced-health.json"
  if [ "$mode" = enforced ]; then
    grep -q '"profile": *"enforced"' "$work/enforced-health.json" || fail "health does not report the enforced profile"
    grep -q '"launcher": *"podman"' "$work/enforced-health.json" || fail "health does not report the podman launcher"
  fi
  "$bin/smcpctl" runtime instances --config "$ecfg" > "$work/instances.json"
  grep -q '"alias": *"probe"' "$work/instances.json" || fail "runtime instances lacks the probe"

  local eca="$einst/state/tls/ca.crt"
  ecall() { # tool, args, expected substring
    "$bin/itest-client" -url "$epublic" -ca "$eca" -username "$signin_user" -call "$1" -args "$2" -expect "$3" \
      || { cat "$elog" >&2; fail "enforced: $1 $2 (expected \"$3\")"; }
  }
  say "Enforced profile: the reference server works inside the sandbox"
  ecall ref_read_file '{"path":"hello.txt"}' "$emarker"
  say "Enforced profile: the probe cannot open network sockets"
  ecall probe_net_connect '{"address":"1.1.1.1:443"}' "blocked:"
  ecall probe_net_connect '{"address":"127.0.0.1:8543"}' "blocked:"
  ecall probe_net_connect '{"address":"127.0.0.1:8544"}' "blocked:"
  say "Enforced profile: the probe cannot write outside its writable grant"
  ecall probe_write_file "{\"path\":\"$work/escape.txt\",\"text\":\"x\"}" "blocked:"
  [ ! -e "$work/escape.txt" ] || fail "the probe wrote outside its mount"
  ecall probe_write_file "{\"path\":\"$share/escape.txt\",\"text\":\"x\"}" "blocked:"
  [ ! -e "$share/escape.txt" ] || fail "the probe wrote into a path granted only to another server"
  ecall probe_write_file '{"path":"/etc/escape","text":"x"}' "blocked:"
  ecall probe_write_file '{"path":"/smcp/bin/escape","text":"x"}' "blocked:"
  ecall probe_read_file "{\"path\":\"$einst/state/keys/admin.token\"}" "blocked:"
  ecall probe_write_file '{"path":"/rw/inside.txt","text":"ok"}' "wrote"
  [ -e "$rw/inside.txt" ] || fail "the writable grant did not reach the host"
  ecall probe_identity '{}' "NoNewPrivs:"$'\t'"1"
  ecall probe_identity '{}' "CapEff:"$'\t'"0000000000000000"

  say "Stopping the enforced smcpd"
  kill -TERM "$pid"
  wait "$pid" || true
  pid=""
  "$bin/smcpctl" journal verify --config "$ecfg"
  grep -rqs '"instance_launched"' "$einst/state/journal" || fail "no instance_launched evidence in the journal"
  if command -v podman >/dev/null && [ -n "$(podman ps -a --filter label=smcp.managed=1 -q)" ]; then
    podman ps -a --filter label=smcp.managed=1 >&2
    fail "server containers left behind after shutdown"
  fi
  say "Enforced profile: sandbox checks passed"
}

if [ "$(uname -s)" = "Linux" ] && command -v podman >/dev/null 2>&1; then
  enforced_section
elif [ "$(uname -s)" = "Linux" ] && [ "${SMCP_REQUIRE_PREREQS:-0}" = 1 ]; then
  fail "enforced profile: podman is not installed"
else
  skip "enforced profile (Podman sandbox): runs on Linux with rootless Podman only"
fi

echo
echo "Integration run complete. Work directory: $work"
if [ "${#skipped[@]}" -gt 0 ]; then
  echo "Skipped (${#skipped[@]}):"
  printf '  - %s\n' "${skipped[@]}"
fi
