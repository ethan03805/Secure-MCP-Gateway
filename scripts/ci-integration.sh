#!/usr/bin/env bash
# End-to-end check of the built binaries, as an operator would run them:
# bootstrap a fresh instance in a temporary directory, start smcpd, drive a
# real MCP client through OAuth (PKCE, sign-in form) and a tool call, stop
# the daemon and verify the evidence journal. On Linux it also checks the
# enforced-profile prerequisites (Podman, nftables).
#
# Used by the "linux-integration" CI job; runs locally too:
#   scripts/ci-integration.sh
#
# Environment:
#   SMCP_ITEST_DIR        work directory (default: a new temporary directory)
#   SMCP_REQUIRE_PREREQS  1 to fail when Podman or nftables is missing (CI on Linux)
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
# bootstrap finds smcp-refserver next to smcpctl and writes its absolute
# path into the example configuration.
(cd "$root" && go build -trimpath -o "$bin/" ./cmd/smcpd ./cmd/smcpctl ./cmd/smcp-refserver ./scripts/itest-client)

new_password() {
  local p
  p=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
  [ "${#p}" -ge 12 ] || p="itest-password-$RANDOM$RANDOM"
  printf '%s' "$p"
}

say "Bootstrapping a new instance in $inst (non-interactive)"
mkdir -p "$inst"
# Passwords come from protected files, never from argv or the environment
# (SR-7.5-2). Harnesses sign in as the Session Approver (FR-2.23).
(umask 077 && new_password > "$work/admin.pw" && new_password > "$work/approver.pw")
"$bin/smcpctl" bootstrap --dir "$inst" \
  --admin-password-file "$work/admin.pw" --approver-password-file "$work/approver.pw"
cfg="$inst/smcp.toml"
[ -f "$cfg" ] || fail "bootstrap did not write $cfg"
"$bin/smcpctl" config validate --config "$cfg"

sandbox="$inst/sandbox"
marker="smcp-itest-$(date +%s)"
printf '%s\n' "$marker" > "$sandbox/hello.txt"

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
# The example configuration serves the sandbox through the bundled
# reference server (alias "ref"), whose paths are relative to its root.
SMCP_SIGNIN_PASSWORD=$(cat "$work/approver.pw")
export SMCP_SIGNIN_PASSWORD
read_marker() {
  "$bin/itest-client" -url "$public_url" -ca "$ca" \
    -call ref_read_file -args '{"path":"hello.txt"}' -expect "$marker"
}
read_marker || { cat "$log" >&2; fail "MCP client flow (ref_read_file)"; }
"$bin/itest-client" -url "$public_url" -ca "$ca" \
  -call ref_list_files -args '{"path":"."}' -expect "hello.txt" \
  || { cat "$log" >&2; fail "MCP client flow (ref_list_files)"; }

say "Emergency stop refuses tool calls; resume restores them"
"$bin/smcpctl" stop --config "$cfg" --reason "integration test"
if read_marker >"$work/stopped-call.log" 2>&1; then
  cat "$work/stopped-call.log" >&2
  fail "a tool call succeeded during emergency stop"
fi
# The endpoint fails closed: 503 before authentication, or EMERGENCY_STOP.
grep -qE 'status 503|EMERGENCY_STOP' "$work/stopped-call.log" \
  || { cat "$work/stopped-call.log" >&2; fail "call during emergency stop failed for another reason"; }
echo "refused during emergency stop: $(tail -n1 "$work/stopped-call.log")"
"$bin/smcpctl" resume --config "$cfg"
read_marker || { cat "$log" >&2; fail "tool call after resume"; }

# Features the gateway does not provide yet: probe the CLI and report.
for sub in backup restore; do
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
if "$bin/smcpd" -h 2>&1 | grep -q -- "-profile"; then
  say "smcpd has a -profile flag; the enforced profile is not exercised by this script yet"
else
  skip "enforced profile (Podman sandbox, nftables egress): not implemented in smcpd yet"
fi

echo
echo "Integration run complete. Work directory: $work"
if [ "${#skipped[@]}" -gt 0 ]; then
  echo "Skipped (${#skipped[@]}):"
  printf '  - %s\n' "${skipped[@]}"
fi
