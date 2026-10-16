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
#   SMCP_FS_SERVER_PKG    npm package for the example filesystem server
#                         (default @modelcontextprotocol/server-filesystem)
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

password=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
[ "${#password}" -ge 12 ] || password="itest-password-$RANDOM$RANDOM"
export SMCP_ADMIN_PASSWORD="$password"

say "Bootstrapping a new instance in $inst (non-interactive)"
mkdir -p "$inst"
"$bin/smcpctl" bootstrap --dir "$inst"
cfg="$inst/smcp.toml"
[ -f "$cfg" ] || fail "bootstrap did not write $cfg"
"$bin/smcpctl" config validate --config "$cfg"

sandbox="$inst/sandbox"
marker="smcp-itest-$(date +%s)"
printf '%s\n' "$marker" > "$sandbox/hello.txt"

# Pin the example server package when requested; the bootstrap template
# launches it through npx.
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
"$bin/itest-client" -url "$public_url" -ca "$ca" \
  -call fs_read_text_file -args "{\"path\":\"$sandbox/hello.txt\"}" -expect "$marker" \
  || { cat "$log" >&2; fail "MCP client flow"; }
"$bin/itest-client" -url "$public_url" -ca "$ca" \
  -call fs_list_directory -args "{\"path\":\"$sandbox\"}" -expect "hello.txt" \
  || { cat "$log" >&2; fail "MCP client flow (list_directory)"; }

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
