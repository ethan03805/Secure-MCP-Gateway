#!/usr/bin/env bash
# Kernel-level check of the Egress Broker (E-18): builds the egress test
# binary, then runs TestNetnsEnforcement as root. The test creates a
# network namespace with a veth pair, attaches it to the broker (which
# installs nftables rules inside the namespace) and checks that direct
# egress is blocked while brokered egress to a granted local HTTP server
# works. No Internet access is used.
#
# Used by the "linux-integration" CI job; runs on any Linux host with sudo,
# iproute2 and nf_tables:
#   scripts/ci-egress-netns.sh
#
# Environment:
#   SMCP_ITEST_DIR  work directory (default: a new temporary directory)
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP: the egress netns test needs Linux (network namespaces, nftables)"
  exit 0
fi
work=${SMCP_ITEST_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/smcp-egress.XXXXXX")}
mkdir -p "$work"
bin="$work/egress.test"

echo "==> Building the egress test binary"
(cd "$root" && go test -c -o "$bin" ./internal/egress)

sudo_cmd=()
if [ "$(id -u)" -ne 0 ]; then
  sudo_cmd=(sudo -n)
fi
if command -v nft >/dev/null 2>&1; then nft --version; fi

echo "==> Running TestNetnsEnforcement as root"
(cd "$work" && "${sudo_cmd[@]}" env SMCP_EGRESS_NETNS_TEST=1 "$bin" \
  -test.run '^TestNetnsEnforcement$' -test.v -test.count=1)
