#!/usr/bin/env bash
# Follows the install guide as written (FR-18.1): extracts the shell block
# marked `<!-- ci-install-guide: NAME -->` from docs/install.md and runs it,
# unchanged, with bash -e in an empty directory of a clean account. A step
# that fails, or a block that is missing, fails the run, so the guide cannot
# drift from what works.
#
# It installs a release into ~/.local/bin and a user service (launchd or
# systemd): run it on a disposable CI runner (job install-guide; the Go test
# cmd/smcpctl.TestInstallGuideWalkthrough calls it).
#
#   scripts/ci-install-guide.sh NAME WORK_DIR
set -euo pipefail

name=${1:?usage: ci-install-guide.sh NAME WORK_DIR}
work=${2:?usage: ci-install-guide.sh NAME WORK_DIR}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
guide="$root/docs/install.md"
mkdir -p "$work"

say() { printf '==> install-guide: %s\n' "$*"; }
fail() {
  printf 'FAIL: install-guide: %s\n' "$*" >&2
  if [ "$(uname -s)" = Linux ] && sudo -n true 2>/dev/null; then
    sudo -n systemctl status smcpd.service --no-pager -l >&2 || true
    sudo -n journalctl -u smcpd.service -n 80 --no-pager >&2 || true
    sudo -n tail -n 80 /var/log/smcp/smcpd.log >&2 || true
  fi
  exit 1
}

# The block: the first ```sh fence after the marker line, up to its closing fence.
awk -v m="<!-- ci-install-guide: $name -->" '
  $0 == m { found = 1; next }
  found == 1 && /^```sh$/ { found = 2; next }
  found == 2 && /^```$/ { exit }
  found == 2 { print }
' "$guide" > "$work/guide-$name.sh"
[ -s "$work/guide-$name.sh" ] || fail "no block marked ci-install-guide: $name in docs/install.md"

case "$(uname -s)" in
  Linux)
    os=linux
    # A CI runner has no login session: lingering starts the user manager
    # and the variables below are what a desktop session sets.
    uid=$(id -u)
    if [ ! -S "/run/user/$uid/bus" ]; then
      sudo -n loginctl enable-linger "$(id -un)" 2>/dev/null || true
      for _ in $(seq 1 40); do [ -S "/run/user/$uid/bus" ] && break; sleep 0.5; done
    fi
    [ -S "/run/user/$uid/bus" ] || fail "no systemd user manager for $(id -un)"
    export XDG_RUNTIME_DIR="/run/user/$uid"
    export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
    ;;
  Darwin) os=darwin ;;
  *) fail "the walkthrough is for macOS and Linux" ;;
esac
for p in "$HOME/.local/bin/smcpctl" "$HOME/.local/bin/smcpd"; do
  [ ! -e "$p" ] || fail "$p exists already; run on a clean account"
done

say "running the '$name' block of docs/install.md as written ($os)"
cat "$work/guide-$name.sh"
run="$work/run"
mkdir -p "$run"
(cd "$run" && bash -euxo pipefail "$work/guide-$name.sh") 2>&1 | tee "$work/guide-$name.log" || fail "a step of the guide failed (see above)"
say "passed $name ($os)"
