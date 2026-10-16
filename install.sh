#!/bin/sh
# Install smcpd and smcpctl from a GitHub release of Secure MCP Gateway.
#
#   curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh
#   sh install.sh --version v0.1.0 --dir "$HOME/.local/bin"
#
# The script detects the OS (linux, darwin) and architecture (amd64, arm64),
# downloads the release archive and its checksum file, verifies the SHA-256
# checksum, and installs the binaries. It installs to ~/.local/bin unless
# --dir is given. It never runs sudo on its own: when the target directory
# is not writable it stops and prints the command to run.
#
# Options:
#   --version <tag>   release tag to install (default: latest release)
#   --dir <path>      installation directory (default: $HOME/.local/bin)
#   --repo <o/r>      GitHub repository (default: ethan03805/Secure-MCP-Gateway)
#   --help            show this help
set -eu

REPO="ethan03805/Secure-MCP-Gateway"
VERSION=""
DIR="${SMCP_INSTALL_DIR:-$HOME/.local/bin}"
PROJECT="smcp"

usage() {
  cat <<'USAGE'
usage: install.sh [--version <tag>] [--dir <path>] [--repo <owner/name>]

Downloads a Secure MCP Gateway release for this OS and architecture,
verifies its SHA-256 checksum and installs smcpd and smcpctl.

  --version <tag>   release tag to install (default: latest release)
  --dir <path>      installation directory (default: $HOME/.local/bin)
  --repo <o/r>      GitHub repository (default: ethan03805/Secure-MCP-Gateway)
USAGE
}
err() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
say() { printf 'install.sh: %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || err "--version needs a value"; VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --dir) [ $# -ge 2 ] || err "--dir needs a value"; DIR="$2"; shift 2 ;;
    --dir=*) DIR="${1#*=}"; shift ;;
    --repo) [ $# -ge 2 ] || err "--repo needs a value"; REPO="$2"; shift 2 ;;
    --repo=*) REPO="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "unknown option: $1" ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || err "$1 is required"; }
need uname
need tar
need mktemp

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
  latest_url() { curl -fsSLI --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q --https-only -O "$2" "$1"; }
  latest_url() { wget --https-only -q -S --spider "$1" 2>&1 | sed -n 's/^ *Location: //p' | tail -n1 | tr -d '\r'; }
else
  err "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
  sha256() { openssl dgst -sha256 "$1" | sed 's/^.*= //'; }
else
  err "sha256sum, shasum or openssl is required to verify the download"
fi

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  *) err "unsupported operating system: $(uname -s) (supported: Linux, macOS)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) err "unsupported architecture: $(uname -m) (supported: amd64, arm64)" ;;
esac

if [ -z "$VERSION" ]; then
  url=$(latest_url "https://github.com/$REPO/releases/latest") || err "could not resolve the latest release"
  VERSION="${url##*/}"
  case "$VERSION" in
    v[0-9]*) ;;
    *) err "could not determine the latest release (got '$VERSION'); pass --version" ;;
  esac
fi
case "$VERSION" in
  v*) ;;
  *) VERSION="v$VERSION" ;;
esac
NUM="${VERSION#v}"

ARCHIVE="${PROJECT}_${NUM}_${OS}_${ARCH}.tar.gz"
SUMS="${PROJECT}_${NUM}_checksums.txt"
BASE="https://github.com/$REPO/releases/download/$VERSION"

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t smcp)
trap 'rm -rf "$TMP"' EXIT INT TERM

say "downloading $ARCHIVE ($VERSION)"
fetch "$BASE/$ARCHIVE" "$TMP/$ARCHIVE" || err "download failed: $BASE/$ARCHIVE"
fetch "$BASE/$SUMS" "$TMP/$SUMS" || err "download failed: $BASE/$SUMS"

want=$(awk -v f="$ARCHIVE" '$2 == f || $2 == "*" f { print $1 }' "$TMP/$SUMS")
[ -n "$want" ] || err "$ARCHIVE is not listed in $SUMS"
got=$(sha256 "$TMP/$ARCHIVE")
[ "$want" = "$got" ] || err "checksum mismatch for $ARCHIVE: expected $want, got $got"
say "checksum verified ($got)"

mkdir -p "$TMP/x"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP/x"

if ! mkdir -p "$DIR" 2>/dev/null || [ ! -w "$DIR" ]; then
  say "$DIR is not writable by $(id -un)."
  say "Either choose a directory you own (--dir \"\$HOME/.local/bin\"), or install as root after reviewing the files:"
  say "  sudo install -m 0755 $TMP/x/smcpd $TMP/x/smcpctl $DIR/"
  trap - EXIT INT TERM
  say "(the extracted files are kept in $TMP/x for that command)"
  exit 1
fi

installed=""
for b in smcpd smcpctl smcp-refserver; do
  if [ -f "$TMP/x/$b" ]; then
    cp "$TMP/x/$b" "$DIR/$b.tmp.$$"
    chmod 0755 "$DIR/$b.tmp.$$"
    mv -f "$DIR/$b.tmp.$$" "$DIR/$b"
    installed="$installed $b"
  fi
done
[ -n "$installed" ] || err "the archive contains no binaries"
say "installed$installed to $DIR"

case ":$PATH:" in
  *":$DIR:"*) ;;
  *) say "$DIR is not on PATH; add it, for example: export PATH=\"$DIR:\$PATH\"" ;;
esac
say "next: smcpctl bootstrap --dir ~/smcp   (see README.md)"
