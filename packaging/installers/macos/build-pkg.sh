#!/usr/bin/env bash
# Builds the macOS command-line installer smcp_<version>_darwin_arm64.pkg
# (SRS FR-20.17, FR-20.21, FR-20.26, SR-4.11-2) with pkgbuild and
# productbuild. Runs on macOS only.
#
#   packaging/installers/macos/build-pkg.sh <version> <binary dir> <output dir>
#
# <binary dir> holds the darwin-arm64 release binaries, or is GoReleaser's
# dist directory with one <id>_darwin_arm64_v8.0/ directory per binary
# (`goreleaser build --single-target` with GOOS=darwin GOARCH=arm64, which
# `make installer-pkg` and .github/workflows/installers.yml run). The
# package installs, owned by root:wheel and not
# writable by the installing user:
#
#   /usr/local/lib/smcp/<binaries>          ad-hoc signed (FR-20.26)
#   /usr/local/lib/smcp/package-format      "pkg" (smcpctl uninstall/upgrade)
#   /usr/local/bin/<binaries>               symbolic links to the above
#   /usr/local/share/doc/smcp/              README, CHANGELOG, LICENSE, SBOM,
#                                           provenance and notices
#
# It has no pre- or post-install script: it creates no configuration,
# state, keys, launchd agent or account and starts nothing (FR-20.21);
# `smcpctl install` does that. The .pkg itself carries no signature
# (productsign with a Developer ID certificate is FR-20.29, deferred).
# When the desktop application exists, this package gains the application
# bundle in /Applications (FR-20.17).
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <version> <binary dir> <output dir>" >&2; exit 2; }
version=$1 bindir=$2 outdir=$3
[ "$(uname -s)" = Darwin ] || { echo "build-pkg.sh: pkgbuild runs on macOS only" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)

# The five commands of FR-20.17, and smcp-refserver, which `smcpctl
# bootstrap` and `smcpctl install` package as the example backend.
binaries=(smcpd smcpctl smcp-session smcp-stdio smcp-connect smcp-refserver)
identifier=io.github.ethan03805.smcp

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root=$work/root
install -d -m 0755 "$root/usr/local/lib/smcp" "$root/usr/local/bin" "$root/usr/local/share/doc/smcp"
for b in "${binaries[@]}"; do
	src=$bindir/$b
	[ -f "$src" ] || src=$(find "$bindir" -path "*/${b}_darwin_arm64*/$b" -type f 2>/dev/null | head -n1)
	[ -n "$src" ] && [ -f "$src" ] || { echo "build-pkg.sh: $b missing in $bindir" >&2; exit 1; }
	file "$src" | grep -q 'arm64' || { echo "build-pkg.sh: $src is not an arm64 executable" >&2; exit 1; }
	install -m 0755 "$src" "$root/usr/local/lib/smcp/$b"
	# Ad-hoc signature (FR-20.26). Go's linker already signs darwin-arm64
	# binaries ad hoc; signing again makes the requirement independent of
	# the toolchain and replaces a linker signature with a full one.
	codesign --force --sign - --timestamp=none "$root/usr/local/lib/smcp/$b"
	codesign --verify --strict "$root/usr/local/lib/smcp/$b"
	ln -s "../lib/smcp/$b" "$root/usr/local/bin/$b"
done
install -m 0644 "$here/package-format" "$root/usr/local/lib/smcp/package-format"
for f in README.md CHANGELOG.md LICENSE; do
	install -m 0644 "$repo/$f" "$root/usr/local/share/doc/smcp/$f"
done
# The SBOM (FR-13.1) and provenance (FR-12.8), as in the archives.
for f in "$repo"/build/sbom/*.spdx.json "$repo"/build/provenance/*; do
	[ -f "$f" ] && install -m 0644 "$f" "$root/usr/local/share/doc/smcp/$(basename "$f")"
done

# Strip extended attributes (quarantine, provenance) from the payload.
xattr -rc "$root"

COPYFILE_DISABLE=1 pkgbuild --root "$root" --identifier "$identifier" --version "$version" \
	--install-location / --ownership recommended \
	"$work/component.pkg"
# The payload lists /usr, /usr/local, /usr/local/bin and so on. pkgbuild
# marks the package overwrite-permissions="true", which would reset the
# owner and mode of those existing directories (a Homebrew prefix under
# /usr/local, for instance) to the payload's root:wheel 0755. Only files
# the package creates get the payload's owner and mode.
pkgutil --expand "$work/component.pkg" "$work/component"
sed -i '' 's/overwrite-permissions="true"/overwrite-permissions="false"/' "$work/component/PackageInfo"
grep -q 'overwrite-permissions="false"' "$work/component/PackageInfo" || { echo "build-pkg.sh: PackageInfo not patched" >&2; exit 1; }
if grep -q 'postinstall-action="none"' "$work/component/PackageInfo" && [ ! -e "$work/component/Scripts" ]; then :; else
	echo "build-pkg.sh: the component package has scripts or a post-install action" >&2
	exit 1
fi
pkgutil --flatten "$work/component" "$work/smcp-component.pkg"
rm -rf "$work/component" "$work/component.pkg"

cat >"$work/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Secure MCP Gateway $version</title>
    <options customize="never" require-scripts="false" hostArchitectures="arm64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <volume-check>
        <allowed-os-versions><os-version min="13.0"/></allowed-os-versions>
    </volume-check>
    <choices-outline><line choice="default"><line choice="$identifier"/></line></choices-outline>
    <choice id="default"/>
    <choice id="$identifier" visible="false"><pkg-ref id="$identifier"/></choice>
    <pkg-ref id="$identifier" version="$version" onConclusion="none">smcp-component.pkg</pkg-ref>
</installer-gui-script>
XML

mkdir -p "$outdir"
out=$outdir/smcp_${version}_darwin_arm64.pkg
productbuild --distribution "$work/distribution.xml" --package-path "$work" "$out"

# Payload check: exactly the files above, nothing else. A process that
# macOS tags with com.apple.provenance (which xattr -c cannot remove) makes
# pkgbuild add AppleDouble "._" entries; that happens in some local
# sessions, never on a CI runner, where it fails the build.
payload=$(pkgutil --payload-files "$out")
if printf '%s\n' "$payload" | grep -q '/\._'; then
	if [ -n "${CI:-}" ]; then
		echo "build-pkg.sh: the payload has AppleDouble entries" >&2
		exit 1
	fi
	echo "build-pkg.sh: warning: the payload has AppleDouble (._) entries from com.apple.provenance; build on a CI runner for a release" >&2
fi
for b in "${binaries[@]}"; do
	printf '%s\n' "$payload" | grep -qx "./usr/local/lib/smcp/$b" || { echo "build-pkg.sh: $b missing from the payload" >&2; exit 1; }
	printf '%s\n' "$payload" | grep -qx "./usr/local/bin/$b" || { echo "build-pkg.sh: link $b missing from the payload" >&2; exit 1; }
done
echo "$out"
