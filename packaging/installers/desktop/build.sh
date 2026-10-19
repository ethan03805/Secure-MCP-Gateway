#!/usr/bin/env bash
# Builds the Desktop Application installers (E-35; SRS FR-20.17 to
# FR-20.19, FR-20.26) with the Tauri bundler, on the platform they are for:
#
#   packaging/installers/desktop/build.sh <version> <binary dir> <output dir> [<smcp .deb> <smcp .rpm>]
#
# <binary dir> holds the release binaries of this platform, or is
# GoReleaser's dist directory with one <id>_<os>_<arch>*/ directory per
# binary. On Linux the smcp .deb and .rpm of the same build give the exact
# package versions the smcp-desktop packages depend on.
#
# macOS (arm64 only, FR-20.1):
#   <output>/smcp-desktop_<version>_darwin_arm64.dmg
#       "Secure MCP Gateway.app" with smcpd, smcpctl, smcp-session,
#       smcp-stdio, smcp-connect and smcp-refserver in Contents/MacOS next to
#       smcp-desktop, and a link to /Applications for drag-and-drop.
#   <output>/app/Secure MCP Gateway.app
#       The same bundle, for build-pkg.sh (the .pkg installs it in
#       /Applications). Not a release asset.
#   Every executable and the bundle carry an ad-hoc signature and nothing
#   else (FR-20.26); the .dmg is not signed.
#
# Linux (amd64 or arm64, the build host's):
#   <output>/smcp-desktop_<deb version>_<arch>.deb
#   <output>/smcp-desktop-<rpm version>.<rpm arch>.rpm (rpmbuild, from the .deb files)
#       The application only (/usr/bin/smcp-desktop, its .desktop entry and
#       icons), depending on smcp of exactly the same version, which
#       provides the commands in /usr/bin (FR-20.18).
#   <output>/smcp-desktop_<version>_linux_<arch>.AppImage
#       The application with the six commands in usr/bin (FR-20.19).
#
# The application finds the commands next to its own executable
# (desktop/src-tauri/src/commands.rs); `smcp-desktop --commands` lists
# them. Uses CARGO_TARGET_DIR when set.
set -euo pipefail

[ $# -eq 3 ] || [ $# -eq 5 ] || {
	echo "usage: $0 <version> <binary dir> <output dir> [<smcp .deb> <smcp .rpm>]" >&2
	exit 2
}
version=$1 bindir=$(cd "$2" && pwd) outdir=$3
smcpdeb="" smcprpm=""
if [ $# -eq 5 ]; then
	smcpdeb=$(cd "$(dirname "$4")" && pwd)/$(basename "$4")
	smcprpm=$(cd "$(dirname "$5")" && pwd)/$(basename "$5")
fi
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
commands=(smcpd smcpctl smcp-session smcp-stdio smcp-connect smcp-refserver)
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
target=${CARGO_TARGET_DIR:-$repo/desktop/src-tauri/target}

case "$(uname -s)" in
Darwin) os=darwin ;;
Linux) os=linux ;;
*) echo "build.sh: macOS or Linux only" >&2; exit 1 ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 rpmarch=x86_64 filearch=x86-64 ;;
arm64 | aarch64) arch=arm64 rpmarch=aarch64 filearch='arm64|aarch64' ;;
*) echo "build.sh: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
[ "$os/$arch" != darwin/amd64 ] || { echo "build.sh: the macOS application is built for arm64 only (FR-20.1)" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The commands of this platform, checked for the architecture.
mkdir -p "$work/bin"
for b in "${commands[@]}"; do
	src=$bindir/$b
	[ -f "$src" ] || src=$(find "$bindir" -path "*/${b}_${os}_${arch}*/$b" -type f 2>/dev/null | head -n1)
	[ -n "$src" ] && [ -f "$src" ] || { echo "build.sh: $b for $os/$arch missing in $bindir" >&2; exit 1; }
	file -L "$src" | grep -Eq "$filearch" || { echo "build.sh: $src is not a $arch executable" >&2; exit 1; }
	install -m 0755 "$src" "$work/bin/$b"
done

cd "$repo/desktop"
[ -d node_modules ] || npm ci --no-audit --no-fund

if [ "$os" = darwin ]; then
	files=$(for b in "${commands[@]}"; do printf '%s\n%s\n' "MacOS/$b" "$work/bin/$b"; done |
		jq -Rn '[inputs] | [range(0; length; 2) as $i | {(.[$i]): .[$i + 1]}] | add')
	jq -n --arg v "$version" --argjson files "$files" \
		'{version: $v, bundle: {macOS: {files: $files}}}' >"$work/tauri.json"
	npx --no-install tauri build --bundles app --no-sign --config "$work/tauri.json"
	app="$target/release/bundle/macos/Secure MCP Gateway.app"
	[ -x "$app/Contents/MacOS/smcp-desktop" ] || { echo "build.sh: $app has no smcp-desktop" >&2; exit 1; }
	xattr -cr "$app"
	# Ad-hoc signatures (FR-20.26): each executable, then the bundle.
	for f in "$app"/Contents/MacOS/*; do
		file "$f" | grep -q arm64 || { echo "build.sh: $f is not arm64" >&2; exit 1; }
		codesign --force --sign - --timestamp=none "$f"
	done
	codesign --force --sign - --timestamp=none "$app"
	codesign --verify --deep --strict "$app"
	rm -rf "$outdir/app"
	mkdir -p "$outdir/app"
	ditto "$app" "$outdir/app/Secure MCP Gateway.app"
	# The disk image: the application and a link to /Applications.
	mkdir -p "$work/dmg"
	ditto "$app" "$work/dmg/Secure MCP Gateway.app"
	ln -s /Applications "$work/dmg/Applications"
	dmg=$outdir/smcp-desktop_${version}_darwin_arm64.dmg
	rm -f "$dmg"
	hdiutil create -quiet -volname "Secure MCP Gateway" -srcfolder "$work/dmg" -fs HFS+ -format UDZO -ov "$dmg"
	hdiutil verify -quiet "$dmg"
	echo "$dmg"
	exit 0
fi

# Linux: the versions the smcp packages of this build have.
[ -n "$smcpdeb" ] || { echo "build.sh: on Linux pass the smcp .deb and .rpm of the same build" >&2; exit 2; }
debver=$(dpkg-deb -f "$smcpdeb" Version)
rpmver=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$smcprpm" 2>/dev/null)
[ -n "$debver" ] && [ -n "$rpmver" ] || { echo "build.sh: cannot read the smcp package versions" >&2; exit 1; }
[ "$(dpkg-deb -f "$smcpdeb" Package)" = smcp ] || { echo "build.sh: $smcpdeb is not the smcp package" >&2; exit 1; }
files=$(for b in "${commands[@]}"; do printf '%s\n%s\n' "/usr/bin/$b" "$work/bin/$b"; done |
	jq -Rn '[inputs] | [range(0; length; 2) as $i | {(.[$i]): .[$i + 1]}] | add')
# productName names the packages (smcp-desktop); the .desktop entry keeps
# the application's name.
jq -n --arg v "$version" --arg deb "smcp (= $debver)" \
	--arg desktop "$here/smcp-desktop.desktop" --argjson files "$files" \
	'{version: $v, productName: "smcp-desktop", bundle: {linux: {
		deb: {depends: [$deb, "libwebkit2gtk-4.1-0", "libgtk-3-0", "libayatana-appindicator3-1"], desktopTemplate: $desktop},
		appimage: {files: $files}}}}' >"$work/tauri.json"
rm -rf "$target/release/bundle/deb" "$target/release/bundle/appimage"
# No Tauri .rpm: its bundler writes each "depends" entry as a bare package
# name, so "smcp = <version>" would require a package of that literal name.
# The .rpm is built below with rpmbuild from the files of the .deb, with a
# real versioned requirement.
npx --no-install tauri build --bundles deb,appimage --config "$work/tauri.json"
one() { # directory pattern
	local f n
	n=$(find "$1" -maxdepth 1 -name "$2" | wc -l | tr -d ' ')
	[ "$n" = 1 ] || { echo "build.sh: expected one $2 in $1, found $n" >&2; exit 1; }
	f=$(find "$1" -maxdepth 1 -name "$2")
	printf '%s\n' "$f"
}
deb=$(one "$target/release/bundle/deb" '*.deb')
appimage=$(one "$target/release/bundle/appimage" '*.AppImage')
[ "$(dpkg-deb -f "$deb" Package)" = smcp-desktop ] || { echo "build.sh: the .deb is not package smcp-desktop" >&2; exit 1; }
dpkg-deb -f "$deb" Depends | grep -qF "smcp (= $debver)" || { echo "build.sh: the .deb does not depend on smcp (= $debver)" >&2; exit 1; }
if dpkg-deb -c "$deb" | grep -Eq '/usr/bin/smcp(d|ctl|-session|-stdio|-connect|-refserver)$'; then
	echo "build.sh: the .deb carries Gateway commands, which belong to the smcp package" >&2
	exit 1
fi

# The .rpm: the files of the .deb, with the version and release of the smcp
# .rpm, requiring exactly that smcp (name, operator and version).
rpmv=${rpmver%-*} rpmr=${rpmver##*-}
mkdir -p "$work/rpm/root" "$work/rpm/top"
dpkg-deb -x "$deb" "$work/rpm/root"
(cd "$work/rpm/root" && find . -type f -o -type l | sed 's|^[.]||' | sort) >"$work/rpm/files"
cat >"$work/rpm/smcp-desktop.spec" <<SPEC
Name: smcp-desktop
Version: $rpmv
Release: $rpmr
Summary: Secure MCP Gateway desktop application
License: Apache-2.0
URL: https://github.com/ethan03805/Secure-MCP-Gateway
Requires: smcp = $rpmver
# Loaded with dlopen for the tray, so not found by the ELF scan.
Requires: libayatana-appindicator3.so.1()(64bit)
%define _build_id_links none
%define debug_package %{nil}
%global __os_install_post %{nil}

%description
Tray, service control and console window for the Secure MCP Gateway. The
Gateway commands come from the smcp package of the same version.

%install
cp -a "$work/rpm/root/." "%{buildroot}/"

%files -f $work/rpm/files
SPEC
rpmbuild --quiet -bb --target "$rpmarch" --define "_topdir $work/rpm/top" "$work/rpm/smcp-desktop.spec"
rpm=$(one "$work/rpm/top/RPMS/$rpmarch" '*.rpm')
req=$(rpm -qp --qf '[%{REQUIRENAME}|%{REQUIREFLAGS:depflags}|%{REQUIREVERSION}\n]' "$rpm" | grep '^smcp|' | tr -d ' ' || true)
[ "$req" = "smcp|=|$rpmver" ] || { echo "build.sh: the .rpm requires '$req', not smcp = $rpmver" >&2; exit 1; }
if rpm -qlp "$rpm" | grep -Eq '^/usr/bin/smcp(d|ctl|-session|-stdio|-connect|-refserver)$'; then
	echo "build.sh: the .rpm carries Gateway commands, which belong to the smcp package" >&2
	exit 1
fi
# A pre-release keeps "~" in the package versions (1.3.0~rc.1 orders
# before 1.3.0) but not in the file names: a GitHub release asset name
# cannot contain "~", so the name in the signed checksum file would not
# match the asset (as for the smcp packages, .goreleaser.yaml).
cp "$deb" "$outdir/smcp-desktop_$(printf '%s' "$debver" | tr '~' '.')_${arch}.deb"
cp "$rpm" "$outdir/smcp-desktop-$(printf '%s' "$rpmver" | tr '~' '.').${rpmarch}.rpm"
install -m 0755 "$appimage" "$outdir/smcp-desktop_${version}_linux_${arch}.AppImage"
ls -l "$outdir"
