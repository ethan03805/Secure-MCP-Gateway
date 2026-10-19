#!/usr/bin/env bash
# Builds the macOS command-line installer smcp_<version>_darwin_arm64.pkg
# on Linux (SRS FR-20.17, FR-20.21, FR-20.26, SR-4.11-2), without pkgbuild
# or productbuild: the release and CI build it here so that no macOS
# runner is needed to publish it (docs/ci.md, "macOS runners").
#
#   packaging/installers/macos/build-pkg-linux.sh <version> <binary dir> <output dir>
#
# The package is the one build-pkg.sh builds on macOS with pkgbuild and
# productbuild: the same payload, install locations, owner root:wheel
# (0:0) and modes, the same component identifier and version, the same
# PackageInfo (overwrite-permissions="false", postinstall-action="none",
# no scripts) and the same Distribution. It is a flat package: a xar
# archive holding Distribution and smcp-component.pkg/{Bom,Payload,
# PackageInfo}, with the payload a gzip-compressed cpio (odc) archive.
# The installed files:
#
#   /usr/local/lib/smcp/<binaries>          ad-hoc signed (FR-20.26)
#   /usr/local/lib/smcp/package-format      "pkg" (smcpctl uninstall/upgrade)
#   /usr/local/bin/<binaries>               symbolic links to the above
#   /usr/local/share/doc/smcp/              README, CHANGELOG, LICENSE, SBOM,
#                                           provenance and notices
#
# Tools (scripts/install-pkg-tools.sh installs pinned builds of them):
#   XAR        xar 1.6.1 (mackyle/xar)                       default: xar
#   MKBOM      mkbom of bomutils (hogliux/bomutils)          default: mkbom
#   LS4MKBOM   ls4mkbom of bomutils                          default: ls4mkbom
#   RCODESIGN  rcodesign of apple-codesign (Apache-2.0)      default: rcodesign
# and file and python3 (which writes the cpio payload).
#
# Ad-hoc signature (FR-20.26): rcodesign signs each binary ad hoc with the
# identifier codesign would choose, <name>-<hex of "UUID" and LC_UUID>.
# codesign hashes 16 KiB pages and rcodesign 4 KiB pages (as Go's linker
# does), so the code directory hashes differ; both are complete ad-hoc
# signatures that `codesign --verify --strict` accepts.
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <version> <binary dir> <output dir>" >&2; exit 2; }
version=$1 bindir=$2 outdir=$3
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
XAR=${XAR:-xar} MKBOM=${MKBOM:-mkbom} LS4MKBOM=${LS4MKBOM:-ls4mkbom} RCODESIGN=${RCODESIGN:-rcodesign}
for t in "$XAR" "$MKBOM" "$LS4MKBOM" "$RCODESIGN" file python3; do
	command -v "$t" >/dev/null || { echo "build-pkg-linux.sh: $t not found (scripts/install-pkg-tools.sh)" >&2; exit 1; }
done

# As build-pkg.sh: the five commands of FR-20.17 and smcp-refserver.
binaries=(smcpd smcpctl smcp-session smcp-stdio smcp-connect smcp-refserver)
identifier=io.github.ethan03805.smcp
case "$version" in *[!A-Za-z0-9.+_-]*|'') echo "build-pkg-linux.sh: bad version '$version'" >&2; exit 1 ;; esac

# codesign's default identifier for a binary without one of its own:
# the file name, "-", and the hex of "UUID" followed by the LC_UUID bytes.
macho_identifier() {
	python3 -I - "$1" "$2" <<'PY'
import struct, sys
path, name = sys.argv[1], sys.argv[2]
with open(path, "rb") as f:
    data = f.read()
if struct.unpack_from("<I", data, 0)[0] != 0xFEEDFACF:
    sys.exit("not a thin 64-bit little-endian Mach-O: " + path)
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", data, off)
    if cmd == 0x1B:  # LC_UUID
        print(name + "-" + (b"UUID" + data[off + 8:off + 24]).hex())
        break
    off += size
else:
    sys.exit("no LC_UUID in " + path)
PY
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root=$work/root
umask 022
install -d -m 0755 "$root/usr/local/lib/smcp" "$root/usr/local/bin" "$root/usr/local/share/doc/smcp"
for b in "${binaries[@]}"; do
	src=$bindir/$b
	[ -f "$src" ] || src=$(find "$bindir" -path "*/${b}_darwin_arm64*/$b" -type f 2>/dev/null | head -n1)
	[ -n "$src" ] && [ -f "$src" ] || { echo "build-pkg-linux.sh: $b missing in $bindir" >&2; exit 1; }
	file "$src" | grep -q 'Mach-O 64-bit.*arm64' || { echo "build-pkg-linux.sh: $src is not a Mach-O arm64 executable" >&2; exit 1; }
	dst=$root/usr/local/lib/smcp/$b
	install -m 0755 "$src" "$dst"
	# Replace the linker's signature with a full ad-hoc one, as
	# build-pkg.sh does with codesign --force --sign -.
	id=$(macho_identifier "$dst" "$b")
	"$RCODESIGN" sign --binary-identifier "$id" "$dst" >/dev/null 2>&1 ||
		{ echo "build-pkg-linux.sh: rcodesign could not sign $b" >&2; exit 1; }
	# rcodesign verify reports false problems for ad-hoc signatures; check
	# the code directory instead (codesign --verify --strict runs in the
	# smoke test on macOS, scripts/package-smoke.sh).
	info=$("$RCODESIGN" print-signature-info "$dst" 2>/dev/null)
	if ! printf '%s\n' "$info" | grep -qx '          flags: CodeSignatureFlags(ADHOC)' ||
		! printf '%s\n' "$info" | grep -qx "          identifier: $id"; then
		echo "build-pkg-linux.sh: $b is not ad-hoc signed as $id" >&2
		exit 1
	fi
	chmod 0755 "$dst"
	ln -s "../lib/smcp/$b" "$root/usr/local/bin/$b"
done
install -m 0644 "$here/package-format" "$root/usr/local/lib/smcp/package-format"
for f in README.md CHANGELOG.md LICENSE; do
	install -m 0644 "$repo/$f" "$root/usr/local/share/doc/smcp/$f"
done
for f in "$repo"/build/sbom/*.spdx.json "$repo"/build/provenance/*; do
	[ -f "$f" ] && install -m 0644 "$f" "$root/usr/local/share/doc/smcp/$(basename "$f")"
done
chmod 0755 "$root"
# Reproducible timestamps when SOURCE_DATE_EPOCH is set (the workflows
# set it to the commit time).
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
	find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
fi

comp=$work/flat/smcp-component.pkg
mkdir -p "$comp"
# Payload: a cpio (odc) archive of the tree as pkgbuild writes it: names
# "./usr/...", a directory before its entries, every entry owned by
# root:wheel (0:0), device 0 and inodes numbered from 0, symbolic links
# with mode 0755 (Linux reports 0777), gzip-compressed. GNU cpio strips
# the leading "./" and cannot set a link's mode, so a short Python writer
# does it; it prints each entry's name and mode.
python3 -I - "$root" "$comp/Payload" >"$work/payload.list" <<'PY'
import gzip, os, stat, sys
root, out = sys.argv[1], sys.argv[2]
names = ["."]
for d, dirs, files in os.walk(root):
    rel = os.path.relpath(d, root)
    for n in dirs + files:
        names.append("./" + os.path.normpath(os.path.join(rel, n)))
names.sort(key=lambda n: n.encode())
def octal(v, w):
    s = "%0*o" % (w, v)
    if len(s) != w:
        sys.exit("cpio field overflow")
    return s.encode()
def header(ino, mode, nlink, mtime, name, size):
    return (b"070707" + octal(0, 6) + octal(ino, 6) + octal(mode, 6) + octal(0, 6) + octal(0, 6)
            + octal(nlink, 6) + octal(0, 6) + octal(mtime, 11) + octal(len(name), 6) + octal(size, 11) + name)
with gzip.GzipFile(out, "wb", compresslevel=9, mtime=0) as z:
    for ino, name in enumerate(names):
        path = os.path.join(root, name)
        st = os.lstat(path)
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            mode = stat.S_IFLNK | 0o755
            data = os.readlink(path).encode()
        elif stat.S_ISREG(mode):
            with open(path, "rb") as f:
                data = f.read()
        elif stat.S_ISDIR(mode):
            data = b""
        else:
            sys.exit("unsupported file type: " + name)
        z.write(header(ino, mode, st.st_nlink, int(st.st_mtime), name.encode() + b"\0", len(data)) + data)
        print("%s\t%o" % (name, mode))
    z.write(header(0, 0, 1, 0, b"TRAILER!!!\0", 0))
PY
# Bom: bomutils' ls4mkbom lists the tree with owner 0:0, links with mode
# 0755 as in the payload; mkbom writes it.
"$LS4MKBOM" -u 0 -g 0 "$root" | awk -F '\t' 'BEGIN { OFS = "\t" } $2 == "120777" { $2 = "120755" } { print }' >"$work/bom.list"
"$MKBOM" -i "$work/bom.list" "$comp/Bom"

# pkgbuild's numbers: numberOfFiles counts every Bom entry (with "."),
# installKBytes is the regular files' sizes rounded up to KiB plus 4.
nfiles=$(wc -l <"$work/payload.list" | tr -d ' ')
kbytes=$(cd "$root" && find . -type f -printf '%s\n' | awk '{ k += int(($1 + 1023) / 1024) } END { print k + 4 }')

# PackageInfo as pkgbuild writes it, with overwrite-permissions="false"
# (build-pkg.sh patches it so that existing directories such as a
# Homebrew prefix under /usr/local keep their owner and mode).
cat >"$work/PackageInfo.in" <<XML
<?xml version="1.0" encoding="utf-8"?>
<pkg-info overwrite-permissions="false" relocatable="false" identifier="$identifier" postinstall-action="none" version="$version" format-version="2" generator-version="smcp build-pkg-linux.sh" install-location="/" auth="root">
    <payload numberOfFiles="$nfiles" installKBytes="$kbytes"/>
    <bundle-version/>
    <upgrade-bundle/>
    <update-bundle/>
    <atomic-update-bundle/>
    <strict-identifier/>
    <relocate/>
</pkg-info>
XML
head -c -1 "$work/PackageInfo.in" >"$comp/PackageInfo"

# Distribution as productbuild writes it from build-pkg.sh's
# distribution.xml.
cat >"$work/Distribution.in" <<XML
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<installer-gui-script minSpecVersion="2">
    <title>Secure MCP Gateway $version</title>
    <options customize="never" require-scripts="false" hostArchitectures="arm64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="13.0"/>
        </allowed-os-versions>
    </volume-check>
    <choices-outline>
        <line choice="default">
            <line choice="$identifier"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$identifier" visible="false">
        <pkg-ref id="$identifier"/>
    </choice>
    <pkg-ref id="$identifier" version="$version" onConclusion="none" installKBytes="$kbytes" updateKBytes="0">#smcp-component.pkg</pkg-ref>
    <pkg-ref id="$identifier">
        <bundle-version/>
    </pkg-ref>
</installer-gui-script>
XML
head -c -1 "$work/Distribution.in" >"$work/flat/Distribution"

mkdir -p "$outdir"
out=$(cd "$outdir" && pwd)/smcp_${version}_darwin_arm64.pkg
rm -f "$out"
(cd "$work/flat" && "$XAR" -c --distribution --compression=gzip '--no-compress=^smcp-component.pkg/Payload$' -f "$out" smcp-component.pkg Distribution)

# Checks: the archive lists exactly the four members, and the payload
# holds exactly the files above, owned by 0:0, nothing else.
members=$("$XAR" -t -f "$out" | LC_ALL=C sort | tr '\n' ' ')
[ "$members" = "Distribution smcp-component.pkg smcp-component.pkg/Bom smcp-component.pkg/PackageInfo smcp-component.pkg/Payload " ] ||
	{ echo "build-pkg-linux.sh: unexpected archive members: $members" >&2; exit 1; }
payload=$(cut -f1 "$work/payload.list")
if printf '%s\n' "$payload" | grep -q '/\._'; then
	echo "build-pkg-linux.sh: the payload has AppleDouble entries" >&2
	exit 1
fi
[ "$(cut -f1,2 "$work/bom.list" | LC_ALL=C sort)" = "$(LC_ALL=C sort "$work/payload.list")" ] ||
	{ echo "build-pkg-linux.sh: the payload and the Bom list different entries or modes" >&2; exit 1; }
[ "$(cut -f3 "$work/bom.list" | sort -u)" = "0/0" ] || { echo "build-pkg-linux.sh: Bom entries not owned by 0/0" >&2; exit 1; }
for b in "${binaries[@]}"; do
	printf '%s\n' "$payload" | grep -qx "./usr/local/lib/smcp/$b" || { echo "build-pkg-linux.sh: $b missing from the payload" >&2; exit 1; }
	printf '%s\n' "$payload" | grep -qx "./usr/local/bin/$b" || { echo "build-pkg-linux.sh: link $b missing from the payload" >&2; exit 1; }
done
echo "$out"
