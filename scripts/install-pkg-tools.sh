#!/usr/bin/env bash
# Installs the tools packaging/installers/macos/build-pkg-linux.sh uses to
# build the macOS .pkg on Linux, into <prefix>/bin:
#
#   xar        mackyle/xar 1.6.1, built from source at a pinned commit
#   mkbom      hogliux/bomutils (with ls4mkbom, lsbom), built from source at a pinned commit
#   rcodesign  apple-codesign 0.29.0 release binary, SHA-256 pinned
#
#   scripts/install-pkg-tools.sh <prefix>
#
# Neither xar nor bomutils is packaged by Ubuntu, so both are built from
# source; a git commit id pins the exact tree. Build dependencies (Ubuntu):
#   build-essential autoconf automake libtool libxml2-dev libssl-dev
#   zlib1g-dev libbz2-dev cpio file git curl ca-certificates
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <prefix>" >&2; exit 2; }
mkdir -p "$1/bin"
prefix=$(cd "$1" && pwd)

XAR_REPO=https://github.com/mackyle/xar
XAR_COMMIT=66d451dab1ef859dd0c83995f2379335d35e53c9 # 2014-06-14, xar 1.6.1
BOMUTILS_REPO=https://github.com/hogliux/bomutils
BOMUTILS_COMMIT=c247002e2f49878bab32dd0fcf805810ae0992cb # 2024-10-28
RCODESIGN_VERSION=0.29.0
declare -A RCODESIGN_SHA256=(
	[x86_64]=dbe85cedd8ee4217b64e9a0e4c2aef92ab8bcaaa41f20bde99781ff02e600002
	[aarch64]=4af92c87ddf52f5f2d1258a3b4e56c7dcb8f1b2468df744976c5f139e031961f
)

src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT

fetch() { # <repo> <commit> <dir>
	git init -q "$3"
	git -C "$3" fetch -q --depth 1 "$1" "$2"
	git -C "$3" checkout -q FETCH_HEAD
	[ "$(git -C "$3" rev-parse HEAD)" = "$2" ] || { echo "install-pkg-tools.sh: $1 is not at $2" >&2; exit 1; }
}

# bomutils: mkbom, ls4mkbom, lsbom.
fetch "$BOMUTILS_REPO" "$BOMUTILS_COMMIT" "$src/bomutils"
make -C "$src/bomutils" -j"$(nproc)" >"$src/bomutils.log" 2>&1 || { tail -40 "$src/bomutils.log" >&2; exit 1; }
install -m 0755 "$src/bomutils/build/bin/mkbom" "$src/bomutils/build/bin/ls4mkbom" "$src/bomutils/build/bin/lsbom" "$prefix/bin/"

# xar: OpenSSL 1.1 and later no longer export OpenSSL_add_all_ciphers,
# which configure probes for; config.guess predates aarch64 Linux.
fetch "$XAR_REPO" "$XAR_COMMIT" "$src/xar"
(
	cd "$src/xar/xar"
	sed -i 's/OpenSSL_add_all_ciphers/OPENSSL_init_crypto/' configure.ac
	./autogen.sh --noconfigure >"$src/xar.log" 2>&1
	for g in /usr/share/automake-*/config.guess /usr/share/automake-*/config.sub; do
		if [ -f "$g" ]; then cp "$g" .; fi
	done
	# -fsigned-char: xar keeps getopt_long()'s result in a char, which is
	# unsigned on arm64.
	if ! { CFLAGS="-O2 -fsigned-char" ./configure --prefix="$src/xar-install" &&
		make -j"$(nproc)" && make install; } >>"$src/xar.log" 2>&1; then
		tail -40 "$src/xar.log" >&2
		exit 1
	fi
)
# Static link of libxar is not offered; keep the shared library next to
# the binary.
install -d "$prefix/lib"
cp -a "$src/xar-install/lib/"libxar.so* "$prefix/lib/"
install -m 0755 "$src/xar-install/bin/xar" "$prefix/bin/xar.bin"
cat >"$prefix/bin/xar" <<SH
#!/bin/sh
LD_LIBRARY_PATH="$prefix/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}" exec "$prefix/bin/xar.bin" "\$@"
SH
chmod 0755 "$prefix/bin/xar"

# rcodesign: the release binary of apple-codesign (Apache-2.0).
arch=$(uname -m)
sum=${RCODESIGN_SHA256[$arch]:-}
[ -n "$sum" ] || { echo "install-pkg-tools.sh: no rcodesign build for $arch" >&2; exit 1; }
name=apple-codesign-$RCODESIGN_VERSION-$arch-unknown-linux-musl
curl -fsSL --retry 3 -o "$src/$name.tar.gz" \
	"https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign%2F$RCODESIGN_VERSION/$name.tar.gz"
echo "$sum  $src/$name.tar.gz" | sha256sum -c --quiet
tar -xzf "$src/$name.tar.gz" -C "$src"
install -m 0755 "$src/$name/rcodesign" "$prefix/bin/rcodesign"

"$prefix/bin/xar" --version
"$prefix/bin/rcodesign" --version
command -v "$prefix/bin/mkbom" >/dev/null
