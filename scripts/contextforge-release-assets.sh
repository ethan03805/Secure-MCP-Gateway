#!/usr/bin/env bash
# The ContextForge assets of a Gateway release (SRS FR-22.18, FR-22.21),
# written to OUTDIR (default build/contextforge):
#
#   contextforge.lock.json          the release lock (packaging/), unchanged
#   contextforge.lock.json.minisig  its minisign signature with the release
#                                   key (MINISIGN_KEY_FILE, MINISIGN_PASSWORD)
#   contextforge-image.spdx.json    the SPDX SBOM of the pinned image, from
#                                   its cosign attestation verified for the
#                                   lock's signer identity
#   contextforge-wheels-<os>-<arch>.spdx.json
#                                   the SPDX SBOM of each wheel set (syft over
#                                   the unpacked wheels, each fetched from its
#                                   URL in the lock and checked against its
#                                   SHA-256)
#   contextforge-LICENSE.txt        the ContextForge license (Apache-2.0)
#   contextforge-NOTICE.txt         the notice of the pinned catalog file
#   contextforge-advisories.txt     the advisory check of the pinned version
#
# and checks that every component of the SBOMs carries an SPDX license
# identifier (tools/sbomcheck -identifiers) and that the pinned version has
# no unfixed high or critical advisory (tools/cfadvisory).
#
#   scripts/contextforge-release-assets.sh [OUTDIR]
#
# Needs jq, curl, unzip, syft, cosign, minisign and go; the advisory check
# reads the advisories with gh (GH_TOKEN). With SMCP_RELEASE=1 (the release
# workflow) the signature and the advisory check are required; otherwise
# (the CI snapshot) a missing key or token skips them with a note.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:-$root/build/contextforge}
lock=$root/packaging/contextforge.lock.json
release=${SMCP_RELEASE:-}
rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

version=$(jq -r .contextforge.version "$lock")
cp "$lock" "$out/contextforge.lock.json"
cp "$root/packaging/contextforge/LICENSE" "$out/contextforge-LICENSE.txt"
cp "$root/internal/contextforge/release/NOTICE" "$out/contextforge-NOTICE.txt"

# The release lock's signature (FR-22.18).
if [ -n "${MINISIGN_KEY_FILE:-}" ]; then
  printf '%s\n' "${MINISIGN_PASSWORD:-}" | minisign -S -s "$MINISIGN_KEY_FILE" -m "$out/contextforge.lock.json" \
    -x "$out/contextforge.lock.json.minisig" -t "smcp ${SMCP_VERSION:-snapshot} file:contextforge.lock.json ContextForge $version" >/dev/null
  echo "signed contextforge.lock.json"
elif [ "$release" = 1 ]; then
  echo "contextforge-release-assets: SMCP_RELEASE=1 but MINISIGN_KEY_FILE is not set" >&2
  exit 1
else
  echo "contextforge.lock.json not signed: no MINISIGN_KEY_FILE"
fi

# The image SBOM: the SPDX attestation of the image index, verified for the
# lock's signer identity (the same check FR-22.19 runs before a start).
ref=$(jq -r '.contextforge.image.reference + "@" + .contextforge.image.index_digest' "$lock")
cosign verify-attestation --type spdxjson \
  --certificate-identity "$(jq -r .contextforge.signer.subject "$lock")" \
  --certificate-oidc-issuer "$(jq -r .contextforge.signer.issuer "$lock")" \
  "$ref" > "$work/attestations.jsonl" 2>"$work/cosign.log" || { cat "$work/cosign.log" >&2; exit 1; }
head -n1 "$work/attestations.jsonl" | jq -r .payload | base64 -d > "$work/statement.json"
want=$(jq -r .contextforge.image.index_digest "$lock")
got=$(jq -r '.subject[0].digest.sha256' "$work/statement.json")
[ "sha256:$got" = "$want" ] || { echo "contextforge-release-assets: the attestation is for sha256:$got, not $want" >&2; exit 1; }
jq '.predicate' "$work/statement.json" > "$out/contextforge-image.spdx.json"
jq -e '.spdxVersion and (.packages | length > 10)' "$out/contextforge-image.spdx.json" >/dev/null
echo "image SBOM: $(jq '.packages | length' "$out/contextforge-image.spdx.json") packages"

# The wheel SBOMs: each wheel fetched from its URL and checked against the
# lock, unpacked (a wheel is a zip of the installed tree with its
# .dist-info), and catalogued by syft.
mkdir -p "$work/dl"
for plat in $(jq -r '.contextforge.wheels | keys[]' "$lock"); do
  site=$work/site-${plat//\//-}
  mkdir -p "$site"
  jq -r --arg p "$plat" '.contextforge.wheels[$p][] | [.file, .sha256, .url] | @tsv' "$lock" > "$work/set.tsv"
  while IFS=$'\t' read -r file sha url; do
    f=$work/dl/$file
    if [ ! -f "$f" ]; then
      curl -fsSL --retry 3 -o "$f.part" "$url"
      mv "$f.part" "$f"
    fi
    echo "$sha  $f" | sha256sum -c --quiet - || { echo "contextforge-release-assets: $file does not match the release lock" >&2; exit 1; }
    unzip -q -o "$f" -d "$site"
  done < "$work/set.tsv"
  name=contextforge-wheels-${plat//\//-}
  syft scan "dir:$site" --source-name "$name" --source-version "$version" -q -o "spdx-json=$out/$name.spdx.json"
  n=$(jq '[.packages[] | select(.SPDXID | startswith("SPDXRef-DocumentRoot") | not)] | length' "$out/$name.spdx.json")
  w=$(wc -l < "$work/set.tsv")
  [ "$n" -ge "$w" ] || { echo "contextforge-release-assets: $name lists $n packages for $w wheels" >&2; exit 1; }
  echo "$plat wheel SBOM: $n packages for $w wheels"
  rm -rf "$site"
done

# FR-22.21: every bundled component carries an SPDX license identifier
# (or a reviewed one in packaging/contextforge-sbom-review.json).
(cd "$root" && go run ./tools/sbomcheck -identifiers -review packaging/contextforge-sbom-review.json "$out"/*.spdx.json)

# FR-22.18: no unfixed high or critical advisory for the pinned version.
if command -v gh >/dev/null 2>&1 && { [ -n "${GH_TOKEN:-}" ] || gh auth status >/dev/null 2>&1; }; then
  repo=$(jq -r '.contextforge.source.repository | sub("https://github.com/"; "")' "$lock")
  gh api --paginate "repos/$repo/security-advisories?state=published&per_page=100" > "$work/advisories.json"
  (cd "$root" && go run ./tools/cfadvisory -lock "$lock" -date "$(date -u +%Y-%m-%d)" "$work/advisories.json") | tee "$out/contextforge-advisories.txt"
elif [ "$release" = 1 ]; then
  echo "contextforge-release-assets: SMCP_RELEASE=1 but gh cannot read the advisories" >&2
  exit 1
else
  echo "advisory check skipped: gh is not authenticated"
fi
ls -l "$out"
