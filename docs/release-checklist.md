# Release checklist

The procedure for publishing a Secure MCP Gateway release, starting with v1.0.0. Each step names the command and what to check. A release is made only from `main` with every required CI job green.

## What a release contains

| Asset | Made by | Requirement |
|---|---|---|
| `smcp_<version>_<os>_<arch>.tar.gz` for darwin-arm64, darwin-amd64, linux-amd64, linux-arm64, each with `smcpd`, `smcpctl`, `smcp-refserver`, `smcp-session`, `smcp-stdio`, `smcp-connect`, `README.md`, `CHANGELOG.md`, `LICENSE` | GoReleaser (`.goreleaser.yaml`) | FR-13.1 |
| `smcp_<version>_checksums.txt` (SHA-256 of every archive) | GoReleaser | FR-13.1 |
| `smcp_<version>_checksums.txt.minisig` | GoReleaser `signs` with the release key (secrets `MINISIGN_SECRET_KEY`, `MINISIGN_PASSWORD`) | FR-13.1, FR-13.2 |
| `smcp_<version>_checksums.txt.sigstore.json` | cosign keyless step in `release.yml` | security review RR-01 |
| `*.sbom.json` per archive | syft through GoReleaser | FR-12.1 |
| `Formula/smcp.rb` in [ethan03805/homebrew-tap](https://github.com/ethan03805/homebrew-tap) | GoReleaser `brews` (secret `HOMEBREW_TAP_TOKEN`) | FR-13.3 |

The console is embedded in `smcpd` from the committed `console/dist`. The SBOMs are separate release assets, not files inside the archives; FR-13.1 asks for the SBOM inside each archive, which is not done yet.

The release public key, published in `SECURITY.md`, `docs/install.md` and embedded in `install.sh`:

```
untrusted comment: minisign public key 064FAC0C64ACCED0
RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
```

## Repository settings (once)

- [ ] Secrets `MINISIGN_SECRET_KEY` (the minisign secret key file, both lines) and `MINISIGN_PASSWORD` exist: `gh secret list -R ethan03805/Secure-MCP-Gateway`. The release job fails when the key is missing.
- [ ] Secret `HOMEBREW_TAP_TOKEN` holds a token with write access to `ethan03805/homebrew-tap` (contents: read and write). Without it GoReleaser skips the tap upload; the release still completes.
- [ ] The repository variable `SMCP_COSIGN` is unset or `true` (cosign keyless signing on).
- [ ] The maintainer's offline copy of the secret key and its password is in place (the copy used to create the secrets).

## Before tagging

- [ ] Every pull request intended for the release is merged; `main` is green on all required jobs (srs, go, lint, site, security, linux-integration, hostile).
- [ ] `make check` passes on a clean checkout of `main`.
- [ ] `make status` and `build/reqreport.md` reviewed: no requirement newly failing; `docs/verification/gap-list.md` matches the report.
- [ ] `CHANGELOG.md` has a `## v<version>` section at the top that lists what the release contains and its known limitations, dated with the release day.
- [ ] Release label: the release is labelled "not enforced" unless AT-01 to AT-21 evidence for the release commit is complete and passing (FR-19.3). There is no automated labelling step yet; the release notes state the label.
- [ ] Local snapshot with signing proves the configuration:

  ```sh
  MINISIGN_KEY_FILE=~/.config/smcp-dev/minisign.key MINISIGN_PASSWORD="$(cat ~/.config/smcp-dev/minisign.password)" make release-snapshot
  minisign -Vm build/dist/smcp_*_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
  tar -tzf build/dist/smcp_*_darwin_arm64.tar.gz
  rm -rf build/dist
  ```

  Check that the four archives exist, that each lists the six binaries, that the signature verifies, and that `build/dist/homebrew/Formula/smcp.rb` names the four archives with their checksums. Without `MINISIGN_KEY_FILE` the snapshot skips signing.

## Tag and publish

- [ ] Tag the release commit on `main` and push the tag:

  ```sh
  git fetch origin && git checkout origin/main
  git tag -a v1.0.0 -m "Secure MCP Gateway v1.0.0"
  git push origin v1.0.0
  ```

- [ ] Watch the `release` workflow: `gh run watch -R ethan03805/Secure-MCP-Gateway $(gh run list -R ethan03805/Secure-MCP-Gateway -w release -L 1 --json databaseId -q '.[0].databaseId')`. It runs the tests, GoReleaser (archives, checksums, minisign signature, SBOMs, release, Homebrew formula), checks the minisign signature against the key in `install.sh` and `SECURITY.md`, then signs the checksum file with cosign and uploads the bundle.

## After publishing

- [ ] The release page lists the four archives, the checksum file, `.minisig`, `.sigstore.json` and the SBOMs: `gh release view v1.0.0 -R ethan03805/Secure-MCP-Gateway`.
- [ ] Verify the release from a clean directory:

  ```sh
  gh release download v1.0.0 -R ethan03805/Secure-MCP-Gateway -D /tmp/smcp-rel
  cd /tmp/smcp-rel
  minisign -Vm smcp_1.0.0_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
  cosign verify-blob --bundle smcp_1.0.0_checksums.txt.sigstore.json \
    --certificate-identity-regexp '^https://github.com/ethan03805/Secure-MCP-Gateway/.github/workflows/release.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com smcp_1.0.0_checksums.txt
  sha256sum --check smcp_1.0.0_checksums.txt   # macOS: shasum -a 256 -c
  ```

- [ ] `install.sh` installs it on macOS and on Linux: `curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh -s -- --version v1.0.0 --dir /tmp/smcp-bin`; the output reports the signature verified and, with cosign installed, the Sigstore bundle verified.
- [ ] Homebrew: `brew install ethan03805/tap/smcp`, then `smcpctl version` and `brew test smcp`. Compare the installed binaries' SHA-256 with those inside the release archive for the platform (FR-13.3).
- [ ] `smcpctl install` on a macOS host and on a Linux host reports every step and `health: degraded`; a second run reports `present` throughout; `smcpctl uninstall` removes the unit and binaries and keeps the journal.
- [ ] Inspect the release for FR-13.1 and record the result (date, release, inspector) in `docs/verification/inspections.md` so that `tools/reqreport` counts it; update `docs/verification/gap-list.md` for FR-13.1 and FR-13.3.
- [ ] Announce: the release notes are the `CHANGELOG.md` section; link them from the site's status page.

## If something goes wrong

- A failed workflow before GoReleaser publishes leaves no release; fix on `main`, delete the tag (`git push origin :refs/tags/v1.0.0`, `git tag -d v1.0.0`) and tag again.
- A published release with a defect is not edited in place. Publish the fix as the next patch version; mark the bad release as a pre-release or delete it with `gh release delete`, and say so in `CHANGELOG.md`.
- A suspected compromise of the minisign key: follow [runbooks/key-compromise.md](runbooks/key-compromise.md) for the release key as well: generate a new key, sign the new public key with the old one if the old one is still trusted, replace it in `install.sh`, `SECURITY.md` and this file, rotate the two secrets, and publish a release signed with the new key.
