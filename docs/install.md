# Install guide

How to install, upgrade, roll back and remove the Secure MCP Gateway on each platform and profile (SRS FR-18.1). For a first run after installing, go to the [quick start](quickstart.md).

**Release status.** No release has been published yet. Until the first tag exists, `install.sh` and Homebrew have nothing to download; build from source (below). The release workflow (`.github/workflows/release.yml`) is in place and the sections on release archives describe what it publishes.

## What gets installed

| Binary | Purpose |
|---|---|
| `smcpd` | The Gateway daemon |
| `smcpctl` | Command-line tool: bootstrap, configuration, policy, approvals, packages, operations |
| `smcp-refserver` | Read-only reference MCP server that `smcpctl bootstrap` packages as the example backend |
| `smcp-stdio`, `smcp-session` | Harness adapters for local clients ([adapters.md](adapters.md)) |
| `smcp-connect` | Relay for cloud agents through the Remote Access Profile ([remote-access.md](remote-access.md)); also published as the npm package `smcp-connect` |

## Platforms and profiles

| Host | Profile | What runs |
|---|---|---|
| Linux x86_64 or arm64 with rootless Podman (crun), nftables, cgroup v2, systemd and AppArmor or SELinux | **Enforced** | Every backend in a rootless Podman sandbox; health can be `healthy`; release label "enforced" only for a build that passed AT-01 to AT-21 |
| macOS arm64 or x86_64 | **Standalone** | Backends as plain subprocesses; health always `degraded: unconfined`; high-risk servers refused; label "not enforced" |
| Linux without the enforced prerequisites | **Standalone** | As macOS |

The profile is chosen by `[profile] mode`: `auto` (default) picks enforced when every prerequisite is present, `enforced` refuses to start without them, `standalone` never sandboxes. `smcpctl runtime doctor` lists what is missing on a Linux host. See [sandbox.md](sandbox.md).

## Option 1: install.sh (Linux and macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh
# or a fixed version and directory
sh install.sh --version v0.1.0 --dir "$HOME/.local/bin"
```

The script detects the OS and architecture, downloads `smcp_<version>_<os>_<arch>.tar.gz` and `smcp_<version>_checksums.txt` from the GitHub release, checks the archive's SHA-256 against the checksum file and installs the binaries into `~/.local/bin` (or `--dir`). It never runs `sudo`; when the directory is not writable it stops and prints the command to run. Options: `--version <tag>`, `--dir <path>`, `--repo <owner/name>`, `--help`.

### Release signature check

`install.sh` verifies the archive against the checksum file. The checksum file itself is signed by the release workflow with Sigstore cosign (keyless, GitHub OIDC) and the bundle is published next to it as `smcp_<version>_checksums.txt.sigstore.json`. Verify it before trusting the checksums:

```sh
cosign verify-blob --bundle smcp_<version>_checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ethan03805/Secure-MCP-Gateway/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  smcp_<version>_checksums.txt
sha256sum --check --ignore-missing smcp_<version>_checksums.txt
```

`install.sh` does not run `cosign` itself. SRS FR-13.1 asks for minisign-signed archives with the key embedded in `install.sh`; that is not implemented, and `SECURITY.md` will publish the release key with the first release.

## Option 2: Homebrew (macOS and Linux)

The formula template is `packaging/homebrew/smcp.rb.tmpl`, rendered per release by `scripts/render-brew-formula.sh`. The tap repository (`ethan03805/homebrew-tap`) does not exist yet. Once it does:

```sh
brew install ethan03805/tap/smcp
```

Homebrew checks the archive's SHA-256 from the formula. The formula installs the same binaries as `install.sh`.

## Option 3: from source

Needs Go (the version in `go.mod`) and git. Node.js is not needed: the console is committed prebuilt in `console/dist` and embedded with `go:embed`.

```sh
git clone https://github.com/ethan03805/Secure-MCP-Gateway.git
cd Secure-MCP-Gateway
make build                       # smcpd and smcpctl into build/bin
go build -o build/bin/ ./cmd/... # all six binaries
export PATH="$PWD/build/bin:$PATH"
```

Builds with cgo (the default when a C compiler is present) use DuckDB for the Observation Store and can export Parquet. Release archives are built with `CGO_ENABLED=0` and use the JSON Lines store instead ([observation.md](observation.md)).

## Create an instance

```sh
smcpctl bootstrap --dir ~/smcp
```

This writes `~/smcp/smcp.toml`, `~/smcp/policy.json` and `~/smcp/state/` (keys, local CA, journal, the packaged reference server). Ports default to `127.0.0.1:8443` (harness) and `127.0.0.1:8444` (control API and console); change them with `--port` and `--admin-port`. The [quick start](quickstart.md) explains the prompts and what to do next.

CP-46 names standard locations (`~/Library/Application Support/smcp-gateway/` on macOS, `$XDG_CONFIG_HOME/smcp-gateway` and `$XDG_STATE_HOME/smcp-gateway` on Linux, `/etc/smcp` and `/var/lib/smcp` for the Enforced profile). `bootstrap` uses the directory you give it; pass one of those paths to follow CP-46.

## Run as a service

`smcpctl` has no command that installs a service on macOS; run `smcpd --config ~/smcp/smcp.toml` in a terminal, or write a launchd user agent with the label `com.smcp.gateway` (`~/Library/LaunchAgents/com.smcp.gateway.plist`). `smcpctl upgrade` and `smcpctl uninstall` find and use that label, or the systemd unit `smcpd.service`, when present.

On Linux for the Enforced profile, `packaging/linux/install-enforced.sh` prepares the host as root:

```sh
sudo packaging/linux/install-enforced.sh --check            # prerequisites only; changes nothing
sudo packaging/linux/install-enforced.sh --bin-dir ./build/bin
```

It checks every prerequisite before changing anything, then creates the CP-46 service identities, subordinate ID ranges, directories, the nftables table `inet smcp` and the systemd units `smcpd.service` and `smcp-nftables.service`. It is idempotent. `--bin-dir` installs `smcpd`, `smcpctl` and `smcp-refserver` into `/usr/local/bin`.

The unit runs `/usr/local/bin/smcpd --config /etc/smcp/smcp.toml` as `smcp-core` with `/var/lib/smcp`, `/run/smcp` and `/var/log/smcp` writable. The configuration it starts needs, in addition to what `bootstrap` writes:

```toml
[state]
dir = "/var/lib/smcp/state"

[profile]
mode = "enforced"          # refuse to start when a prerequisite is missing

[runtime]
sandbox = "podman"
cgroup_manager = "cgroupfs"

[[runtime.server]]         # one per backend that needs host paths
alias = "ref"
[[runtime.server.mount]]
source = "/srv/smcp-share" # readable by other users: instances run under subordinate UIDs
```

Then `sudo packaging/linux/install-enforced.sh --start`. The enforced profile is exercised in CI (`scripts/ci-integration.sh`, linux-integration job) with smcpd started directly; the path through `smcpd.service` under a real systemd has not been exercised yet. Every `[runtime]` key, the mount rules and the startup refusal are in [sandbox.md](sandbox.md#installing-on-a-linux-host).

## Upgrade and rollback

```sh
smcpctl upgrade --config ~/smcp/smcp.toml --release <dir with new binaries and SHA256SUMS> \
  --passphrase-file <backup passphrase file>
```

The upgrade checks the new binaries against `SHA256SUMS`, takes an encrypted pre-upgrade backup, stops dispatch, swaps the binaries (keeping `<name>.prev`), migrates the configuration's `schema_version`, starts the Gateway and waits up to 60 s (CP-47) for it to leave fail-closed. If any step fails it restores the backup and the previous binaries and records `upgrade_rolled_back`. Pass `--start-cmd` and `--stop-cmd` when the Gateway is not run by launchd or systemd. The release-signature check is not part of `smcpctl upgrade`; verify the release first as above. See [operations/upgrade-uninstall.md](operations/upgrade-uninstall.md) and the [upgrade rollback runbook](runbooks/upgrade-rollback.md).

Homebrew users run `brew upgrade smcp` and then restart the Gateway; that path has no automatic backup, so run `smcpctl backup` first.

## Uninstall

```sh
smcpctl uninstall --config ~/smcp/smcp.toml           # services and binaries; keeps evidence
smcpctl uninstall --config ~/smcp/smcp.toml --purge   # also configuration, state, keys, journal
```

Without `--purge` the configuration, the state directory and the evidence journal stay, so `smcpctl journal verify` still works afterwards. `--purge` asks for the installation ID (`smcpctl keys status` shows it) before deleting. On the Enforced profile it also removes the service identities. Homebrew installs are removed with `brew uninstall smcp` after `smcpctl uninstall`.

## Verify an installation

```sh
smcpctl version --config ~/smcp/smcp.toml   # with a running Gateway, also its profile and label
smcpctl health --config ~/smcp/smcp.toml
smcpctl journal verify --config ~/smcp/smcp.toml
smcpctl doctor --config ~/smcp/smcp.toml    # client configuration and CA trust
```
