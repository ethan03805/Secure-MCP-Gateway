# Install guide

How to install, upgrade, roll back and remove the Secure MCP Gateway on each platform and profile (SRS FR-18.1). For a first run after installing, go to the [quick start](quickstart.md).

**Release status.** v1.2.0 is the latest release (2026-10-19, rehearsed with v1.2.0-rc.1 on the same commit); it is the first with the `smcp` `.deb`, `.rpm` and macOS `.pkg` packages (Option 4). The pre-release `v1.3.0-beta.1` (2026-10-20) adds the desktop application packages for Linux and macOS and the ContextForge catalog; it has no Windows files, no `.pkg` and no Sigstore bundle, because its release run stopped at the SBOM license check after publishing (fixed on main). The pre-release `v1.3.0-beta.2` (2026-10-20) also has the Windows zip archives and the `smcp` `.msi` for x64 and arm64; it has no `.pkg`, no `smcp-desktop` `.msi` (built on main since) and no Sigstore bundle, because its release run stopped at the Windows zip check after publishing (fixed on main). v1.1.0 was released on 2026-10-18 (main `935dc4d`, rehearsed with v1.1.0-rc.1 and rc.2; rc.2 and v1.1.0 are the same commit). v1.0.0 was the first final release, rehearsed with v1.0.0-rc.1 to rc.3 (rc.3 and v1.0.0 are the same commit, `17b84ba`). GitHub's latest-release link skips pre-releases, so `install.sh` without `--version` installs the latest final release and a pre-release needs `--version`. The release workflow writes each final release's formula to the Homebrew tap (rehearsed with v1.0.0-rc.2, [verification/FR-13.3.md](verification/FR-13.3.md)). For v1.1.0 the `tap` workflow installed the formula and the archive on macOS and Ubuntu and found every binary equal to the release archive (run 39178720966; for v1.0.0, run 39096814323). Building from source (below) needs no release. The sections on release archives describe what the release workflow (`.github/workflows/release.yml`) publishes. Since v1.1.0 the archives also carry the build recipe, the lockfiles, `PROVENANCE.md` and `THIRD_PARTY_NOTICES.txt`, and their SBOMs pass the license check (FR-12.8, FR-12.1). [release-checklist.md](release-checklist.md) is the release procedure.

The short path on macOS or Linux, once a release exists:

```sh
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh   # or: brew install ethan03805/tap/smcp
smcpctl install          # Standalone: CP-46 directories, keys, smcp.toml, launchd agent or systemd user unit, health check
```

Which path to take (the desktop application and the Windows files are planned for v1.3.0 and are in the pre-releases only):

| Computer | Command-line Gateway | Desktop application |
|---|---|---|
| macOS on Apple silicon | `install.sh`, Homebrew or the `.pkg` (macOS 13 or later) ([Option 1](#option-1-installsh-linux-and-macos), [Option 4](#option-4-platform-packages-deb-rpm-macos-pkg-and-dmg-appimage-msi)) | The `.dmg` (macOS 14 or later), which carries the commands too |
| macOS on Intel | `install.sh` or Homebrew | None (the application is built for Apple silicon only) |
| Debian, Ubuntu, Fedora, RHEL | `install.sh` or the `smcp` `.deb` or `.rpm` | The `smcp-desktop` `.deb` or `.rpm`, installed together with the `smcp` package of the same version |
| Other Linux with a graphical desktop | `install.sh` | The AppImage, which carries the commands |
| Windows 11 23H2 or later (x64, arm64) | `install.ps1` or the `smcp` `.msi` ([Option 1a](#option-1a-installps1-windows-planned-for-v130)) | The `smcp-desktop` `.msi`, which carries the commands |
| Windows Server 2022 and 2025 | `install.ps1` or the `smcp` `.msi` | None (Windows Server gets the command-line Gateway only) |

None of the installers carries an Apple Developer ID or Authenticode signature; check each download with minisign and SHA-256 as described below before you open it.

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
| Windows 11 23H2 or later (x64, arm64), Windows Server 2022 and 2025 (planned for v1.3.0, on main) | **Standalone** | Per user: backends as child processes in Job Objects, label `not enforced (windows-user)`. Machine mode (`smcpctl install --machine`): the service under `NT SERVICE\smcpd`, each backend in an AppContainer with egress only through the Egress Broker, health `degraded: partially_confined`, label `not enforced (windows-machine)` ([windows-port.md](windows-port.md)) |

The profile is chosen by `[profile] mode`: `auto` (default) picks enforced when every prerequisite is present, `enforced` refuses to start without them, `standalone` never sandboxes. `smcpctl runtime doctor` lists what is missing on a Linux host. See [sandbox.md](sandbox.md).

## Option 1: install.sh (Linux and macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh
# or a fixed version and directory
sh install.sh --version v1.1.0 --dir "$HOME/.local/bin"
```

The script detects the OS and architecture and downloads `smcp_<version>_<os>_<arch>.tar.gz`, `smcp_<version>_checksums.txt` and `smcp_<version>_checksums.txt.minisig` from the GitHub release. It then, in order:

1. verifies the minisign signature of the checksum file with the release public key embedded in the script, and checks that the signed trusted comment names that checksum file (SRS FR-13.2);
2. when `cosign` is installed, downloads `smcp_<version>_checksums.txt.sigstore.json` and verifies it with `cosign verify-blob` against the release workflow identity (security review RR-01); when `cosign` is not installed it says so;
3. checks the archive's SHA-256 against the verified checksum file.

If any check fails it installs nothing and removes its temporary directory. Otherwise it installs the binaries into `~/.local/bin` (or `--dir`). It never runs `sudo`; when the directory is not writable it stops and prints the command to run.

The signature check uses `minisign` when it is installed and otherwise OpenSSL 3 (`openssl pkeyutl`, Ed25519 over the BLAKE2b-512 digest). macOS ships LibreSSL as `/usr/bin/openssl`, which cannot do this; install `minisign` first (`brew install minisign`), or use Homebrew for the whole install. Debian 12, Ubuntu 22.04 and later have OpenSSL 3.

Options: `--version <tag>`, `--dir <path>`, `--repo <owner/name>`, `--base-url <url>` (a mirror holding the same files), `--pubkey <key>` (the release key of a fork), `--no-cosign` (skip the cosign check even when cosign is installed), `--help`.

### Release signing key

```
untrusted comment: minisign public key 064FAC0C64ACCED0
RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
```

The same key is in `SECURITY.md` and embedded in `install.sh`. To check a release by hand:

```sh
minisign -Vm smcp_<version>_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
cosign verify-blob --bundle smcp_<version>_checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ethan03805/Secure-MCP-Gateway/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  smcp_<version>_checksums.txt
sha256sum --check --ignore-missing smcp_<version>_checksums.txt
```

## Option 1a: install.ps1 (Windows, planned for v1.3.0)

Windows support is built on main for v1.3.0 (SRS FR-21; status in [windows-port.md](windows-port.md)), and `v1.3.0-beta.2` is the first pre-release with Windows files. From v1.3.0 on, each release carries `smcp_<version>_windows_amd64.zip` and `smcp_<version>_windows_arm64.zip` with `smcpd.exe`, `smcpctl.exe`, `smcp-session.exe`, `smcp-stdio.exe` and `smcp-connect.exe`, listed in the same signed checksum file. `install.ps1` installs them for the current user, without elevation:

```powershell
irm https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.ps1 | iex
# or a fixed version, from a downloaded copy of the script
powershell -ExecutionPolicy Bypass -File install.ps1 -Version v1.3.0
```

Windows refuses to run a downloaded script by its default execution policy, so these are the two supported invocations. With `irm | iex` the options are environment variables (`$env:SMCP_VERSION = 'v1.3.0'`). The script checks the same things as `install.sh`, in the same order: the minisign signature and trusted comment of the checksum file with the embedded release key, the Sigstore bundle when `cosign.exe` is installed, then the archive's SHA-256 with `Get-FileHash`. The signature is checked with `minisign.exe` when it is on `PATH` (`winget install jedisct1.minisign`) and otherwise with the OpenSSL 3 that Git for Windows installs. With neither, or when a check fails, it installs nothing and removes its temporary directory. It installs into `%LOCALAPPDATA%\Programs\smcp-gateway` (or `-Dir`) and prints the command that adds that directory to the user `PATH`.

Options: `-Version <tag>`, `-Dir <path>`, `-Repo <owner/name>`, `-BaseUrl <url>` (a mirror over https; plain http only on `127.0.0.1` or `localhost`), `-From <dir>` (release files already downloaded, for example by a browser), `-PubKey <key>`, `-NoCosign`, `-Help`.

After installing the binaries, `smcpctl install` sets up the Gateway for the current user, without elevation: `%LOCALAPPDATA%\smcp-gateway` with DACLs for the user, SYSTEM and Administrators only, keys protected with DPAPI, and a Task Scheduler task that starts `smcpd` at logon (or, when Windows refuses the task to a standard user, a `HKCU\...\Run` entry). `smcpctl install --machine`, from an elevated prompt, installs the machine mode instead: the Windows service `smcpd` under `NT SERVICE\smcpd`, with its files in `%ProgramData%\smcp-gateway`; enable each packaged server from an elevated prompt (`smcpctl package enable`) so that it gets its AppContainer. `smcpctl install --wsl --wsl-version <tag>` installs the WSL2 mode: the Linux build in the WSL2 distribution `smcp-gateway`, with interop off (not yet run on a WSL2 host). All three are labelled "not enforced": MCP servers are not contained on Windows the way the Linux Enforced profile contains them ([windows-port.md](windows-port.md)).

**Unsigned binaries.** The Windows binaries carry no Authenticode signature yet (SRS FR-21.22; signing is FR-20.30). SmartScreen may warn when they first run, and Smart App Control blocks them outright when it is on. Verify them instead with minisign and SHA-256: `install.ps1` does this before installing and only then removes the Mark of the Web from the installed files. To check a release by hand in PowerShell:

```powershell
minisign -Vm smcp_<version>_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
(Get-FileHash -Algorithm SHA256 smcp_<version>_windows_amd64.zip).Hash.ToLower()   # compare with the line in the checksum file
```

## Option 2: Homebrew (macOS and Linux)

```sh
brew install ethan03805/tap/smcp
smcpctl install
```

The release workflow writes `Formula/smcp.rb` to the tap repository [ethan03805/homebrew-tap](https://github.com/ethan03805/homebrew-tap) with GoReleaser (`brews` in `.goreleaser.yaml`); its URLs and SHA-256 values are those of the release archives for darwin and linux. Homebrew checks the archive's SHA-256 from the formula; it does not check the minisign signature. The formula installs the same binaries as `install.sh`. `packaging/homebrew/smcp.rb.tmpl` with `scripts/render-brew-formula.sh` renders an equivalent formula by hand.

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

## Option 4: platform packages (.deb, .rpm, macOS .pkg and .dmg, AppImage, .msi)

Specified for release v1.3.0 (SRS FR-20.17 to FR-20.26). v1.2.0 has the `smcp` `.deb`, `.rpm` and `.pkg`; `v1.3.0-beta.1` adds the desktop `.deb`, `.rpm`, AppImage and `.dmg`; `v1.3.0-beta.2` adds the `smcp` `.msi`; the `smcp-desktop` `.msi` is built on main and in no published release yet. The release workflow builds them from the tag, installs, exercises and removes each one on a runner of its platform before it publishes anything (`.github/workflows/installers.yml` with `scripts/package-smoke.sh`), and lists each in the signed checksum file. The desktop application installers (`smcp-desktop` `.deb` and `.rpm`, the `.dmg` and the AppImage) are built and smoke-tested the same way (`scripts/desktop-smoke.sh`); the `.dmg` needs a Mac to build, and a release made while no macOS runner was available has none. The Windows `.msi` of the command-line Gateway is built with the WiX Toolset (`packaging/installers/windows`) and installed, checked and removed on Windows x64 and arm64 runners. The `smcp-desktop` `.msi` with the desktop application (Windows 11 x64 and arm64, SRS FR-20.20) is built with the Tauri bundler and installed, started and removed on the same runners (`scripts/desktop-msi-smoke.ps1`).

| File | Platform | Installs |
|---|---|---|
| `smcp_<version>_amd64.deb`, `smcp_<version>_arm64.deb` | Debian, Ubuntu | `smcpd`, `smcpctl`, `smcp-session`, `smcp-stdio`, `smcp-connect`, `smcp-refserver` in `/usr/bin`; README, CHANGELOG, LICENSE, SBOM, `PROVENANCE.md` and the third-party notices in `/usr/share/doc/smcp`; the marker `/usr/lib/smcp/package-format` |
| `smcp-<version>-1.x86_64.rpm`, `smcp-<version>-1.aarch64.rpm` | Fedora, RHEL and derivatives | The same |
| `smcp_<version>_darwin_arm64.pkg` | macOS 13 or later on Apple silicon | The same binaries in `/usr/local/lib/smcp`, each with an ad-hoc signature, with links in `/usr/local/bin`; documents in `/usr/local/share/doc/smcp`. The desktop application is in the `.dmg` (next row): the `.pkg` is built on Linux, and the application only on a Mac |
| `smcp-desktop_<version>_darwin_arm64.dmg` | macOS 14 or later on Apple silicon | A disk image with `Secure MCP Gateway.app`, which holds the six commands in `Contents/MacOS`; drag it to Applications. No administrator password is needed, and the copy belongs to your user, so `smcpctl doctor` reports it as writable (SR-4.11-2) |
| `smcp-desktop_<version>_amd64.deb`, `smcp-desktop_<version>_arm64.deb`, `smcp-desktop-<version>-1.x86_64.rpm`, `smcp-desktop-<version>-1.aarch64.rpm` | Debian, Ubuntu; Fedora, RHEL (WebKitGTK 4.1 and a StatusNotifier or AppIndicator tray) | The desktop application in `/usr/bin/smcp-desktop` with its menu entry; depends on the `smcp` package of exactly the same version, which provides the commands, so install both together |
| `smcp_<version>_windows_amd64.msi`, `smcp_<version>_windows_arm64.msi` | Windows 11 23H2 or later, Windows Server 2022 and 2025 | `smcpd.exe`, `smcpctl.exe`, `smcp-refserver.exe`, `smcp-session.exe`, `smcp-stdio.exe` and `smcp-connect.exe` per machine in `%ProgramFiles%\smcp-gateway` (users can read and run them, not change them), the license and documents, and that directory on the system `PATH`. No desktop application and no WebView2 |
| `smcp-desktop_<version>_windows_amd64.msi`, `smcp-desktop_<version>_windows_arm64.msi` | Windows 11 23H2 or later (x64, arm64); not for Windows Server | The desktop application per machine in `%ProgramFiles%\Secure MCP Gateway`, with the six commands beside it (users can read and run them, not change them), a Start menu entry and the `smcp` link scheme. The WebView2 runtime is part of Windows 11; on a computer without it, the package runs the embedded WebView2 bootstrapper, which downloads it. Not on the system `PATH`: the `smcp` `.msi` adds that |
| `smcp-desktop_<version>_linux_amd64.AppImage`, `smcp-desktop_<version>_linux_arm64.AppImage` | Other Linux distributions with a graphical desktop (the host provides the OpenGL, OpenGL ES and EGL libraries, as for every AppImage) | The desktop application with the six commands inside; runs without root and without a package manager. Like the `.dmg`, it is writable by your user |

A pre-release version such as `1.3.0-rc.1` is `1.3.0~rc.1` inside the Linux packages, so that the package managers order it before `1.3.0`, and `1.3.0.rc.1` in their file names (`smcp_1.3.0.rc.1_amd64.deb`), because a GitHub release asset name cannot contain `~`.

**What the packages do and do not do.** They place files only (FR-20.21): no configuration, state, keys, service unit or account is created and nothing is started, and an existing installation's configuration, journal, keys and backups are left as they are. Every file is owned by root and cannot be written by your user, so an agent running as you cannot replace the Gateway (SR-4.11-2); `smcpctl doctor` reports a Gateway binary that your user can write, as `install.sh` into `~/.local/bin` leaves it. The `.deb` and `.rpm` declare no dependency and have one maintainer script, the pre-removal script, which stops a system `smcpd` service on removal. After installing, set the Gateway up as with any other method: `smcpctl install` (below), or `smcpctl bootstrap`. `smcpctl upgrade` refuses to replace packaged binaries; upgrade with the package manager or the new `.pkg`.

### Verify the package before installing

The packages carry no platform signature yet (Apple Developer ID and notarization are deferred, FR-20.29). Check them against the release's signed checksum file instead, exactly as the archives: download the package, `smcp_<version>_checksums.txt`, its `.minisig` and its `.sigstore.json` from the release page into one directory, then

```sh
minisign -Vm smcp_<version>_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
cosign verify-blob --bundle smcp_<version>_checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ethan03805/Secure-MCP-Gateway/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  smcp_<version>_checksums.txt
sha256sum --check --ignore-missing smcp_<version>_checksums.txt      # Linux
shasum -a 256 --check --ignore-missing smcp_<version>_checksums.txt  # macOS
```

On Windows, in PowerShell, with `minisign.exe` (`winget install jedisct1.minisign`) and, optionally, `cosign.exe`:

```powershell
minisign -Vm smcp_<version>_checksums.txt -P RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq
(Get-FileHash smcp-desktop_<version>_windows_amd64.msi -Algorithm SHA256).Hash.ToLower()   # compare with its line in the checksum file
```

`minisign` must print `Signature and comment signature verified` and a trusted comment naming that checksum file, `cosign` `Verified OK`, and the checksum line of your package `OK` (on Windows, the hash must equal the one on the package's line). If any check fails, do not install the package.

**Prompts for an unsigned installer** (until Developer ID signing, FR-20.29, and Authenticode signing, FR-20.30, are in place). These are the prompts a verified package is expected to show; any other wording, such as a damaged or revoked package, means you should download and check it again.

- macOS 15 and later, opening the `.pkg` or the application from the `.dmg` in Finder: the dialog **"<name>" Not Opened** ("Apple could not verify ... is free of malware"), with Done and Move to Trash. Click Done, open System Settings, Privacy & Security, find the message that the item was blocked to protect your Mac, click **Open Anyway** and confirm with your password. `sudo installer -pkg` in Terminal shows no prompt. Details are in [Install](#install) below.
- Windows, opening a downloaded `.msi` from the browser or Explorer: SmartScreen shows **Windows protected your PC** ("Microsoft Defender SmartScreen prevented an unrecognized app from starting") with only a Don't run button. Select **More info**, check that the file name is the one you verified, and select **Run anyway**. `msiexec /i` from a terminal does not show this dialog.
- Windows, the User Account Control prompt that follows: **Do you want to allow this app from an unknown publisher to make changes to your device?** with **Publisher: Unknown** and the file name. Unknown publisher is expected, because the `.msi` carries no Authenticode signature; select Yes only for the file you verified.
- Windows 11 with **Smart App Control** on: it blocks unsigned installers and programs outright and offers no option to run them. The packages cannot be installed while it is on; the choice to turn it off (Windows Security, App & browser control, Smart App Control settings) is a decision for that computer, and it covers every unsigned program, not only this one.

Packages are downloaded from the [release page](https://github.com/ethan03805/Secure-MCP-Gateway/releases) once a release has them.

`install.sh --package` does the same checks for you: it downloads the package of this host's format (`--package=deb`, `--package=rpm` or `--package=pkg` to choose), verifies the checksum file's minisign signature with the release key, the Sigstore bundle when `cosign` is installed and the package's SHA-256, and only then saves it (in `--dir`, default the current directory). Run as root it also installs the package with `apt-get`, `dnf` or `installer`, which upgrades an installed `smcp`; otherwise it prints that command. A package that fails a check is neither saved nor installed, and an installed older version stays as it is:

```sh
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sudo sh -s -- --version v<version> --package
```

After an upgrade, restart a running Gateway service (`systemctl --user restart smcpd.service`, `sudo systemctl restart smcpd.service` for the Enforced profile, or `launchctl kickstart -k gui/$(id -u)/com.smcp.gateway` on macOS).

### Install

```sh
sudo apt install ./smcp_<version>_amd64.deb            # Debian, Ubuntu
sudo dnf install ./smcp-<version>-1.x86_64.rpm         # Fedora, RHEL
sudo installer -pkg smcp_<version>_darwin_arm64.pkg -target /   # macOS
smcpctl version
# Desktop application, Linux: both packages in one command.
sudo apt install ./smcp_<version>_amd64.deb ./smcp-desktop_<version>_amd64.deb
sudo dnf install ./smcp-<version>-1.x86_64.rpm ./smcp-desktop-<version>-1.x86_64.rpm
```

On Windows, from an elevated PowerShell (check the `.msi` against the checksum file first, as in [Option 1a](#option-1a-installps1-windows-planned-for-v130)):

```powershell
msiexec /i smcp_<version>_windows_amd64.msi /qn
smcpctl version          # in a new terminal, which has the new PATH
msiexec /x smcp_<version>_windows_amd64.msi /qn   # remove; configuration, state and the journal stay
```

The `.msi` registers no service: run `smcpctl install` (per user) or `smcpctl install --machine` (Windows service) afterwards, as after a `.deb`. `smcpctl uninstall` and `smcpctl upgrade` leave the packaged binaries to Windows Installer. Installing needs no network access: the package carries every file it installs. Removing either `.msi` (not upgrading it) first runs `smcpctl uninstall --package-removal` as the system account, as the `.deb` and `.rpm` pre-removal script does: it stops and removes the Windows service `smcpd` that `smcpctl install --machine` created from the package, and keeps the configuration, state, journal, evidence key and backups in `%ProgramData%\smcp-gateway`, so `smcpctl journal verify` works after a fresh install (FR-20.22). A per-user installation (the scheduled task) stays: run `smcpctl uninstall` as each user before removing the package, or `smcpctl uninstall --purge` to delete its configuration, state and journal as well.

The desktop application on Windows 11 is the `smcp-desktop` `.msi` (`msiexec /i smcp-desktop_<version>_windows_amd64.msi`, or double-click it and accept the User Account Control prompt). It is not signed, so SmartScreen may show "Windows protected your PC" when it is opened from a browser download; check it against the checksum file first, then select More info and Run anyway. Start the application from the Start menu; its first-run setup runs `smcpctl install` for your user. Remove it in Settings, Apps, or with `msiexec /x`; configuration, state and the journal stay.

On macOS, `sudo installer` in Terminal installs the package without a Gatekeeper prompt. Opening the downloaded `.pkg` in Finder instead shows, on macOS 15 and later, the dialog **"smcp_<version>_darwin_arm64.pkg" Not Opened** ("Apple could not verify ... is free of malware that may harm your Mac or compromise your privacy"), with the buttons Done and Move to Trash. This is the expected prompt for a package without a Developer ID signature; any other wording (for example a damaged or revoked package) is not, and you should check the download again. After verifying the package as above, click Done, open System Settings, Privacy & Security, scroll to Security, where the message **"smcp_<version>_darwin_arm64.pkg" was blocked to protect your Mac** is shown with an **Open Anyway** button; click it, confirm with your password, and the Installer opens. The button is offered for about an hour after the blocked attempt. Earlier macOS versions show a similar "cannot be opened because it is from an unidentified developer" dialog and the same Open Anyway button.

### Remove a Linux package

```sh
smcpctl uninstall --config ~/.config/smcp-gateway/smcp.toml   # first, as each user with a Standalone service
sudo apt remove smcp-desktop smcp        # or: sudo dnf remove smcp-desktop smcp
```

Removing the package removes its files and, through its pre-removal script (`smcpctl uninstall --package-removal`), stops, disables and removes a system-wide `smcpd.service` and `smcp-nftables.service` that `smcpctl install --profile enforced` created. It keeps the configuration, the state with the evidence journal and the evidence public key, the backups, and every other host object, so `smcpctl journal verify --dir <state>/journal --key <state>/keys/evidence-genesis.pub` still works after a fresh install (FR-20.22). The package manager does not run as each user, so per-user services (the Standalone launchd agent or systemd user unit) are removed by `smcpctl uninstall` before the package is removed; to delete configuration, state, keys and the journal as well, run `smcpctl uninstall --purge` before removing the package. `apt purge smcp` removes nothing more: the package owns no configuration file.

### Remove the macOS package

macOS has no command that removes a package. Remove the per-user service first, then the files the `.pkg` installed, then its receipt:

```sh
smcpctl uninstall --config "$HOME/Library/Application Support/smcp-gateway/config/smcp.toml"   # or --purge
sudo rm -f /usr/local/bin/smcpd /usr/local/bin/smcpctl /usr/local/bin/smcp-session \
  /usr/local/bin/smcp-stdio /usr/local/bin/smcp-connect /usr/local/bin/smcp-refserver
sudo rm -rf /usr/local/lib/smcp /usr/local/share/doc/smcp
sudo pkgutil --forget io.github.ethan03805.smcp
```

`smcpctl uninstall` leaves the packaged binaries in place (it says so) and, without `--purge`, keeps the configuration, journal, keys and backups. `pkgutil --files io.github.ethan03805.smcp` lists what the package installed before you forget it.

## Install as a service: smcpctl install

`smcpctl install` sets up a complete installation in one idempotent command (SRS FR-13.4 to FR-13.6). It reports every step as `created` or `present` (`updated` when a unit file it wrote earlier has changed); a second run reports `present` throughout and leaves configuration, keys, policy and the journal byte-for-byte unchanged.

**Standalone (macOS and Linux, as your user):**

```sh
smcpctl install                         # prompts for the administrator and Session Approver passwords
smcpctl install --admin-password-file a.pw --approver-password-file b.pw --port 8443 --admin-port 8444
```

| Step | macOS | Linux |
|---|---|---|
| CP-46 directories (0700) | `~/Library/Application Support/smcp-gateway/{config,state}`, `~/Library/Logs/smcp-gateway` | `$XDG_CONFIG_HOME/smcp-gateway`, `$XDG_STATE_HOME/smcp-gateway` with `log/`, `$XDG_RUNTIME_DIR/smcp-gateway` |
| Keys, local CA, reference package | in the state directory (as `smcpctl bootstrap`) | same |
| `smcp.toml` and `policy.json` | in `config/`, with `[profile] mode = "standalone"` and `[log] file` in the log directory | in the configuration directory, same values |
| Service | launchd user agent `~/Library/LaunchAgents/com.smcp.gateway.plist`, loaded with `launchctl bootstrap gui/<uid>` | systemd user unit `~/.config/systemd/user/smcpd.service`, enabled and started with `systemctl --user` |
| Health | waits up to `--health-timeout` (60 s) for the control API; fails on `fail-closed` | same |

It ends by printing that the installation is not enforced. The unit runs the `smcpd` next to `smcpctl` (`--bin-dir` to choose another directory). `--no-start` writes the unit without loading it and skips the health check. Other flags are those of `bootstrap`: `--port`, `--admin-port`, `--metrics-port`, `--notify`, `--sandbox`, `--bootstrap-token`. On Linux a user unit stops at logout unless lingering is on: `loginctl enable-linger "$USER"`. An existing configuration is never rewritten; if it selects another profile, install says so.

**Enforced (Linux, as root):**

```sh
sudo smcpctl install --profile enforced --admin-password-file a.pw --approver-password-file b.pw
```

It runs the copy of `packaging/linux/install-enforced.sh` embedded in `smcpctl` with `--bin-dir` set to the directory of `smcpctl` (which must also hold `smcpd` and `smcp-refserver`). That script checks every Section 1.5.1 prerequisite before changing the host and stops naming the missing ones; then it creates the CP-46 service identities and subordinate ranges, the directories, the nftables table, the AppArmor profile (when AppArmor is enabled) and the systemd units, and installs the binaries into `/usr/local/bin`. When `smcpctl` comes from the smcp `.deb` or `.rpm` (Option 4), it passes `--packaged-bin /usr/bin` instead: nothing is copied, `smcpd.service` runs `/usr/bin/smcpd`, and an upgrade of the package replaces the file the service runs (restart it afterwards with `sudo systemctl restart smcpd.service`). A copy left in `/usr/local/bin` by an earlier archive install is reported with the command that removes it, because the package manager never updates it. `smcpctl install` then bootstraps the state into `/var/lib/smcp/state` and the policy into `/var/lib/smcp/policy` (owned by `smcp-core`), writes `/etc/smcp/smcp.toml` (root:smcp 0640) with `[profile] mode = "enforced"`, `[runtime] sandbox = "podman"`, `cgroup_manager = "cgroupfs"`, a mount of `/srv/smcp/sandbox` for the reference server `[log] file = "/var/log/smcp/smcpd.log"` and `[backup] dir = "/var/lib/smcp/backups"` (smcpd cannot write next to the configuration; installations made by v1.1.0 or earlier lack this line, see the Enforced walkthrough below), publishes the client view (`/var/lib/smcp/public/ca.crt`, a copy of the Gateway CA certificate, and `client.json`, the listener addresses; mode 0644, no secret) for the desktop application and `smcpctl connect` run by users who cannot read `/etc/smcp`, starts `smcp-nftables.service` and `smcpd.service`, and checks health. `smcpd` keeps the client view current after a CA rotation; `smcpctl uninstall --purge` removes it.

Remove either installation with `smcpctl uninstall` (below); without `--config` it finds the configuration that install wrote.

## Create an instance by hand

```sh
smcpctl bootstrap --dir ~/smcp
```

This writes `~/smcp/smcp.toml`, `~/smcp/policy.json` and `~/smcp/state/` (keys, local CA, journal, the packaged reference server). Ports default to `127.0.0.1:8443` (harness) and `127.0.0.1:8444` (control API and console); change them with `--port` and `--admin-port`. The [quick start](quickstart.md) explains the prompts and what to do next.

CP-46 names standard locations (`~/Library/Application Support/smcp-gateway/` on macOS, `$XDG_CONFIG_HOME/smcp-gateway` and `$XDG_STATE_HOME/smcp-gateway` on Linux, `/etc/smcp` and `/var/lib/smcp` for the Enforced profile). `bootstrap` uses the directory you give it; pass one of those paths to follow CP-46.

## Run as a service

`smcpctl install` (above) is the supported way. For an instance made with `bootstrap`, run `smcpd --config ~/smcp/smcp.toml` in a terminal, or write a launchd user agent with the label `com.smcp.gateway` (`~/Library/LaunchAgents/com.smcp.gateway.plist`). `smcpctl upgrade` and `smcpctl uninstall` find and use that label, or the systemd unit `smcpd.service`, when present.

On Linux for the Enforced profile, `smcpctl install --profile enforced` runs the following script for you; it can also be run directly from a checkout to prepare the host as root:

```sh
sudo packaging/linux/install-enforced.sh --check            # prerequisites only; changes nothing
sudo packaging/linux/install-enforced.sh --bin-dir ./build/bin
```

It checks every prerequisite before changing anything, then creates the CP-46 service identities, subordinate ID ranges, directories, the nftables table `inet smcp` and the systemd units `smcpd.service` and `smcp-nftables.service`. It is idempotent. `--bin-dir` installs `smcpd`, `smcpctl` and `smcp-refserver` into `/usr/local/bin`.

The unit runs `/usr/local/bin/smcpd --config /etc/smcp/smcp.toml` (`/usr/bin/smcpd` when installed from the smcp `.deb` or `.rpm`) as `smcp-core` with `/var/lib/smcp`, `/run/smcp` and `/var/log/smcp` writable. The configuration it starts needs, in addition to what `bootstrap` writes:

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

Then `sudo packaging/linux/install-enforced.sh --start`. The enforced profile is exercised in CI (linux-integration job): `scripts/ci-integration.sh` with smcpd started directly, and `scripts/ci-systemd.sh`, which installs with `smcpctl install --profile enforced` and runs `smcpd.service` under systemd. Every `[runtime]` key, the mount rules and the startup refusal are in [sandbox.md](sandbox.md#installing-on-a-linux-host).

## Upgrade and rollback

```sh
smcpctl upgrade --config ~/smcp/smcp.toml --release <dir with the downloaded release files> \
  --passphrase-file <backup passphrase file>
```

Download the release's checksum file, its `.minisig` and the archive for the host into one directory (`gh release download v1.1.0 -R ethan03805/Secure-MCP-Gateway -D <dir> -p 'smcp_1.1.0_checksums.txt*' -p 'smcp_1.1.0_<os>_<arch>.tar.gz'`). The upgrade verifies the minisign signature of the checksum file with the release key and the archive's SHA-256 against it, as `install.sh` does (FR-13.2), and changes nothing when either fails. It then takes an encrypted pre-upgrade backup, stops dispatch, swaps the binaries (keeping `<name>.prev`), migrates the configuration's `schema_version`, starts the Gateway and waits up to 60 s (CP-47) for it to leave fail-closed. If any step after the backup fails it restores the backup and the previous binaries and records `upgrade_rolled_back`. Pass `--start-cmd` and `--stop-cmd` when the Gateway is not run by launchd or systemd. See [operations/upgrade-uninstall.md](operations/upgrade-uninstall.md) and the [upgrade rollback runbook](runbooks/upgrade-rollback.md).

Homebrew users run `brew upgrade smcp` and then restart the Gateway; that path has no automatic backup, so run `smcpctl backup` first.

## Uninstall

```sh
smcpctl uninstall --config ~/smcp/smcp.toml           # services and binaries; keeps evidence
smcpctl uninstall --config ~/smcp/smcp.toml --purge   # also configuration, state, keys, journal
```

Without `--purge` the configuration, the state directory and the evidence journal stay, so `smcpctl journal verify` still works afterwards. `--purge` asks for the installation ID (`smcpctl keys status` shows it) before deleting. On the Enforced profile it also removes the service identities. Each profile removes only what its own install created: an installation whose configuration selects `[profile] mode = "enforced"` removes the system units, the nftables table `inet smcp`, the AppArmor profiles and the `smcp-srv` setup; any other installation removes only your launchd agent or systemd user unit, so a Standalone uninstall on a host that also has an Enforced installation leaves the Enforced one running. Homebrew installs are removed with `brew uninstall smcp` after `smcpctl uninstall`. Binaries installed by a platform package stay in place (`smcpctl uninstall` says so); remove them as in [Remove a Linux package](#remove-a-linux-package) or [Remove the macOS package](#remove-the-macos-package).

## Walkthrough: Standalone, from install to uninstall

The commands below take a clean macOS or Linux account through the whole life of a Standalone installation: install v1.0.0 with `install.sh` (signature and checksum checks), install the service, upgrade to v1.1.0 from the downloaded release files, and uninstall while keeping the evidence. Run them in an empty directory. CI runs this block as written on macOS arm64 and Ubuntu (`scripts/ci-install-guide.sh`, job `install-guide`) and fails when a step no longer works. On Linux a CI runner has no login session, so the script first enables lingering and sets `XDG_RUNTIME_DIR`, as a desktop session does.

<!-- ci-install-guide: standalone -->
```sh
# 1. Install v1.0.0 with install.sh. It verifies the minisign signature of the
#    checksum file and the archive's SHA-256 before it installs anything.
if [ "$(uname -s)" = Darwin ]; then brew install minisign; fi
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh -s -- --version v1.0.0
export PATH="$HOME/.local/bin:$PATH"
smcpctl version --short

# 2. Passwords of the administrator, the Session Approver and the pre-upgrade backup.
(umask 077 && openssl rand -hex 16 > admin.pw && openssl rand -hex 16 > approver.pw && openssl rand -hex 16 > backup.pw)

# 3. Install the service: a launchd user agent on macOS, a systemd user unit on Linux.
smcpctl install --admin-password-file admin.pw --approver-password-file approver.pw
case "$(uname -s)" in
  Darwin) cfg="$HOME/Library/Application Support/smcp-gateway/config/smcp.toml" ;;
  *) cfg="${XDG_CONFIG_HOME:-$HOME/.config}/smcp-gateway/smcp.toml" ;;
esac
smcpctl health --config "$cfg"

# 4. Upgrade to v1.1.0 from the release files (checked as install.sh does,
#    backed up first, rolled back automatically if the new version fails).
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m); case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
mkdir -p release
for f in smcp_1.1.0_checksums.txt smcp_1.1.0_checksums.txt.minisig "smcp_1.1.0_${os}_${arch}.tar.gz"; do
  curl -fsSL -o "release/$f" "https://github.com/ethan03805/Secure-MCP-Gateway/releases/download/v1.1.0/$f"
done
smcpctl upgrade --config "$cfg" --release release --passphrase-file backup.pw
smcpctl version --short
smcpctl health --config "$cfg"

# 5. Uninstall. The service and binaries go; the configuration, state and
#    journal stay. uninstall removes smcpctl too, so keep a copy to verify the journal.
cp "$HOME/.local/bin/smcpctl" smcpctl-kept
smcpctl uninstall --config "$cfg"
./smcpctl-kept journal verify --config "$cfg"
```

## Walkthrough: Enforced on Ubuntu, from install to uninstall

The same life cycle in the Enforced profile, on a Linux host that has the prerequisites of the table above (Ubuntu 24.04 with Podman, crun, uidmap, nftables and AppArmor) and an account with sudo. Run it in an empty directory. CI runs this block as written on Ubuntu (job `install-guide`).

<!-- ci-install-guide: enforced -->
```sh
# 1. Install v1.0.0 with install.sh (signature and checksum checks) into ./bin.
curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh -s -- --version v1.0.0 --dir "$PWD/bin"

# 2. Passwords of the administrator, the Session Approver and the pre-upgrade backup.
(umask 077 && openssl rand -hex 16 > admin.pw && openssl rand -hex 16 > approver.pw && openssl rand -hex 16 > backup.pw)

# 3. Install the Enforced profile: identities, directories, nftables table,
#    AppArmor profiles, systemd units, binaries in /usr/local/bin, smcpd.service started.
sudo bin/smcpctl install --profile enforced --admin-password-file admin.pw --approver-password-file approver.pw
sudo -u smcp-core smcpctl health --config /etc/smcp/smcp.toml

# 4. Upgrade to v1.1.0 from the release files.
arch=$(uname -m); case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
mkdir -p release
for f in smcp_1.1.0_checksums.txt smcp_1.1.0_checksums.txt.minisig "smcp_1.1.0_linux_${arch}.tar.gz"; do
  curl -fsSL -o "release/$f" "https://github.com/ethan03805/Secure-MCP-Gateway/releases/download/v1.1.0/$f"
done
#    Installations made by v1.1.0 or earlier keep backups next to the
#    read-only configuration; give them a writable backup directory once.
if ! sudo grep -q '^\[backup\]' /etc/smcp/smcp.toml; then
  sudo install -d -o smcp-core -g smcp -m 0700 /var/lib/smcp/backups
  printf '\n[backup]\ndir = "/var/lib/smcp/backups"\n' | sudo tee -a /etc/smcp/smcp.toml >/dev/null
  sudo systemctl restart smcpd.service
  until sudo -u smcp-core smcpctl health --config /etc/smcp/smcp.toml >/dev/null 2>&1; do sleep 1; done
fi
sudo smcpctl upgrade --config /etc/smcp/smcp.toml --release release --passphrase-file backup.pw
smcpctl version --short
sudo -u smcp-core smcpctl health --config /etc/smcp/smcp.toml

# 5. Uninstall: services, units, nftables table, AppArmor profiles and
#    binaries go; the journal and the evidence key stay. The v1.0.0 smcpctl
#    kept in ./bin verifies the journal.
sudo smcpctl uninstall --config /etc/smcp/smcp.toml --bin-dir /usr/local/bin
sudo bin/smcpctl journal verify --dir /var/lib/smcp/state/journal --key /var/lib/smcp/state/keys/evidence-genesis.pub
```

## Verify an installation

```sh
smcpctl version --config ~/smcp/smcp.toml   # with a running Gateway, also its profile and label
smcpctl health --config ~/smcp/smcp.toml
smcpctl journal verify --config ~/smcp/smcp.toml
smcpctl doctor --config ~/smcp/smcp.toml    # client configuration and CA trust
```
