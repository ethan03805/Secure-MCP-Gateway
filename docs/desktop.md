# Desktop application (draft)

> **Status: in development for v1.3.0 (SRS FR-20, planned).** This is the first draft of the desktop application guide that SRS FR-20.27 requires. It describes what is built today in `desktop/`: the tray, service control, the console window, approval notifications, first-run setup, client setup and updates. The platform installers and Windows support come in later changes. Until the installers ship, build the application from source as described at the end of this page.

The Secure MCP Gateway desktop application is a tray (menu-bar) application, built with Tauri 2, that shows the Gateway's health at a glance, starts and stops the `smcpd` service, tells you when tool calls are waiting for approval, and opens the management console in its own window instead of a browser tab. It runs on macOS 14 or later on Apple silicon (there is no Intel build; Intel Macs keep the command-line path) and on Linux with WebKitGTK 4.1 and a tray that supports StatusNotifierItem or AppIndicator. The terminal path (`install.sh`, `smcpctl`) stays fully supported.

## What the application can and cannot do

**The desktop application holds no authority beyond your console sign-in.** It has no role of its own (SRS Appendix C) and it never reads the operator token, the Secret Vault, the key store, the evidence journal or the Gateway configuration. It does four things on its own:

- it reads the metrics endpoint on loopback (CP-51), which needs no credential and carries no tool arguments, principals or sessions;
- it starts, stops and restarts the `smcpd` service through the platform's service manager;
- it opens the console that `smcpd` serves;
- it checks GitHub for a newer release and, when you ask, installs it after verifying it (see [Updates](#updates)).

Every other operation, including the emergency stop and every approval, happens inside the console window, under your own console sign-in and role, exactly as in a browser. A notification is never an approval, and the tray state is advisory: the console and `smcpctl health` are authoritative.

The only file of the Gateway installation the application reads is the public CA certificate bundle `tls/ca.crt`, so that the console window can check the admin listener's certificate.

## Introduction

The first time the application starts for a user, it opens a short introduction (SRS FR-20.40): four steps that say what the Gateway does and name the three things a new user does, set up the Gateway, connect an agent, and review calls and decide approvals, each with the control that starts it. When you finish or skip the introduction and the Gateway is not set up yet, first-run setup opens next.

- **Skip** with Skip introduction or the Escape key, from any step. The introduction does not open at start again once you have finished or skipped it.
- **Reopen** it from the menu: Help, then Introduction.
- It is packaged with the application, works offline, needs no account and sends nothing. The only thing it stores is whether you finished or skipped it, in the file `introduction` in the application's configuration directory (on macOS, `~/Library/Application Support/com.smcp.desktop/`). Delete that file to see the introduction at the next start.
- Keyboard and screen readers: focus moves to each step's heading, and VoiceOver reads "Step 2 of 4: Set up the Gateway". With Reduce motion on (System Settings, Accessibility, Display), the step change has no fade.

## First-run setup

When no Gateway is set up on the computer (no configuration file and no `smcpd` service unit), the application opens the **Set Up the Gateway** window after the introduction, or at start once the introduction has been finished or skipped. It is also in the menu under Help. Setup is a front end to the terminal procedure, not a second implementation of it (SRS FR-20.8):

1. **Choose a profile.** Standalone is offered everywhere. On Linux the window first runs `smcpctl install --profile enforced --check`, which checks the FR-13.5 prerequisites as your user and changes nothing; Enforced is offered only when every prerequisite is present, and otherwise the window lists each missing one (FR-20.9). The AppImage offers Standalone only. Before you install, the window states that the Standalone profile is labelled `not enforced` and does not contain MCP servers.
2. **Choose whether to enable the bundled ContextForge instance** (SRS FR-22.44). The box is unchecked by default. Its two notes are the ones `smcpctl bootstrap` shows on a terminal: what it adds (hosted servers from the IBM ContextForge catalog, reached only through the Gateway) and its risk (a large third-party service runs on this host, and the code of hosted servers cannot be inspected). A checked box adds `--with-contextforge` to the command below, which writes `[contextforge] bundled = true` and fetches the pinned image; otherwise the configuration gets `bundled = false`. See [ContextForge](contextforge.md).
3. **Set the Administrator and Approver passwords.** Each needs 12 or more characters, the rule `smcpctl` applies.
4. **Install.** The application runs `smcpctl install --profile <profile> --admin-password-file <file> --approver-password-file <file> --metrics-port 9464 --notify off`. `smcpctl install` performs the `smcpctl bootstrap` step (keys, TLS certificates, configuration, policy and the two accounts) and then installs and starts the service. The passwords are written only to two files of mode 0600 in a new directory of mode 0700 under the temporary directory; the files are overwritten and deleted as soon as the command ends, and no password appears in any process's argument list. Metrics are left on at the CP-51 address `127.0.0.1:9464`, the address the tray reads (FR-20.5). The desktop application raises the approval notifications, so `smcpd`'s own are turned off. For Enforced the command runs through `pkexec`, which asks for an administrator's password and names the command in its prompt; Standalone needs no elevation.

The window shows the two steps (keys, configuration and accounts; then the service) and the command's output as it runs. When a step fails it shows what happened, the full output, the code of the message, and the command to run in a terminal instead (it prompts for the passwords), with a Copy Details button and Try Again.

`smcpctl` is looked for beside the application (the `.dmg` and the AppImage carry it), then in `/usr/local/bin`, `/usr/bin`, `/opt/homebrew/bin` and `~/.local/bin`, never on `PATH`. If none is there, the window says so and names the installers.

After an Enforced installation, the Gateway CA certificate (`/var/lib/smcp/state/tls/ca.crt`) is not readable by your account; copy it to a file you can read and set it in Settings so that the console window can check the admin listener (see [Console window](#console-window)).

## Client setup

**Set Up a Client** (tray menu, the introduction, and the end of first-run setup) connects an agent to the Gateway through `smcpctl connect`, the alias of `smcpctl clients setup` (SRS FR-20.10):

1. The window runs `smcpctl clients detect --json` and lists the supported agents (Appendix K) it finds for your account, each marked Connected or Not connected. Supported agents that were not found are named below the list.
2. **Connect** runs `smcpctl connect <client> --config <configuration> --dry-run --json` and shows every file the setup would create or change, with its full new content, and the lockdown profile's changes. Nothing is written at this point. The **Also apply the lockdown profile** switch (on by default where the agent has one, FR-15.1) runs the preview again without the lockdown.
3. **Connect** on the preview runs `smcpctl connect <client> --config <configuration>` (with `--no-lockdown` when the switch is off). The application applies only a setup whose preview you saw, with the same switch setting. Restart the agent afterwards.
4. **Disconnect** runs `smcpctl connect <client> --config <configuration> --remove`, which restores the agent's files from the backups setup made.

The commands run in your home directory, so they change only user-scope and managed settings, never a project directory. A failure shows the message, the command and its output, with Copy Details. Without a Gateway configuration the window asks you to run first-run setup first. `smcpctl clients detect` and `--dry-run --json` are also available in a terminal.

## Tray states

The tray icon shows one of seven states. Its shape changes with the state as well as its color, and its accessible name (the tooltip, read by VoiceOver and Orca) states it in words, for example "Secure MCP Gateway: degraded (not enforced), 2 pending approvals".

| Icon | State | Meaning |
|---|---|---|
| Green filled square | healthy | The Gateway answers and reports `healthy`. |
| Green square, left half filled | running, not enforced | A Standalone Gateway whose only cause is `unconfined` (`smcp_health_profile_only` is 1). It works as designed: calls are checked and recorded, servers are not contained. |
| Amber diamond | degraded | The Gateway runs with a non-critical cause other than the Standalone profile's own. Open the console (Gateway control, Causes) or run `smcpctl health`. |
| Red triangle | fail-closed | The Gateway refuses tool calls because of a critical cause. Open the console (Health) or run `smcpctl health`. |
| Red triangle with a bar under it | emergency stop | The emergency stop is set. Resume in the console, signed in as an Administrator, or with `smcpctl resume`. |
| Grey hollow square | stopped | The service manager reports the service stopped, and the metrics endpoint does not answer. |
| Grey ring | unreachable | No metrics reading for 15 seconds while the service is not known to be stopped. Stale data is never shown as healthy. |

The shapes are those of the visual guide ([design/visual.md](design/visual.md)), so they also tell the states apart without color. On macOS the icon is a monochrome template image that follows the menu bar's color, so only the shape changes; on Linux and Windows it is drawn in the state colors.

The top of the menu repeats the state in words, with the first sentence of what it means, for example "Running, not enforced" and "The Gateway is running and checking every tool call your agents make." Selecting either line opens the **Gateway Status** window, which explains the state, says what to do and offers the control that does it: Start for stopped, Restart for unreachable, Open Console for the others. For unreachable it shows how long ago the status was last read, and on an installation that is not labelled `enforced` it explains what `not enforced` means. The text comes from the shared message catalogue `docs/design/messages.json` (FR-20.48), the same text the console uses.

Beside the icon, the label **not enforced** is shown unless the Gateway reports the release label `enforced` (the gauge `smcp_release_enforced`). The application reads the endpoint every 2 seconds, so a change shows within a few seconds.

The tray needs the metrics endpoint. `smcpctl bootstrap` enables it on the admin port plus one by default (8445); the application's default is the CP-51 address `127.0.0.1:9464`. Set the address the Gateway uses in **Settings**, or set `[metrics] enabled = true` and `address = "127.0.0.1:9464"` in the Gateway configuration and reload. The two gauges the tray needs, `smcp_release_enforced` and `smcp_emergency_stop`, are documented with the other metrics in [operations/logging-metrics-reload.md](operations/logging-metrics-reload.md).

## Menu

| Item | Action |
|---|---|
| Status lines | The state and what it means (above). Opens the Gateway Status window. |
| Open Console | Opens the console window, or brings it to the front. |
| Approvals (*n* pending) | Opens the console window at the Approvals view (G-13). |
| Start, Stop, Restart | Controls the `smcpd` service through the service manager. Start is enabled only while the service is stopped; Stop and Restart only while it runs. |
| Set Up a Client… | Opens the client setup window (below). |
| Check for Updates… | Opens the Check for Updates window and checks for a newer release (see [Updates](#updates)). The item reads "Update Available (*version*)…" after a check that found one. |
| Settings… | The admin listener address, the metrics endpoint, the CA file, the notification switch, Open the app when I log in, and the daily update check. |
| Help | Introduction (reopens the introduction), Set Up the Gateway (first-run setup), Gateway Status, and Desktop Guide (this page, in the default browser). |
| Quit | Quits the application. The Gateway keeps running. |

## Service control

The application controls only a service that `smcpctl install` created, and only through the service manager, with fixed commands:

| Platform and profile | Start | Stop | Restart |
|---|---|---|---|
| macOS (launchd user agent `com.smcp.gateway`) | `launchctl bootstrap gui/<uid> ~/Library/LaunchAgents/com.smcp.gateway.plist` | `launchctl bootout gui/<uid>/com.smcp.gateway` | `launchctl kickstart -k gui/<uid>/com.smcp.gateway` |
| Linux Standalone (systemd user unit) | `systemctl --user start smcpd.service` | `systemctl --user stop smcpd.service` | `systemctl --user restart smcpd.service` |
| Linux Enforced (system units) | `pkexec systemctl start smcp-nftables.service smcpd.service` | `pkexec systemctl stop smcpd.service` | `pkexec systemctl restart smcpd.service` |

Only the Enforced system unit asks for elevation; polkit shows the command in its prompt. The outcome of each action, with the service manager's error text when it fails, is shown as a notification within 30 seconds.

Stopping the service is not the emergency stop. The emergency stop keeps the Gateway and its evidence path running and refuses tool calls; it is done in the console, signed in.

## Console window

The console window loads the console that `smcpd` serves on the admin listener (CP-03, default `https://127.0.0.1:8444`), never a copy bundled with the application, so you sign in exactly as in a browser and your role decides what you can do. The window:

- **trusts only this installation's Gateway CA.** The application checks the listener's certificate itself, against the CA file in Settings (default: `tls/ca.crt` in the Standalone state directory, `~/Library/Application Support/smcp-gateway/state/tls/ca.crt` on macOS and `~/.local/state/smcp-gateway/tls/ca.crt` on Linux) as the only trust anchor, and requires the certificate to name the configured host. A certificate from any other CA, including one the operating system trusts, an expired certificate or one for another name shows an error page with no way to continue. The window title names the failed check. After a CA rotation, close the window and open the console again from the tray.
- **forgets your session when it closes.** It uses a non-persistent web data store, so the session cookie and anything you type never reach disk. Sign in again after reopening.
- **stays on the admin listener.** A link to another site opens in your default browser; other link types are ignored.
- **has no access to the application.** It has no Tauri permission and can call no application command, so content shown in the console cannot reach the desktop.

For the Linux Enforced profile the state directory is not readable by your account; copy the CA certificate (`/var/lib/smcp/state/tls/ca.crt`, public) to a file you can read and set it in Settings.

## Approval notifications

When the number of pending approvals goes up and notifications are on, the application raises one notification: "*n* tool calls are waiting for approval. Open the console to review them." The text is fixed except for the count; it never names a tool, a server or an argument, because the application knows nothing else without signing in, and notification centers are visible to anyone at the unlocked desktop. A notification has no approve, deny or reply action. To decide, open **Approvals** from the tray menu and sign in as an Approver or Administrator. Turn notifications off in **Settings**. Clicking the notification opens the console window at the Approvals view (macOS and Linux); that is its only action. On Windows the notification does not open the console yet; use Approvals in the tray menu.

## Updates

The application looks for a newer stable release on the project's GitHub Releases (SRS FR-20.11): once a day while it runs, and when you select **Check for Updates…**. That check is the only network request the application makes on its own. It is an anonymous HTTPS GET of the releases document (`api.github.com/repos/ethan03805/Secure-MCP-Gateway/releases/latest`) with the fixed `User-Agent` `smcp-desktop` and no cookie, credential, query string, version or other installation data. The only thing it stores is the time of the last check, in the file `update-check` in the application's configuration directory. Turn the daily check off in **Settings** (Check for updates once a day) on a computer without internet access; Check for Updates in the menu still works. Without network access a check you start shows "Could not check for updates" once, and the daily check fails silently and waits another day; it never retries in a loop.

When a newer release exists, the window shows its version, the version of the app and of the Gateway, and a **Release Notes** link that opens in your browser. It then offers what applies:

- **Update App** (FR-20.13). The application downloads the release's installer of the kind that installed it: the `.pkg` or `.dmg` on macOS, the `smcp` and `smcp-desktop` `.deb` or `.rpm` packages or the AppImage on Linux, the `.msi` on Windows. A copy built from source, or any build whose version is 0.x, is not updated from here, because the version check below needs the true installed version. Nothing runs until the checks below pass. Then: the `.pkg` opens in Installer, the `.dmg` opens in the Finder (drag the app to Applications again), and the `.msi` starts with its User Account Control prompt, and the application quits so the installer can replace it; on Linux, `pkexec dpkg -i` or `pkexec rpm -U` installs the packages (polkit shows the command), or the AppImage file is replaced, and the application restarts. The Tauri updater plugin is not used.
- **Upgrade Gateway** (FR-20.12), for a Standalone installation from the release archive (`install.sh`). The application downloads the archive for your platform, verifies it, and runs `smcpctl upgrade --config <the service's configuration> --release <download directory> --passphrase-file -`, using the `smcpctl` beside the `smcpd` that the launchd agent or systemd user unit runs. Enter the backup passphrase in the window: `smcpctl upgrade` takes an encrypted backup first and restores it if the upgrade fails. The passphrase goes to `smcpctl`'s standard input, never to an argument or a file, and is not stored. The window shows the upgrade's output as it runs. A rollback is reported as a failed upgrade with the version that runs afterwards ("The upgrade was rolled back"). An Enforced installation is upgraded as root in a terminal (see [install.md](install.md#upgrade-and-rollback)), and packaged binaries are updated with their package, which Update App installs.

**Verification** (SR-7-2). Before anything runs, the application checks, in this order:

1. that the release is newer than the installed version. An older or equal release is refused ("The update was not installed"), so an old signed release with known flaws cannot be installed again;
2. the minisign signature of `smcp_<version>_checksums.txt` with the release key built into the application, the key in [SECURITY.md](../SECURITY.md) and `install.sh` (key ID `064FAC0C64ACCED0`), and that its signed trusted comment names that file, which binds the signature to the version;
3. when `cosign` is installed (in `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` or on `PATH`), the checksum file's Sigstore bundle against the release workflow identity, as `install.sh` checks it;
4. the SHA-256 of each downloaded file against the verified checksum file.

When a check fails the downloaded files are deleted, nothing is installed, and the window names the failed check (for example "did not pass the SHA-256 checksum check") with the details. Downloads go to a directory only your user can read, in the application's cache directory; leftovers are removed at the next start. On Linux the verified packages are handed to `dpkg` or `rpm` as sealed in-memory copies, so no program running as you can change them between the check and the install. On macOS and Windows the installer reads the verified file from the download directory; see [security-limitations.md](security-limitations.md).

To try a release candidate, point the application at another releases document with the environment variable `SMCP_DESKTOP_RELEASE_FEED` (an HTTPS URL, or plain HTTP to a loopback address). The release key is not configurable, so another feed can offer only releases the project signed.

## Single instance

Only one copy runs per user session. Starting the application again opens or focuses the console window of the copy that is running.

## Start at login

The application does not start at login after installation. Turn on **Open the app when I log in** in Settings to add it as a login item of your account, without elevation: on macOS the launch agent `~/Library/LaunchAgents/com.smcp.desktop.plist`, on Linux the autostart entry `~/.config/autostart/smcp-desktop.desktop` (for an AppImage it names the AppImage file), on Windows the value `Secure MCP Gateway` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Turning the switch off removes it. The Gateway service has its own login start (`smcpctl install`) and does not depend on the application.

## Links that open the console

The application registers the URL scheme `smcp` (SRS FR-20.28) and accepts only three links:

| Link | Opens |
|---|---|
| `smcp://console` | the console window |
| `smcp://approvals` | the Approvals view |
| `smcp://approvals/<approval ID>` | one approval, where the ID is a UUID |

An accepted link only brings the console window to that page; you still sign in and decide there. Every other link, including one with a query string, another path, an ID that is not a UUID or more than 64 characters, is ignored and nothing is sent to the Gateway. Any web page can open a registered link, so a link never approves, denies or changes anything.

## Building from source

You need Rust 1.90 or later, Node.js 22.18 or later, and on Linux `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev` and `libxdo-dev`.

```
cd desktop
npm ci
npm run build
npx tauri build --bundles app --no-sign     # macOS: desktop/src-tauri/target/release/bundle/macos/
cd src-tauri && cargo test
```

The macOS bundle is not signed; macOS asks you to approve it in System Settings, Privacy & Security, Open Anyway. Signed and notarized installers are covered by SRS FR-20.29 (deferred).

## Not yet available

The Windows 11 build of the application and its `smcp-desktop` `.msi` (FR-20.1, FR-20.20): there is no Windows build yet, and Windows hosts use the command-line Gateway. The Linux and macOS installers are in the pre-release `v1.3.0-beta.1`; installing, verifying and removing them is in the [install guide](install.md#option-4-platform-packages-deb-rpm-macos-pkg-and-dmg-appimage-msi). What else is missing for each FR-20 requirement is in the [gap list](verification/gap-list.md#planned-for-v130).
