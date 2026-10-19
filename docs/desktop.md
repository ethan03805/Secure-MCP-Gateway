# Desktop application (draft)

> **Status: in development for v1.3.0 (SRS FR-20, planned).** This is the first draft of the desktop application guide that SRS FR-20.27 requires. It describes what is built today in `desktop/`: the tray, service control, the console window, approval notifications, first-run setup and client setup. updates, the platform installers and Windows support come in later changes. Until the installers ship, build the application from source as described at the end of this page.

The Secure MCP Gateway desktop application is a tray (menu-bar) application, built with Tauri 2, that shows the Gateway's health at a glance, starts and stops the `smcpd` service, tells you when tool calls are waiting for approval, and opens the management console in its own window instead of a browser tab. It runs on macOS 14 or later on Apple silicon (there is no Intel build; Intel Macs keep the command-line path) and on Linux with WebKitGTK 4.1 and a tray that supports StatusNotifierItem or AppIndicator. The terminal path (`install.sh`, `smcpctl`) stays fully supported.

## What the application can and cannot do

**The desktop application holds no authority beyond your console sign-in.** It has no role of its own (SRS Appendix C) and it never reads the operator token, the Secret Vault, the key store, the evidence journal or the Gateway configuration. It does three things on its own:

- it reads the metrics endpoint on loopback (CP-51), which needs no credential and carries no tool arguments, principals or sessions;
- it starts, stops and restarts the `smcpd` service through the platform's service manager;
- it opens the console that `smcpd` serves.

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
2. **Set the Administrator and Approver passwords.** Each needs 12 or more characters, the rule `smcpctl` applies.
3. **Install.** The application runs `smcpctl install --profile <profile> --admin-password-file <file> --approver-password-file <file> --metrics-port 9464 --notify off`. `smcpctl install` performs the `smcpctl bootstrap` step (keys, TLS certificates, configuration, policy and the two accounts) and then installs and starts the service. The passwords are written only to two files of mode 0600 in a new directory of mode 0700 under the temporary directory; the files are overwritten and deleted as soon as the command ends, and no password appears in any process's argument list. Metrics are left on at the CP-51 address `127.0.0.1:9464`, the address the tray reads (FR-20.5). The desktop application raises the approval notifications, so `smcpd`'s own are turned off. For Enforced the command runs through `pkexec`, which asks for an administrator's password and names the command in its prompt; Standalone needs no elevation.

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

The tray icon shows one of six states. Its shape changes with the state as well as its color, and its accessible name (the tooltip, read by VoiceOver and Orca) states it in words, for example "Secure MCP Gateway: degraded (not enforced), 2 pending approvals".

| Icon | State | Meaning |
|---|---|---|
| Green filled square | healthy | The Gateway answers and reports `healthy`. |
| Amber diamond | degraded | The Gateway runs with a non-critical cause. In the Standalone profile this is normal: the cause is `unconfined`. |
| Red triangle | fail-closed | The Gateway refuses tool calls because of a critical cause. Open the console (Health) or run `smcpctl health`. |
| Red triangle with a bar under it | emergency stop | The emergency stop is set. Resume in the console, signed in as an Administrator, or with `smcpctl resume`. |
| Grey hollow square | stopped | The service manager reports the service stopped, and the metrics endpoint does not answer. |
| Grey ring | unreachable | No metrics reading for 15 seconds while the service is not known to be stopped. Stale data is never shown as healthy. |

The shapes are those of the visual guide ([design/visual.md](design/visual.md)), so they also tell the states apart without color.

The top of the menu repeats the state in words, with the first sentence of what it means, for example "Degraded, not enforced" and "The Gateway is running and checking tool calls." Selecting either line opens the **Gateway Status** window, which explains the state, says what to do and offers the control that does it: Start for stopped, Restart for unreachable, Open Console for the others. For unreachable it shows how long ago the status was last read, and on an installation that is not labelled `enforced` it explains what `not enforced` means. The text comes from the shared message catalogue `docs/design/messages.json` (FR-20.48), the same text the console uses.

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
| Check for Updates | Not available yet (shown disabled). |
| Settings… | The admin listener address, the metrics endpoint, the CA file and the notification switch. |
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

When the number of pending approvals goes up and notifications are on, the application raises one notification: "*n* tool calls are waiting for approval. Open the console to review them." The text is fixed except for the count; it never names a tool, a server or an argument, because the application knows nothing else without signing in, and notification centers are visible to anyone at the unlocked desktop. A notification has no approve, deny or reply action. To decide, open **Approvals** from the tray menu and sign in as an Approver or Administrator. Turn notifications off in **Settings**. Opening the Approvals view by clicking the notification itself is planned.

## Single instance

Only one copy runs per user session. Starting the application again opens or focuses the console window of the copy that is running.

## Building from source (until the installers ship)

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

Update checks and upgrades (FR-20.11 to FR-20.13), start at login (FR-20.14), deep links (FR-20.28), Windows (FR-20.1, FR-20.20), and the platform installers with their installation and removal instructions (FR-20.17 to FR-20.26).
