# Desktop application (draft)

> **Status: in development for v1.3.0 (SRS FR-20, planned).** This is the first draft of the desktop application guide that SRS FR-20.27 requires. It describes what is built today in `desktop/`: the tray, service control, the console window and approval notifications. First-run setup, client setup, updates, the platform installers and Windows support come in later changes. Until the installers ship, build the application from source as described at the end of this page.

The Secure MCP Gateway desktop application is a tray (menu-bar) application, built with Tauri 2, that shows the Gateway's health at a glance, starts and stops the `smcpd` service, tells you when tool calls are waiting for approval, and opens the management console in its own window instead of a browser tab. It runs on macOS 14 or later on Apple silicon (there is no Intel build; Intel Macs keep the command-line path) and on Linux with WebKitGTK 4.1 and a tray that supports StatusNotifierItem or AppIndicator. The terminal path (`install.sh`, `smcpctl`) stays fully supported.

## What the application can and cannot do

**The desktop application holds no authority beyond your console sign-in.** It has no role of its own (SRS Appendix C) and it never reads the operator token, the Secret Vault, the key store, the evidence journal or the Gateway configuration. It does three things on its own:

- it reads the metrics endpoint on loopback (CP-51), which needs no credential and carries no tool arguments, principals or sessions;
- it starts, stops and restarts the `smcpd` service through the platform's service manager;
- it opens the console that `smcpd` serves.

Every other operation, including the emergency stop and every approval, happens inside the console window, under your own console sign-in and role, exactly as in a browser. A notification is never an approval, and the tray state is advisory: the console and `smcpctl health` are authoritative.

The only file of the Gateway installation the application reads is the public CA certificate bundle `tls/ca.crt`, so that the console window can check the admin listener's certificate.

## Tray states

The tray icon shows one of six states. Its shape changes with the state as well as its color, and its accessible name (the tooltip, read by VoiceOver and Orca) states it in words, for example "Secure MCP Gateway: degraded (not enforced), 2 pending approvals".

| Icon | State | Meaning |
|---|---|---|
| Green disc | healthy | The Gateway answers and reports `healthy`. |
| Amber triangle | degraded | The Gateway runs with a non-critical cause. In the Standalone profile this is normal: the cause is `unconfined`. |
| Red disc with a bar | fail-closed | The Gateway refuses tool calls because of a critical cause. Open the console (Health) or run `smcpctl health`. |
| Red octagon | emergency stop | The emergency stop is set. Resume in the console, signed in as an Administrator, or with `smcpctl resume`. |
| Grey square | stopped | The service manager reports the service stopped, and the metrics endpoint does not answer. |
| Grey ring | unreachable | No metrics reading for 15 seconds while the service is not known to be stopped. Stale data is never shown as healthy. |

Beside the icon, the label **not enforced** is shown unless the Gateway reports the release label `enforced` (the gauge `smcp_release_enforced`). The application reads the endpoint every 2 seconds, so a change shows within a few seconds.

The tray needs the metrics endpoint. `smcpctl bootstrap` enables it on the admin port plus one by default (8445); the application's default is the CP-51 address `127.0.0.1:9464`. Set the address the Gateway uses in **Settings**, or set `[metrics] enabled = true` and `address = "127.0.0.1:9464"` in the Gateway configuration and reload. The two gauges the tray needs, `smcp_release_enforced` and `smcp_emergency_stop`, are documented with the other metrics in [operations/logging-metrics-reload.md](operations/logging-metrics-reload.md).

## Menu

| Item | Action |
|---|---|
| Open Console | Opens the console window, or brings it to the front. |
| Approvals (*n* pending) | Opens the console window at the Approvals view (G-13). |
| Start, Stop, Restart | Controls the `smcpd` service through the service manager. Start is enabled only while the service is stopped; Stop and Restart only while it runs. |
| Set Up a Client | Not available yet (shown disabled). Use `smcpctl connect <client>` meanwhile. |
| Check for Updates | Not available yet (shown disabled). |
| Settings… | The admin listener address, the metrics endpoint, the CA file and the notification switch. |
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

First-run setup (FR-20.8, FR-20.9), client setup (FR-20.10), update checks and upgrades (FR-20.11 to FR-20.13), start at login (FR-20.14), deep links (FR-20.28), Windows (FR-20.1, FR-20.20), and the platform installers with their installation and removal instructions (FR-20.17 to FR-20.26).
