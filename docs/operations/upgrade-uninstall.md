# Upgrade, rollback and uninstall

## Upgrade (FR-13.7, FR-13.8)

```
smcpctl upgrade --release DIR \
  (--passphrase-file FILE | --recipient age1... --identity-file FILE) \
  [--bin-dir DIR] [--start-cmd CMD --stop-cmd CMD] [--health-timeout 60s]
```

`DIR` is an unpacked release: the binaries (`smcpd`, `smcpctl`, and `smcp-refserver` and `smcp-connect` when present) and a `SHA256SUMS` file in `sha256sum` format listing them. `--bin-dir` is where the installed binaries are (default: the directory of the running `smcpctl`).

The Gateway is started and stopped through the installed service unit (launchd agent `com.smcp.gateway` on macOS, systemd units `smcpd.service` on Linux (system units from `packaging/linux/install-enforced.sh`, or a user unit)), or through `--start-cmd` and `--stop-cmd`, which are run with `sh -c` and get `SMCP_CONFIG` set to the absolute configuration path.

Steps:

1. Verify every file listed in `SHA256SUMS`; `smcpd` and `smcpctl` must be listed. A mismatch stops the upgrade before anything changes. (The release signature check of the downloaded archive is done by the installer, FR-13.2.)
2. Take an encrypted backup (online when the Gateway runs; see [backup.md](backup.md)).
3. Stop dispatch (`POST /admin/v1/stop`, reason `upgrade`) and stop the Gateway.
4. Install the new binaries; each replaced binary is kept as `<name>.prev`.
5. Run the new release's `smcpctl config migrate`, limited to 120 s (CP-47).
6. Start the Gateway and wait up to 60 s (CP-47, `--health-timeout`) for it to answer with a state other than `fail-closed` and the new version.

If step 4, 5 or 6 fails, the upgrade rolls back: it stops the new Gateway, restores the `.prev` binaries, restores the pre-upgrade backup (the state of the failed attempt is kept as `<state>.pre-restore-<time>`), writes `state/upgrade-event.json`, and starts the previous version, which records an `upgrade_rolled_back` event (reason `UPGRADE_ROLLED_BACK`, with both versions and the reason) in the journal when it starts. `smcpctl upgrade` then exits with status 1 and `upgrade rolled back: <reason>; the previous version is running`.

Upgrading to a release older than the running one is not refused; use the backup and `.prev` binaries for a manual downgrade instead.

## Uninstall (FR-13.11)

```
smcpctl uninstall [--bin-dir DIR] [--stop-cmd CMD]
```

1. Stops the Gateway (service unit or `--stop-cmd`) and waits until the control API stops answering.
2. Removes the launchd plist or the systemd units (`smcpd.service`, `smcp-nftables.service`) and `/etc/smcp/smcp.nft`, the nftables table `inet smcp` (Linux, with `sudo -n` when not root), AppArmor profiles `/etc/apparmor.d/smcp-*` (Linux), and the binaries `smcpd`, `smcpctl`, `smcp-refserver`, `smcp-connect` and their `.prev` copies in `--bin-dir`.
3. Keeps the evidence journal, the evidence public keys, the backup archives, the configuration and the state directory, and prints how to verify the kept journal later:

```
smcpctl journal verify --dir <state>/journal --key <state>/keys/evidence-genesis.pub
```

## Purge (FR-13.12)

```
smcpctl uninstall --purge
```

Prints the installation ID and asks the operator to type it; any other input stops the purge before anything is removed. Then it performs the uninstall steps, prints the name and SHA-256 of the last journal segment (record it), and deletes the configuration file, the policy file, the state directory (keys, journal, TLS material), the diagnostic log files, and on Linux the CP-46 service identities (`smcp-core`, `smcp-evidence`, `smcp-keys`, `smcp-vault`, `smcp-data`, `smcp-console`, `smcp-srv`) that exist. Backup archives are kept; delete them separately.

## Errors

| Message | Meaning |
|---|---|
| `release verification failed, nothing changed` | A file does not match `SHA256SUMS`, or `smcpd`/`smcpctl` is not listed |
| `pre-upgrade backup failed, nothing changed` | See [backup.md](backup.md) |
| `no service manager unit is installed for the Gateway; pass --start-cmd and --stop-cmd` | No unit was found |
| `--recipient needs --identity-file` | A rollback must be able to decrypt the pre-upgrade backup |
| `upgrade rolled back: ...` | The upgrade failed and the previous version runs |
| `upgrade failed (...) and the rollback had errors: ...` | Manual recovery needed: restore the `.prev` binaries and the named backup |
| `installation ID does not match; nothing was removed` | Purge refused |
