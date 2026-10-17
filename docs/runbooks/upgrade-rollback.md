# Runbook: upgrade and rollback

Reference: [../operations/upgrade-uninstall.md](../operations/upgrade-uninstall.md). Execution records go in `docs/verification/` (FR-18.8); none is recorded for this runbook yet. `scripts/ci-integration.sh` runs a successful upgrade and a rolled-back upgrade on every pull request.

## Upgrade

1. Download and verify the release archive (install guide), unpack it into `DIR`, and confirm `DIR/SHA256SUMS` lists `smcpd` and `smcpctl` (`cd DIR && sha256sum smcpd smcpctl > SHA256SUMS` if the release ships only the archive checksum).
2. `smcpctl upgrade --config smcp.toml --release DIR --passphrase-file /secure/backup.pass`
   (add `--start-cmd` and `--stop-cmd` when the Gateway is not run by launchd or systemd).
3. Expect `upgrade complete`. `smcpctl version --config smcp.toml` shows the new version.
4. The previous binaries remain as `<name>.prev` next to the new ones until the next upgrade.

## When the upgrade rolls back

1. The command exits with `upgrade rolled back: <reason>; the previous version is running`.
2. `smcpctl health --config smcp.toml` answers; `smcpctl version` shows the previous version.
3. The journal holds an `upgrade_rolled_back` event with the reason.
4. The state of the failed attempt is kept as `<state>.pre-restore-<time>`; keep it for diagnosis and as evidence.
5. If the command reports `the rollback had errors`, restore by hand: copy each `<name>.prev` over `<name>`, run `smcpctl restore --archive <named backup>`, and start the Gateway.
