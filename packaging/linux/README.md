# Linux enforced-profile packaging

| File | Installed as | Purpose |
|---|---|---|
| `install-enforced.sh` | (run from here as root) | Checks prerequisites, then creates service identities, subordinate ID ranges, directories, the nftables table and the systemd units; idempotent |
| `systemd/smcpd.service` | `/etc/systemd/system/smcpd.service` | smcpd as `smcp-core` with a delegated cgroup for rootless Podman |
| `systemd/smcp-nftables.service` | `/etc/systemd/system/smcp-nftables.service` | Loads the nftables table at boot |
| `nftables/smcp.nft` | `/etc/smcp/smcp.nft` | Table `inet smcp` |
| `apparmor/smcpd` | `/etc/apparmor.d/smcpd` | AppArmor profile of smcpd, loaded in enforce mode when AppArmor is enabled |

See [docs/enforced-profile.md](../../docs/enforced-profile.md) for the installation walk-through and [docs/sandbox.md](../../docs/sandbox.md) for what each object is for and for the `[runtime]` configuration.
