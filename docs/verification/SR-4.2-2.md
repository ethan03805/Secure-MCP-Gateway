# SR-4.2-2 Observation file protection

| Field | Content |
|---|---|
| Requirement or scenario | SR-4.2-2 |
| Commit | `985493959979eef7d52e732f54f0394915e659e7` |
| Profile and platform | Enforced; ubuntu-24.04 GitHub-hosted runner (image 20261012.334.1), linux/amd64 |
| Date | 2026-10-18 |
| Executor | Claude Code agent (enforced-host partials task); CI run 39186227196, job linux-integration (117849220122) |
| Method | Inspection |
| Result | pass |

In release 1.x the Observation Store runs inside `smcpd` (SR-4.1-1), so the Data Server identity that owns its files is `smcp-core` (rationale of SR-4.2-2, `srs_build/req5.txt:736`).

Steps: the CI job linux-integration of https://github.com/ethan03805/Secure-MCP-Gateway/actions/runs/39186227196 (pull request #126) ran `scripts/ci-systemd.sh`. The script installed the Enforced profile, ran `smcpd.service` with observation at its defaults, made tool calls through the reference server and the sandbox probe, and stopped the service. `cmd/smcpctl.TestEnforcedLayoutOnHost` (`scripts/ci-systemd.sh:328`) then listed every entry under `/var/lib/smcp/state/observation` with `find -printf '%y %u %m %p'`. It failed the run for any entry not owned by `smcp-core`, any file with permission bits outside 0600 and any directory with group or other bits (`cmd/smcpctl/layout_host_linux_test.go:89`). I read the job log.

Observations:

- `ls -ld` printed `drwx------ 5 smcp-core smcp ... /var/lib/smcp/state/observation`, and `/var/lib/smcp/state` itself is `smcp-core:smcp 700`.
- The test logged `observation store: 6 files, all smcp-core's with mode 0600 or stricter` and passed.
- The Observation Store writes its files with mode 0600 and its directories with 0700 (`internal/obsstore.TestStoreLayoutAndModes`, partial claim), and smcpd's unit sets `UMask=0077` (`packaging/linux/systemd/smcpd.service:37`).

Deviation: none for the statement as its rationale reads it in release 1.x. The files are not readable by any other identity, the server identity `smcp-srv` included.
