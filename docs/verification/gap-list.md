# Verification gap list

Every requirement of the current requirement set that is not yet verified, grouped by primary element (the first E-xx of the requirement's allocation), with what is missing. Rebuilt on 2026-10-19 by the phase-10 steward pass from the CI status data of main `383485d` (run https://github.com/ethan03805/Secure-MCP-Gateway/actions/runs/39203581561), with FR-11 counted as verified by the Analysis record [FR-11.md](FR-11.md) added in the same pass (529 requirements: 489 verified, 39 partly verified, 1 unverified, 0 failing; 108 more are planned for a later release and not counted). `make status` produces the same report locally (`build/reqreport.md`); regenerate it before acting on an entry, because later merges change the counts.

Each entry is marked:

- **missing**: the behavior, or a stated part of it, does not exist in the code.
- **unverified**: the behavior appears to exist, but no test or record proves the whole statement yet. These need a test or an inspection record, not new code.
- **external**: the requirement needs an artifact or run outside the source tree (a release tag, a person, credentials, a third-party service). The entries that only the owner can unblock are collected in [Blocked on the owner](#blocked-on-the-owner) at the end.

Parent requirements whose verification is "Review the verification results of every child requirement" are verified by `tools/reqreport` once all their children are, and reported partial while some but not all children are verified. They are not listed below. In this status data they are: FR-8, FR-9, FR-10, FR-12, FR-13, FR-14, FR-15, FR-16, FR-18. FR-11 is not a roll-up: it is reviewed by Analysis against a performance report on the recorded reference hardware ([reference-hardware.md](../reference-hardware.md)), and its record is [FR-11.md](FR-11.md) (run 39203581561 of main `383485d`, every FR-11 child verified).

Requirements deferred from release 1.x (SRS Section 2.7, Appendix N) and requirements planned for a later release with a `TARGET:` line (SRS Section 2.8: FR-20, FR-22 and the security requirements planned with them, all for v1.3.0) are not part of the requirement set and are not listed.

The claiming tests of each partly verified requirement say, in the comment next to `reqtest.Partial`, which clauses are missing; `build/reqreport.md` lists the claiming tests. Some requirements are full claims only from the published result of a workflow run on a release tag, and partial claims from a run on any other ref (FR-13.3, FR-14.9, FR-15.2, FR-15.8; [verification/README.md](README.md#results-of-separate-workflows)). FR-13.3 and FR-14.9 are verified by the v1.1.0 runs; FR-15.2 needs the lockdown job, and FR-15.8 the matrix job, on the next release tag, v1.2.0.

## E-01 Harness Interface Endpoint

- FR-12.2 **unverified** (partly verified): The offline job does not run AT-07, AT-08 and AT-10.
- FR-16.1 **external** (partly verified): The Remote Access listener is tested behind a local tunnel stand-in.
- FR-16.2 **external** (partly verified): The tunnel drivers are tested against fake tailscale and cloudflared binaries.

## E-13 Library Trust Verifier

- FR-14.3 **unverified** (partly verified): The reference servers are packaged with the unconfined probe; the Podman probe is tested with the hostile packaging fixture only.

## E-21 Audit & Evidence Service

- FR-16.8 **external** (partly verified): The fields are tested on the listener; calls through a real tunnel are not.
- SR-6.1-1 **unverified** (partly verified): No single test triggers every event class under the most minimal policy.
- SR-6.7-1 **unverified** (partly verified): The AT-13 run checks credential formats, not a secret delivered by the Secret Broker on every captured surface.

## E-24 Management Console & Control API

- FR-8.16 **missing** (partly verified): Cache hit ratios and the Observation Store's memory use against its budget are not shown.
- FR-8.24 **external** (partly verified): A scripted first-time task, not the Demonstration with three first-time users.
- FR-8.30 **unverified** (partly verified): Current browser engines only; the previous major version of each browser and Safari itself are not run.
- FR-8.32 **unverified** (partly verified): The Runtime instance kill is done against a mocked instance table.
- FR-8.33 **unverified** (partly verified): The Runtime instance kill is done against a mocked instance table.
- FR-12.7 **unverified** (partly verified): The subcommands are tested one by one; the Demonstration in both profiles is not recorded.
- FR-13.7 **unverified** (partly verified): The launchd and systemd service paths of each profile are not exercised.
- FR-18.1 **unverified** (partly verified): The install guide has not been followed on clean hosts.

## E-25 Graph Database Engine

- FR-9.1 **missing** (partly verified): Relationship types owned by other elements are not created by the mirror.
- SR-7.4-1 **unverified** (partly verified): The engine itself is not run as smcp-data on an Enforced host with its configuration and firewall rules inspected together.

## E-28 Data Lifecycle & Memory Manager

- FR-9.10 **missing** (partly verified): The page-cache measurement and the other budgeted components are not covered.
- FR-9.11 **missing** (partly verified): The page-cache measurement and the other budgeted components are not covered.

## E-29 Observation Collector

- FR-10.1 **unverified** (partly verified): The collector's offer path is tested with consumption stalled; instrumented elements processing calls during the stall are not.
- FR-10.2 **missing** (partly verified): Only the edge's stages emit spans; a call without an approval has no approval span.
- FR-10.5 **unverified** (partly verified): The fixture covers the argument features only.
- FR-10.10 **unverified** (partly verified): P-213 is computed from journal timestamps; no independent harness-side measurement is compared.

## E-33 Harness Adapter Kit

- FR-15.1 **external** (partly verified): Only Claude Code is run with its lockdown at the pinned version.
- FR-15.2 **external** (partly verified): Claimed in full only by the lockdown job of a release tag.
- FR-15.7 **external** (partly verified): Only Claude Code connects over TLS with what smcpctl clients setup wrote.
- FR-15.8 **external** (partly verified): Gemini CLI and Grok Build are not run; the matrix result is a full claim only from a release tag.
- FR-15.10 **external** (partly verified): Gemini CLI and Grok Build have no result in the matrix job.
- FR-18.3 **external** (no claiming test or record): Gemini CLI needs a GEMINI_API_KEY and Grok Build has no installable CLI, so their quick starts are not followed.
- SR-4.9-1 **external** (partly verified): Only Claude Code is started at its pinned version with a second server added.
- SR-4.11-1 **external** (partly verified): Only Claude Code is started at its pinned version with its lockdown.

## History

The dated notes below record how the list changed, in the order they were added. Requirements named in them as open may since have been verified; the list above is the current state.

Updated on 2026-10-17 against the status data of `58a40c1`: entries that tests now verify or partly verify were removed (FR-1.39, FR-1.40, FR-1.49, FR-5.20, FR-5.24, SR-5.6-2, SR-7.2-1 and FR-19.1 after the hostile-suite fixes).

Updated on 2026-10-17 by the acceptance work: FR-11.1 and FR-10.11 are verified, FR-10.2, FR-12.2, FR-19.3 and SR-7.11-1 have partial claims, the FR-11 measurements have partial claims from the CI job `perf`, and FR-12.5 is deferred (Appendix N).

Updated on 2026-10-17 by the E-01 to E-04 partials sweep: SR-7.11-1 is verified (CP-09 connection and unauthenticated-work limits, slow headers and bodies, `internal/edge.TestPreParseBounds`).

Updated on 2026-10-17 by the egress-capability work: SR-5.16-1 is restored from Appendix N and verified (`TestEgressCapabilities`), and AT-10 is claimed by `TestAT10WebBroker`, so every scenario has a claiming test (FR-19.4). Whether the release label is "enforced" depends on the scenarios passing in the Enforced profile for the release commit (FR-19.3).

Updated on 2026-10-17 by the perf work: FR-11.4 is within its budget in the CI job `perf` (partial claim, no longer missing). The perf harness now takes P-213 from the request's receipt to delivery minus server execution to the backend's response; before, it ended server execution at the completed event, which follows response inspection, and so left response inspection out of FR-11.4 and FR-11.5.

Checked on 2026-10-17 against the status data of main `ee2e851` (386 verified, 117 partial, 26 unverified, none failing); every unverified requirement other than a parent is listed below, together with partly verified requirements whose missing part is external (reference hardware, a release, a person) needs a record rather than a test, or was a single named case (SR-7.9-1, since verified).

Updated on 2026-10-17 by the security-final work: SR-4.14-1 is implemented (`smcpctl remote enable` installs nftables host rules; verified by the root namespace test of the linux-integration job, partial claims elsewhere), SR-2.13-2 is narrowed and verified by an inspection record, SR-7.9-1 is verified by AT-19 (a server revision suspended before both rollbacks), and SR-3.6-1, SR-5.8-1, SR-5.9-2 and SR-6.2-1 are verified by new tests. SR-4.9-1 and SR-4.11-1 stay partial: they need each client started at its pinned version with a second server added (real-agent workflow).

Updated on 2026-10-17 by the partials-c sweep: FR-1.51, FR-17.3, FR-13.13 (verification narrowed to one schema version) and FR-10.34 (audit subgraph added; checked with pinned pyarrow, pandas and NetworkX in the CI go job) have verifying tests; none of them was listed.

Updated on 2026-10-17 by the verification records work: FR-18.8 (runbook executions, `runbooks/FR-18.8.md`), FR-14.5, FR-3.18 and FR-12.3 have records; FR-8.24, FR-8.30, FR-8.32, FR-8.33 and FR-13.3 are updated below. FR-14.9 is claimed by the `reference-packages` workflow's published result (partial on a branch, full on a release tag). After the merge, the `tap` workflow for v1.0.0-rc.2 (run 39074221187) and the `reference-packages` workflow on main (run 39074222847) published their results to `site-data/workflows.json`: FR-13.3 is verified by the tap run of a release tag (its line is removed), FR-14.9 is partial until the workflow runs on a release tag.

Updated on 2026-10-18 by the data partials work: FR-7.11 is verified by `internal/e2e` `TestHealthFaultEachDependency` (each dependency faulted in turn in a running Gateway; vault availability and decision-snapshot currency checks added, every check evaluated once per second).

Updated on 2026-10-18 by the data partials work: SR-7.8-1 is verified (`internal/backup` `TestRestoreVerifiesPolicyStoreReappliesRevocationsAndRebuildsGraph`).

Updated on 2026-10-18 by the data partials work: FR-17.7 is verified (`TestOpsKeyRotationUnderTraffic`; the SRS statement of the CA overlap was narrowed to what one TLS chain per handshake can serve).

Checked on 2026-10-17 by the phase-8 documentation pass against the status data of main `788c8b4` (529 requirements: 413 verified, 95 partial, 21 unverified, none failing). The 21 unverified are the 12 parents FR-3, FR-5, FR-7, FR-8, FR-11, FR-12, FR-13, FR-14, FR-15, FR-16, FR-17 and FR-19 and the nine requirements marked external or missing below (FR-12.1, FR-12.8, SR-4.1-1, FR-18.6, SR-6.12-1, FR-12.4, FR-15.9, FR-16.10, FR-18.3). Every acceptance scenario passed in the Enforced profile for that commit (label "enforced"). The FR-11 figures below are from the CI job `perf` of that commit.

Updated on 2026-10-18 by the release-ops work: FR-19.3 has an Inspection record (`FR-19.3.md`), FR-19.4 is verified by `TestEveryScenarioHasEvidence` (it now reads the AT-07 annotation of the console suite), FR-14.9 is verified by the `reference-packages` run on tag v1.0.0 (run 39096364892, published to `site-data/workflows.json`), and the FR-12.1 and FR-12.8 entries record the inspection of the v1.0.0 release. SR-7.5-2 (the prompt on a pseudo-terminal, and `smcpctl install`) and FR-16.11 (Operator refused through a signed-in console account) are verified, FR-13.6 is claimed by the `install-standalone` job (macOS arm64 and Ubuntu without Podman, merged only when both report), and SR-4.1-1 is narrowed and has an Inspection record of the linux-integration run of PR #104 (`SR-4.1-1.md`). FR-18.6 has an Inspection record (`FR-18.6.md`: `@modelcontextprotocol/server-sequential-thinking` packaged by following the guide, imported, enabled and called), and FR-14.1 is claimed in full by `TestIntegrationPackageBuildEachType` in the linux-integration job (the OCI image is probed with rootless Podman). FR-13.8 is verified by `TestUpgradeAndRollback` (a failing migration added) and FR-13.12 by `TestEnforcedUninstallAndPurgeOnHost` on the Enforced CI host.

Updated on 2026-10-18 by the console partials work (part B): FR-8.22, FR-8.23, FR-8.26, FR-8.27, FR-8.28, FR-8.29, FR-8.31, SR-3.4-1 (narrowed: the bill of materials is the signed provenance statement) and SR-6.17-1 (fixtures written by `scripts/evidence-fixture`) have verifying console tests, and SR-2-2 and SR-2.5-1 verifying acceptance tests against the real `smcpd`; the FR-8.29 and FR-8.31 entries are removed.

Updated on 2026-10-18 by the remote-agents partials work: FR-12.13 and FR-16.9 are verified (`internal/conformance.TestConformanceThroughAdapters`). FR-15.9 and FR-16.10 are narrowed by an SRS change (live cloud-agent runs descoped from release 1.x) and verified by Inspection records. Parents with some evidenced children are now reported partial rather than unverified.

Updated on 2026-10-19 by the doctor work: FR-15.4 is verified by `cmd/smcpctl.TestDoctorEnforcedHostAsHarnessUser`. On the Enforced installation of the `linux-integration` job, doctor runs as the runner account (the harness user, not in group `smcp`), and then for a Standalone instance of the same user. Before this change doctor stopped at the unreadable Enforced configuration; it now checks the CP-46 Enforced directories as the harness user.

Checked on 2026-10-18 by the phase-9 steward pass against the status data of main `1a96b1c` (529 requirements: 457 verified, 68 partly verified, 4 unverified, none failing; v1.0.0 was released at 413, 95 and 21). The four unverified requirements are FR-11 (reviewed against a performance report on recorded hardware), FR-12.4, SR-6.12-1 and FR-18.3, each listed below; each parent not yet verified is reported partial. FR-9.17 is verified (smcpd answers `-31004` while the journal cannot be opened, then starts; AT-03). Every acceptance scenario passed in the Enforced profile for that commit (label "enforced"). The FR-11 figures below are from the CI job `perf` of `1a96b1c`. The lines below were checked against that status data: none of the listed requirements is verified yet.

Updated on 2026-10-19 by the secrets work: SR-2-1 is verified by `internal/secrets.TestSecretsNeverNorthbound`. Secrets are delivered in the S1 to S4 modes and echoed through results, tool errors, JSON-RPC errors and progress notifications. The test checks that none reaches the harness, the session API responses, the evidence or the diagnostic log.

Updated on 2026-10-18 by the v1.1.0 release: v1.1.0 (main `935dc4d`, release run 39178207151, rehearsed with v1.1.0-rc.2 on the same commit) is the first release built by the fixed pipeline. Its SBOMs and bundle were inspected: every SBOM entry has an OSI-approved license or a reviewed exception, and every archive carries the build recipe, the lockfiles, `PROVENANCE.md` and `THIRD_PARTY_NOTICES.txt`. FR-12.1 and FR-12.8 now have passing Inspection records (`inspections.md`) and their lines above are removed. FR-13.1 has a v1.1.0 record. The `tap` workflow passed for v1.1.0 on macOS and Ubuntu (run 39178720966), and `reference-packages` passed on the tag (run 39178206965); both results are published to `site-data/workflows.json` (FR-13.3, FR-14.9). The runbooks were executed again on `d55c08f` for FR-18.8 (`runbooks/`). In the CI status data of main `935dc4d` (529 requirements: 466 verified, 59 partly verified, 4 unverified, none failing; label "enforced") the four unverified requirements are still FR-11, FR-12.4, SR-6.12-1 and FR-18.3, listed above.

Updated on 2026-10-18 by the install-ops partials work: FR-13.5 is verified by `cmd/smcpctl.TestEnforcedInstallOnHost` on the linux-integration host, and FR-13.4 and FR-13.11 are claimed in full by `tools/reqreport.TestInstallProfilesEvidence` from the Standalone (macOS arm64, Ubuntu) and Enforced results of the same CI run. A Standalone `smcpctl uninstall` no longer removes the nftables table, AppArmor profiles, system units or service identities of an Enforced installation on the same host.

Updated on 2026-10-19 by the agents-partials work: the Real agents workflow has a `lockdown` job (`scripts/agents/lockdown.go`). Claude Code 2.1.302 follows its quick start (option B), connects over TLS with only what `smcpctl clients setup` wrote, and with the managed-settings lockdown applied a second MCP server in user and project scope does not load, the Read of the Gateway state directory and the Edit of its own `.mcp.json` are refused, and `smcpctl doctor` reports the extra servers (run 39184564500). The first run found that `smcpctl lockdown apply` wrote the managed file with mode 0600, which Claude Code ignored; it is now 0644. The job's result claims FR-15.2 and the matrix job's result claims FR-15.8 through `site-data/workflows.json` (partial from main, full from a release tag), and the broken-build check now runs every client. FR-15.1, FR-15.7, SR-4.9-1 and SR-4.11-1 stay partial: only Claude Code is locked down and run through `smcpctl clients setup` by CI; the lockdown mechanisms recorded for Codex CLI, OpenCode, Gemini CLI and Goose are not yet confirmed against their pinned versions.

Updated on 2026-10-18 by the perf work: the GitHub-hosted `ubuntu-24.04` standard runner class (x86_64, 4 vCPU, 16 GiB, SSD) is the recorded reference hardware of FR-11 (SRS §1.6, [reference-hardware.md](../reference-hardware.md)). `perf.json` records each run's processor, memory and disk, and a complete measurement within budget on that class is a full claim. The FR-11.2, FR-11.4, FR-11.5, FR-11.8 and FR-11.9 lines are removed. The CI job `perf` now also runs the FR-11.6 replay (2,000 records per second for 10 minutes through the analytics store writer into the DuckDB store, no backpressure signal) and the FR-11.8 analytics queries over the 30 days of observation data that replay writes. FR-11.9 now includes the graph engine (Neo4j, CP-33 budget). In the dispatch run 39190807816 of this branch (AMD EPYC 9V45, `referenceHardware` true), every measurement passed and was complete: FR-11.2 0.011 ms, FR-11.4 0.42 ms, FR-11.5 9.4 ms, FR-11.6 2,000 records/s with no offer at 80% queue occupancy and no drop, FR-11.8 458 ms p95 over 1,200,000 observation records and the 100,000-event journal, FR-11.9 1,541 MiB (smcpd 120 MiB, Neo4j 1,421 MiB). The earlier run 39187565839 on an EPYC 7763 runner measured FR-11.4 at 1.19 ms while Neo4j ran from the start of the job; the engine now starts after the FR-11.4 loads. On EPYC 7763 runners FR-11.4 had measured 0.52 to 0.95 ms before, so its margin stays thin there. FR-11 itself is reviewed by Analysis against a performance report and still needs a record that cites a passing `perf` run of main with every child verified. FR-11.6 and FR-11.8 are measured with the DuckDB store of the SRS stack. The release archives are built without cgo, and their JSON Lines fallback store is not measured at this volume.


Rebuilt on 2026-10-19 by the phase-10 steward pass: the per-element lines are now generated from the status data of main `383485d` and list every open requirement, partly verified ones included, with the missing part taken from the claiming tests' comments and the verification statement. The section below collects what only the owner can provide.

## Blocked on the owner

These open requirements cannot be closed by more code or CI work in this repository. Each needs something only the project owner can provide or decide. Everything else in the list above can be closed by a test, a record or a release run.

- **Three first-time users for the G-04 usability Demonstration** (FR-8.24). Needed: three people who have not used the console, each given the in-console help and the task "create and publish a scoped Observation Policy of at least 10 parameters" in the G-04 Observation & Parameter Workbench, timed from sign-in. The requirement passes when at least two finish within 10 minutes. The owner records each person's time and completion (names are not needed) as a Demonstration record in `docs/verification/FR-8.24.md`, which now holds the scripted run, in the format of `docs/verification/README.md`. The scripted run of the same task (`console/e2e/firsttime.spec.ts`, 16 actions in Chromium, Firefox and WebKit) is supporting evidence only. The alternative is an SRS change that accepts the scripted run as the verification.
- **A Gemini API key for the Gemini CLI runs** (FR-15.8, FR-15.10, FR-18.3, and the Gemini CLI part of FR-15.1, FR-15.7, SR-4.9-1 and SR-4.11-1). Needed: a Google AI Studio (Gemini API) key stored as the repository Actions secret `GEMINI_API_KEY`. The Vercel AI Gateway key the other clients use does not serve the Gemini API, and the Real agents workflow runs Gemini CLI only when this secret is set (`.github/workflows/agents.yml`). With the key, the matrix job gives Gemini CLI a result and its quick start can be followed at the pinned version.
- **A decision on Grok Build** (FR-15.8, FR-15.10, FR-18.3, FR-15.1). Grok Build is a local client of SRS Appendix K, but xAI publishes no installable Grok Build CLI, so no pinned version can be installed or run, and its configuration location and lockdown mechanism are unconfirmed. Needed: either a download location and terms that allow running a pinned Grok Build CLI in CI, or an owner decision to change Appendix K (drop Grok Build from the local clients, or record it as not runnable for release 1.x the way live cloud-agent runs were descoped in FR-15.9).
- **A real tunnel for the Remote Access Profile** (FR-16.1, FR-16.2, FR-16.8). The listener, the origin fields and the tunnel drivers are tested behind a local TLS stand-in and against fake `tailscale` and `cloudflared` binaries. FR-16.2 is a Demonstration with each of Tailscale Funnel and Cloudflare Tunnel on a test host, and FR-16.1 and FR-16.8 need calls through such a tunnel. Needed, either of: (a) the owner runs `smcpctl remote enable tailscale`, `smcpctl remote check` and a few calls through the public name on a host of the owner's tailnet (Funnel is already enabled there), then the same with `cloudflared`, and records the output; or (b) repository Actions secrets for an ephemeral, Funnel-enabled Tailscale auth key and for a Cloudflare named-tunnel token with a hostname on a zone the owner controls, so a CI job can run the Demonstration. Exposing a Gateway on a public name is the owner's decision, which is why this is not done from CI without them.
