# Verification gap list

Requirements that no test or record verifies, grouped by primary element (the first E-xx of the requirement's allocation), each with one line on what is missing. Built on 2026-10-16 from the requirement report of `origin/main` at `067ccbc` plus the tests and records added with this file (rebased on `217535b`, which verifies SR-2.6-1 and SR-8.9-1), by reading each requirement against the code. It is a starting point for implementation work, not a substitute for `make status`: regenerate the report before acting on an entry.

Each entry is marked:

- **missing**: the behavior, or a stated part of it, does not exist in the code.
- **unverified**: the behavior appears to exist, but no test or record proves the whole statement yet. These need a test or an inspection record, not new code.
- **external**: the requirement needs an artifact or run outside the source tree (a release, a person, reference hardware).

Parent requirements whose verification is "Review the verification results of every child requirement" (FR-1, FR-2, FR-3, FR-4, FR-5, FR-7, FR-8, FR-12, FR-13, FR-14, FR-15, FR-16, FR-17, FR-19) are verified automatically by `tools/reqreport` once all their children are, and reported partial while some but not all children are verified or partial; they are not listed below. FR-11 is reviewed against the performance report on recorded hardware instead.

Requirements deferred from release 1.0 (SRS Section 2.7, Appendix N) are not part of the requirement set and are not listed.

Updated on 2026-10-17 against the status data of `58a40c1`: entries that tests now verify or partly verify were removed (FR-1.39, FR-1.40, FR-1.49, FR-5.20, FR-5.24, SR-5.6-2, SR-7.2-1 and FR-19.1 after the hostile-suite fixes).

Updated on 2026-10-17 by the acceptance work: FR-11.1 and FR-10.11 are verified, FR-10.2, FR-12.2, FR-19.3 and SR-7.11-1 have partial claims, the FR-11 measurements have partial claims from the CI job `perf`, and FR-12.5 is deferred (Appendix N).

Updated on 2026-10-17 by the E-01 to E-04 partials sweep: SR-7.11-1 is verified (CP-09 connection and unauthenticated-work limits, slow headers and bodies, `internal/edge.TestPreParseBounds`).

Updated on 2026-10-17 by the egress-capability work: SR-5.16-1 is restored from Appendix N and verified (`TestEgressCapabilities`), and AT-10 is claimed by `TestAT10WebBroker`, so every scenario has a claiming test (FR-19.4). Whether the release label is "enforced" depends on the scenarios passing in the Enforced profile for the release commit (FR-19.3).

Updated on 2026-10-17 by the perf work: FR-11.4 is within its budget in the CI job `perf` (partial claim, no longer missing). The perf harness now takes P-213 from the request's receipt to delivery minus server execution to the backend's response; before, it ended server execution at the completed event, which follows response inspection, and so left response inspection out of FR-11.4 and FR-11.5.

Checked on 2026-10-17 against the status data of main `ee2e851` (386 verified, 117 partial, 26 unverified, none failing); every unverified requirement other than a parent is listed below, together with partly verified requirements whose missing part is external (reference hardware, a release, a person) needs a record rather than a test, or was a single named case (SR-7.9-1, since verified).

Updated on 2026-10-17 by the security-final work: SR-4.14-1 is implemented (`smcpctl remote enable` installs nftables host rules; verified by the root namespace test of the linux-integration job, partial claims elsewhere), SR-2.13-2 is narrowed and verified by an inspection record, SR-7.9-1 is verified by AT-19 (a server revision suspended before both rollbacks), and SR-3.6-1, SR-5.8-1, SR-5.9-2 and SR-6.2-1 are verified by new tests. SR-4.9-1 and SR-4.11-1 stay partial: they need each client started at its pinned version with a second server added (real-agent workflow).

Updated on 2026-10-17 by the partials-c sweep: FR-1.51, FR-17.3, FR-13.13 (verification narrowed to one schema version) and FR-10.34 (audit subgraph added; checked with pinned pyarrow, pandas and NetworkX in the CI go job) have verifying tests; none of them was listed.

Requirements reported as **partial** are not listed one by one. Their claiming tests state, in the comment next to `reqtest.Partial`, which clauses are missing; `build/reqreport.md` lists the claiming tests of each.

Updated on 2026-10-17 by the verification records work: FR-18.8 (runbook executions, `runbooks/FR-18.8.md`), FR-14.5, FR-3.18 and FR-12.3 have records; FR-8.24, FR-8.30, FR-8.32, FR-8.33 and FR-13.3 are updated below. FR-14.9 is claimed by the `reference-packages` workflow's published result (partial on a branch, full on a release tag). After the merge, the `tap` workflow for v1.0.0-rc.2 (run 39074221187) and the `reference-packages` workflow on main (run 39074222847) published their results to `site-data/workflows.json`: FR-13.3 is verified by the tap run of a release tag (its line is removed), FR-14.9 is partial until the workflow runs on a release tag.

Updated on 2026-10-18 by the data partials work: FR-7.11 is verified by `internal/e2e` `TestHealthFaultEachDependency` (each dependency faulted in turn in a running Gateway; vault availability and decision-snapshot currency checks added, every check evaluated once per second).

Updated on 2026-10-18 by the data partials work: SR-7.8-1 is verified (`internal/backup` `TestRestoreVerifiesPolicyStoreReappliesRevocationsAndRebuildsGraph`).

Updated on 2026-10-18 by the data partials work: FR-17.7 is verified (`TestOpsKeyRotationUnderTraffic`; the SRS statement of the CA overlap was narrowed to what one TLS chain per handshake can serve).

Checked on 2026-10-17 by the phase-8 documentation pass against the status data of main `788c8b4` (529 requirements: 413 verified, 95 partial, 21 unverified, none failing). The 21 unverified are the 12 parents FR-3, FR-5, FR-7, FR-8, FR-11, FR-12, FR-13, FR-14, FR-15, FR-16, FR-17 and FR-19 and the nine requirements marked external or missing below (FR-12.1, FR-12.8, SR-4.1-1, FR-18.6, SR-6.12-1, FR-12.4, FR-15.9, FR-16.10, FR-18.3). Every acceptance scenario passed in the Enforced profile for that commit (label "enforced"). The FR-11 figures below are from the CI job `perf` of that commit.

Updated on 2026-10-18 by the release-ops work: FR-19.3 has an Inspection record (`FR-19.3.md`), FR-19.4 is verified by `TestEveryScenarioHasEvidence` (it now reads the AT-07 annotation of the console suite), FR-14.9 is verified by the `reference-packages` run on tag v1.0.0 (run 39096364892, published to `site-data/workflows.json`), and the FR-12.1 and FR-12.8 entries record the inspection of the v1.0.0 release. SR-7.5-2 (the prompt on a pseudo-terminal, and `smcpctl install`) and FR-16.11 (Operator refused through a signed-in console account) are verified, FR-13.6 is claimed by the `install-standalone` job (macOS arm64 and Ubuntu without Podman, merged only when both report), and SR-4.1-1 is narrowed and has an Inspection record of the linux-integration run of PR #104 (`SR-4.1-1.md`). FR-18.6 has an Inspection record (`FR-18.6.md`: `@modelcontextprotocol/server-sequential-thinking` packaged by following the guide, imported, enabled and called), and FR-14.1 is claimed in full by `TestIntegrationPackageBuildEachType` in the linux-integration job (the OCI image is probed with rootless Podman). FR-13.8 is verified by `TestUpgradeAndRollback` (a failing migration added) and FR-13.12 by `TestEnforcedUninstallAndPurgeOnHost` on the Enforced CI host.

Updated on 2026-10-18 by the console partials work (part B): FR-8.22, FR-8.23, FR-8.26, FR-8.27, FR-8.28, FR-8.29, FR-8.31, SR-3.4-1 (narrowed: the bill of materials is the signed provenance statement) and SR-6.17-1 (fixtures written by `scripts/evidence-fixture`) have verifying console tests, and SR-2-2 and SR-2.5-1 verifying acceptance tests against the real `smcpd`; the FR-8.29 and FR-8.31 entries are removed.

## E-01 Harness Interface Endpoint


## E-02 Protocol Mediator


## E-03 Identity & Authentication Service


## E-04 Session Manager


## E-05 Policy Administration Service


## E-06 Policy Decision Service


## E-08 Access Enforcement Point


## E-12 Enforcement Coordinator


## E-13 Library Trust Verifier


## E-14 Local Server Registry


## E-15 Server Runtime Manager


## E-18 Egress Broker


## E-20 Secret Broker


## E-21 Audit & Evidence Service


## E-22 Key & Trust Anchor Manager


## E-24 Management Console & Control API

- FR-8.16 partial: G-08 shows graph heap and page cache against budget, store sizes, the collector queue, the observation degradation stage, storage quota levels, backups and keys, and publishes the Observation Store memory budget, which applies at the next start of `smcpd` (not shown after a restart in a test); cache hit ratios and the Observation Store's memory use against its budget are not shown, because no element reports them.
- FR-8.24 external: the Demonstration with three first-time users has not been run. A scripted run of the same G-04 task (`console/e2e/firsttime.spec.ts`, record `FR-8.24.md`) completes it in 16 actions in all three engines; it is not a person's time.
- FR-8.30 external: the console suite passed in Chromium 156, Firefox 157 and WebKit 27.2 of Playwright 1.64.1 (supporting record `FR-8.30.md`, partial claim in CI); the previous major version of each browser and Safari itself are not run.
- FR-8.32, FR-8.33 unverified (partial claims): `console/e2e/a11y.spec.ts` runs axe on every view as it loads and tabs through every control of every view in all three browsers (WebKit with Option+Tab); `console/e2e/keyboard.spec.ts` completes the actions of every view G-01 to G-14 and Egress with keyboard events only in all three browsers and runs axe on each intermediate state; G-08 key rotation and graph rebuild, G-14 journal export downloads, the Runtime instance kill, and, on a dedicated Gateway, G-10 suspend and enable of the running server and the G-01 health acknowledgment are done with keyboard events too; the manual checks are in `FR-8.32.md` (Chromium, Firefox) and `FR-8.32-webkit.md`. The accepted graph rebuild is done with the keyboard on a dedicated Gateway with the graph mirror (`console/e2e/decision.spec.ts`; the console job runs Neo4j in a service container). Missing: a real instance for the Runtime kill (the acceptance Gateway runs no sandboxed instance, so its instance table is mocked).

## E-25 Graph Database Engine

- SR-7.4-1 partial: the graph job checks the engine's effective settings (no SR-7.4-1 finding), its plugin archives and its procedures. On the Enforced host the nftables rule that rejects new connections from `smcp-data` is checked with stand-in processes (`cmd/smcpctl.TestGraphPortFirewallOnHost`). Missing: an Enforced host that runs the engine itself as `smcp-data`, with its effective configuration and firewall rules inspected together.


## E-26 Data Access Service


## E-28 Data Lifecycle & Memory Manager

- FR-12.7 partial: `internal/acceptance.TestAdminCLIDemonstration` exercises 20 of the 23 subcommands on one installation in the Standalone profile (go job) and the Enforced profile (acceptance-enforced job) and uploads the steps (`build/admin-cli/<profile>.json`). `install`, `upgrade` and `uninstall` change the host and are exercised separately: `TestInstallStandaloneServiceManager` (install-standalone job, Standalone only), `TestUpgradeAndRollback` (test releases under a temporary root) and `TestEnforcedUninstallAndPurgeOnHost` (Enforced host). Missing: `install --profile enforced` and `upgrade` on a real Enforced installation, and a Demonstration record of a release build.

## E-29 Observation Collector


## E-31 Anomaly Scorer


## E-33 Harness adapters

- FR-18.3 external: per-client quick starts exist. The Claude Code quick start (option B) is followed at the pinned version by the `lockdown` job of the Real agents workflow, and the client lists and calls tools through the Gateway. Gemini CLI needs a `GEMINI_API_KEY` (the Vercel AI Gateway does not serve the Gemini API) and Grok Build has no publicly installable CLI, so their quick starts cannot be followed here.

Updated on 2026-10-18 by the remote-agents partials work: FR-12.13 and FR-16.9 are verified (`internal/conformance.TestConformanceThroughAdapters`). FR-15.9 and FR-16.10 are narrowed by an SRS change (live cloud-agent runs descoped from release 1.x) and verified by Inspection records. Parents with some evidenced children are now reported partial rather than unverified.

Updated on 2026-10-19 by the doctor work: FR-15.4 is verified by `cmd/smcpctl.TestDoctorEnforcedHostAsHarnessUser`. On the Enforced installation of the `linux-integration` job, doctor runs as the runner account (the harness user, not in group `smcp`), and then for a Standalone instance of the same user. Before this change doctor stopped at the unreadable Enforced configuration; it now checks the CP-46 Enforced directories as the harness user.

Checked on 2026-10-18 by the phase-9 steward pass against the status data of main `1a96b1c` (529 requirements: 457 verified, 68 partly verified, 4 unverified, none failing; v1.0.0 was released at 413, 95 and 21). The four unverified requirements are FR-11 (reviewed against a performance report on recorded hardware), FR-12.4, SR-6.12-1 and FR-18.3, each listed below; each parent not yet verified is reported partial. FR-9.17 is verified (smcpd answers `-31004` while the journal cannot be opened, then starts; AT-03). Every acceptance scenario passed in the Enforced profile for that commit (label "enforced"). The FR-11 figures below are from the CI job `perf` of `1a96b1c`. The lines below were checked against that status data: none of the listed requirements is verified yet.

Updated on 2026-10-19 by the secrets work: SR-2-1 is verified by `internal/secrets.TestSecretsNeverNorthbound`. Secrets are delivered in the S1 to S4 modes and echoed through results, tool errors, JSON-RPC errors and progress notifications. The test checks that none reaches the harness, the session API responses, the evidence or the diagnostic log.

Updated on 2026-10-18 by the v1.1.0 release: v1.1.0 (main `935dc4d`, release run 39178207151, rehearsed with v1.1.0-rc.2 on the same commit) is the first release built by the fixed pipeline. Its SBOMs and bundle were inspected: every SBOM entry has an OSI-approved license or a reviewed exception, and every archive carries the build recipe, the lockfiles, `PROVENANCE.md` and `THIRD_PARTY_NOTICES.txt`. FR-12.1 and FR-12.8 now have passing Inspection records (`inspections.md`) and their lines above are removed. FR-13.1 has a v1.1.0 record. The `tap` workflow passed for v1.1.0 on macOS and Ubuntu (run 39178720966), and `reference-packages` passed on the tag (run 39178206965); both results are published to `site-data/workflows.json` (FR-13.3, FR-14.9). The runbooks were executed again on `d55c08f` for FR-18.8 (`runbooks/`). In the CI status data of main `935dc4d` (529 requirements: 466 verified, 59 partly verified, 4 unverified, none failing; label "enforced") the four unverified requirements are still FR-11, FR-12.4, SR-6.12-1 and FR-18.3, listed above.

Updated on 2026-10-18 by the install-ops partials work: FR-13.5 is verified by `cmd/smcpctl.TestEnforcedInstallOnHost` on the linux-integration host, and FR-13.4 and FR-13.11 are claimed in full by `tools/reqreport.TestInstallProfilesEvidence` from the Standalone (macOS arm64, Ubuntu) and Enforced results of the same CI run. A Standalone `smcpctl uninstall` no longer removes the nftables table, AppArmor profiles, system units or service identities of an Enforced installation on the same host.

Updated on 2026-10-19 by the agents-partials work: the Real agents workflow has a `lockdown` job (`scripts/agents/lockdown.go`). Claude Code 2.1.302 follows its quick start (option B), connects over TLS with only what `smcpctl clients setup` wrote, and with the managed-settings lockdown applied a second MCP server in user and project scope does not load, the Read of the Gateway state directory and the Edit of its own `.mcp.json` are refused, and `smcpctl doctor` reports the extra servers (run 39184564500). The first run found that `smcpctl lockdown apply` wrote the managed file with mode 0600, which Claude Code ignored; it is now 0644. The job's result claims FR-15.2 and the matrix job's result claims FR-15.8 through `site-data/workflows.json` (partial from main, full from a release tag), and the broken-build check now runs every client. FR-15.1, FR-15.7, SR-4.9-1 and SR-4.11-1 stay partial: only Claude Code is locked down and run through `smcpctl clients setup` by CI; the lockdown mechanisms recorded for Codex CLI, OpenCode, Gemini CLI and Goose are not yet confirmed against their pinned versions.

Updated on 2026-10-18 by the perf work: the GitHub-hosted `ubuntu-24.04` standard runner class (x86_64, 4 vCPU, 16 GiB, SSD) is the recorded reference hardware of FR-11 (SRS §1.6, [reference-hardware.md](../reference-hardware.md)). `perf.json` records each run's processor, memory and disk, and a complete measurement within budget on that class is a full claim. The FR-11.2, FR-11.4, FR-11.5, FR-11.8 and FR-11.9 lines are removed. The CI job `perf` now also runs the FR-11.6 replay (2,000 records per second for 10 minutes through the analytics store writer into the DuckDB store, no backpressure signal) and the FR-11.8 analytics queries over the 30 days of observation data that replay writes. FR-11.9 now includes the graph engine (Neo4j, CP-33 budget). In the dispatch run 39190807816 of this branch (AMD EPYC 9V45, `referenceHardware` true), every measurement passed and was complete: FR-11.2 0.011 ms, FR-11.4 0.42 ms, FR-11.5 9.4 ms, FR-11.6 2,000 records/s with no offer at 80% queue occupancy and no drop, FR-11.8 458 ms p95 over 1,200,000 observation records and the 100,000-event journal, FR-11.9 1,541 MiB (smcpd 120 MiB, Neo4j 1,421 MiB). The earlier run 39187565839 on an EPYC 7763 runner measured FR-11.4 at 1.19 ms while Neo4j ran from the start of the job; the engine now starts after the FR-11.4 loads. On EPYC 7763 runners FR-11.4 had measured 0.52 to 0.95 ms before, so its margin stays thin there. FR-11 itself is reviewed by Analysis against a performance report and still needs a record that cites a passing `perf` run of main with every child verified. FR-11.6 and FR-11.8 are measured with the DuckDB store of the SRS stack. The release archives are built without cgo, and their JSON Lines fallback store is not measured at this volume.
