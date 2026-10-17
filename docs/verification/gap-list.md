# Verification gap list

Requirements that no test or record verifies, grouped by primary element (the first E-xx of the requirement's allocation), each with one line on what is missing. Built on 2026-10-16 from the requirement report of `origin/main` at `067ccbc` plus the tests and records added with this file (rebased on `217535b`, which verifies SR-2.6-1 and SR-8.9-1), by reading each requirement against the code. It is a starting point for implementation work, not a substitute for `make status`: regenerate the report before acting on an entry.

Each entry is marked:

- **missing**: the behavior, or a stated part of it, does not exist in the code.
- **unverified**: the behavior appears to exist, but no test or record proves the whole statement yet. These need a test or an inspection record, not new code.
- **external**: the requirement needs an artifact or run outside the source tree (a release, a person, reference hardware).

Parent requirements whose verification is "Review the verification results of every child requirement" (FR-1, FR-2, FR-3, FR-4, FR-5, FR-7, FR-8, FR-11, FR-12, FR-13, FR-14, FR-15, FR-16, FR-17, FR-19) are verified automatically by `tools/reqreport` once all their children are; they are not listed below.

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

Checked on 2026-10-17 by the phase-8 documentation pass against the status data of main `788c8b4` (529 requirements: 413 verified, 95 partial, 21 unverified, none failing). The 21 unverified are the 12 parents FR-3, FR-5, FR-7, FR-8, FR-11, FR-12, FR-13, FR-14, FR-15, FR-16, FR-17 and FR-19 and the nine requirements marked external or missing below (FR-12.1, FR-12.8, SR-4.1-1, FR-18.6, SR-6.12-1, FR-12.4, FR-15.9, FR-16.10, FR-18.3). Every acceptance scenario passed in the Enforced profile for that commit (label "enforced"). The FR-11 figures below are from the CI job `perf` of that commit.

## E-01 Harness Interface Endpoint

- FR-11.5 external: the CI job `perf` measures p95 P-213 (request receipt to delivery minus server execution to the backend's response) for 64 KiB results at eight concurrent calls with synchronous scoring (partial claim, `cmd/smcp-workload`; 17.4 ms and 19.0 ms on 4-CPU runners, 27.1 ms in the run of main `ee2e851`, 18.9 ms at `788c8b4`, budget 50 ms); no measurement on recorded reference hardware. AT-20 in the go job checks only the time before dispatch and after the completed event.
- FR-12.1 external: every archive of v1.0.0-rc.2 carries `sbom.spdx.json` (FR-13.1 inspection), but no record inspects its license fields; the v1.0.0 SBOM needs the same inspection.
- FR-12.8 external: the v1.0.0-rc.2 release carries archives, the signed checksum file, the Sigstore bundle and an SBOM per archive; no record inspects the bundle for commit IDs, build recipes, lockfiles and license notices.

## E-02 Protocol Mediator


## E-03 Identity & Authentication Service


## E-04 Session Manager


## E-05 Policy Administration Service


## E-06 Policy Decision Service

- FR-11.2 external: the CI job `perf` measures p95 decision latency for 100,000 decisions with 256 candidate rules and eight callers (partial claim; 0.03 ms at `788c8b4`, budget 10 ms); no measurement on recorded reference hardware.

## E-08 Access Enforcement Point


## E-12 Enforcement Coordinator

- SR-4.1-1 external: distinct CP-46 service identities are prepared by `packaging/linux/install-enforced.sh`; running processes on an Enforced host have not been inspected.

## E-13 Library Trust Verifier

- FR-18.6 external: `docs/packaging-guide.md` exists; nobody has followed it to package a non-reference server.

## E-14 Local Server Registry


## E-15 Server Runtime Manager


## E-18 Egress Broker


## E-20 Secret Broker


## E-21 Audit & Evidence Service

- SR-6.12-1 external: the evidence key and checkpoint directory permissions depend on the Enforced installation's identities; not exercised.

## E-22 Key & Trust Anchor Manager


## E-24 Management Console & Control API

- FR-8.4 to FR-8.8, FR-8.11 to FR-8.13, FR-8.15 to FR-8.17 (G-02 to G-05, G-07 to G-09 view requirements) partial: every view exists and `console/e2e/views.spec.ts` exercises each; the tests' partial claims reach the requirement report (`console/e2e/reqreport.ts`), but no Demonstration record exists. The G-03, G-04 and G-06 editors publish the Audit Profile, Observation Policy and Anomaly Response Policy objects of FR-3.1.
- FR-8.24 external: the Demonstration with three first-time users has not been run. A scripted run of the same G-04 task (`console/e2e/firsttime.spec.ts`, record `FR-8.24.md`) completes it in 16 actions in all three engines; it is not a person's time.
- FR-8.29 partial: `console/e2e/views.spec.ts` covers loading, empty and error states with partial claims; no test covers all three states for every view.
- FR-8.30 external: the console suite passed in Chromium 156, Firefox 157 and WebKit 27.2 of Playwright 1.64.1 (supporting record `FR-8.30.md`, partial claim in CI); the previous major version of each browser and Safari itself are not run.
- FR-8.31 partial: G-01 shows a first-run checklist (`console/src/views/Control.tsx`); no record compares its items with the requirement's list.
- FR-8.32, FR-8.33 unverified (partial claims): `console/e2e/a11y.spec.ts` runs axe on every view as it loads and tabs through every control of every view in all three browsers (WebKit with Option+Tab); `console/e2e/keyboard.spec.ts` completes the actions of every view G-01 to G-14 and Egress with keyboard events only in all three browsers and runs axe on each intermediate state; G-08 key rotation and graph rebuild, G-14 journal export downloads, the Runtime instance kill, and, on a dedicated Gateway, G-10 suspend and enable of the running server and the G-01 health acknowledgment are done with keyboard events too; the manual checks are in `FR-8.32.md` (Chromium, Firefox) and `FR-8.32-webkit.md`. Missing: a real instance for the Runtime kill (the acceptance Gateway runs no sandboxed instance, so its instance table is mocked) and an accepted graph rebuild (no graph database in the console job; the refusal is real, the accepted answer is mocked).
- FR-11.8 external: the CI job `perf` measures the console's audit queries over a 100,000-event, 30-day journal (partial claim; 803 ms p95 at `788c8b4`, budget 2,000 ms); analytics queries over 30 days of observation data and reference hardware are missing. The journal has no index (E-21 note).
- SR-7.5-2 partial: bootstrap, hash-password and admin redeem refuse arguments, standard input and files looser than 0600; the interactive prompt is not exercised (no terminal in tests), and there is no separate install command (installation runs bootstrap).

## E-25 Graph Database Engine


## E-26 Data Access Service


## E-28 Data Lifecycle & Memory Manager

- FR-11.9 external: the CI job `perf` samples the idle `smcpd` resident memory 10 minutes after start (partial claim; 103 MiB at `788c8b4`, budget 4 GiB); not on recorded reference hardware.
- FR-12.4 external: CP-46 directories, owners and modes have not been inspected on installed Enforced and Standalone hosts.

## E-29 Observation Collector

- FR-11.4 external: the CI job `perf` compares p95 P-213 with observation enabled and disabled over eight fresh instances in a balanced order (partial claim; -0.04 ms and -0.02 ms in two runs on 4-CPU runners, enabled 10.27 ms and disabled 10.28 ms in the second, after the capture path changes of 2026-10-17; 0.42 ms in the run of main `ee2e851`, 0.97 ms at `788c8b4` against the 1 ms budget; the runners' processor model varies between runs); no measurement on recorded reference hardware.

## E-31 Anomaly Scorer


## E-33 Harness adapters

- FR-15.9 missing: no dated manual cloud-agent run is recorded; every cloud entry in `docs/clients/matrix.json` is `not-run`.
- FR-16.10 missing: the cloud-agent quick start states each vendor allowlist setting as "not confirmed" rather than naming the setting or stating that none is offered.
- FR-18.3 external: per-client quick starts exist; none has been followed at the pinned version for every client (two local clients fail on the CA name constraints).
