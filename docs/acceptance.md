# Acceptance scenarios, release label and performance

This page describes how the acceptance scenarios AT-01 to AT-21 of SRS Appendix M are run and reported (FR-19.4), how a release gets its "enforced" or "not enforced" label (FR-19.3), and how the FR-11 performance measurements are produced.

## Claiming a scenario

A Go test claims a scenario with `reqtest.Scenario(t, profile, "AT-nn")`, where `profile` is `reqtest.Standalone` or `reqtest.Enforced` and must be the profile the Gateway actually ran in. The test claims the scenario's requirements separately with `reqtest.Verifies` or `reqtest.Partial`. A Playwright test claims one with the annotation `{ type: "scenario", description: "AT-nn profile=standalone" }`. A scenario executed by a person is recorded in `docs/verification/AT-nn.md` in the record format of [verification/README.md](verification/README.md); its "Profile and platform" field starts with `Enforced` or `Standalone`.

`tools/reqreport` computes, for every scenario and profile:

- **fail**: a claiming test in that profile failed or never finished, or the latest counted record says `fail`;
- **pass**: at least one claiming test or counted record passed and nothing failed;
- **not-run**: otherwise. A skipped test is not a result.

A record counts only when it is complete and its commit is the commit of the report. The results are in `build/reqreport.md` ("Acceptance scenarios") and in the `acceptance` member of the status data, which the project site shows on its Status page.

## The release label

The label is "enforced" only when every one of the 21 scenarios passed in the Enforced profile for the release commit, and "not enforced" otherwise (FR-19.3). The release workflow runs

```
go run ./tools/reqreport label -status status.json -commit "$GITHUB_SHA" -out release-label.md
```

on the status data published for the tagged commit and adds the result to the release notes. Status data for any other commit labels the release "not enforced". The Standalone profile can never earn the label.

## Where each scenario runs

| Scenario | Tests | Profile |
|---|---|---|
| AT-01 to AT-06, AT-09, AT-13 to AT-16, AT-18 to AT-21 | `internal/acceptance`: the real `smcpd`, `smcpctl` and `smcp-refserver`, bootstrapped in temporary directories and driven through the CLI, the control API and an OAuth-signed MCP client | Standalone in the `go` job; Enforced in the `acceptance-enforced` job (`SMCP_ACCEPTANCE_PROFILE=enforced`, rootless Podman) |
| AT-08 | `internal/hostile`: HF-20 to HF-24 must all pass | Enforced (CI job `hostile`) |
| AT-09 | also `internal/hostile`: HF-04 to HF-09 and HF-16 | Standalone and Enforced (CI job `hostile`) |
| AT-11 | `internal/graph` `TestAT11AuditLinkageSurvivesChanges` | Standalone |
| AT-12 | `internal/edge` (journal flush faults before launch and before release) and `internal/graph` (mirror replay, duplicate event IDs) | Standalone |
| AT-17 | `internal/acceptance` `TestAT17OfflineEngineeringWorkflow`, in the CI job `offline`: the reference filesystem and git packages are built with network access, then the acceptance suite runs in a network namespace with loopback only | Standalone |
| AT-20 | `internal/acceptance` `TestAT20LimitsAndLoad` mounts a 320 MiB file system (disk image on macOS, tmpfs with sudo on Linux) to fill the audit reserve | Standalone |
| AT-07 | `console/e2e/inert.spec.ts` (Playwright): hostile strings in every view are inert text, and G-10 bounds evidence to 256 KiB per page | Standalone (CI job `console`) |
| AT-10 | none yet: see the gap list | not run |

AT-10 needs the one-use egress capability of SR-5.16-1, which the Egress Broker does not check. It is not claimed until that exists.

Run the suite locally with `go test ./internal/acceptance/` (about 100 seconds; skipped with `-short`). AT-17 skips unless `SMCP_ACCEPTANCE_OFFLINE=1` and `SMCP_REFPKG_DIR` are set.

## Performance measurements (FR-11)

`smcp-workload` (`cmd/smcp-workload`, shipped in the release archives) is the reference workload generator of FR-11.1:

- `smcp-workload generate --out DIR [--state STATE]` writes the reference policy (9,995 rules plus the 5 registry nodes of the reference server, 256 candidate rules for every decision of the decision template) and, with `--state`, a signed 100,000-event Evidence Journal spanning 30 days into a bootstrapped state directory;
- `smcp-workload run --bin DIR --out perf.json --test-json perf-test.json` starts real `smcpd` instances and measures, with eight concurrent callers:

| Requirement | Measurement | Budget (CP-32) |
|---|---|---|
| FR-11.2 | p95 latency of 100,000 decisions against the compiled reference policy, as the caller sees it | 10 ms |
| FR-11.4 | p95 P-213 with observation enabled minus disabled, same workload on four fresh instances (enabled, disabled, disabled, enabled; mean p95 per condition) | 1 ms |
| FR-11.5 | p95 P-213 for 64 KiB results with synchronous scoring (journal timestamps: requested to dispatched plus completed to delivered) | 50 ms |
| FR-11.8 | p95 of the console's audit queries over the 30-day, 100,000-event journal, 100 repetitions | 2 s |
| FR-11.9 | resident memory of an idle `smcpd` 10 minutes after start | 4 GiB |

The CI job `perf` runs on pushes to main and on demand; the status job publishes `perf.json` as the `performance` member of the status data and merges `perf-test.json`, where each measurement within its budget is a partial claim of its requirement and each one over budget is a failing test. CI runners are not the recorded reference hardware, so these measurements never fully verify an FR-11 requirement.

## Stage timing spans (FR-10.2, FR-10.11)

Every tool call emits one span per pipeline stage (authenticate, session check, decision, request inspection, approval, launch authorization, dispatch, response inspection, release authorization) and one per filter run, with monotonic start and end, the thread CPU time of the stage, the correlation ID and the policy revision and decisive rule revision of the call's decision. The Observation Collector stores them in the `spans` table (`monotonic = 1`, `cpu_ms`, `rule_id`, `filter_id`) and aggregates span time by stage, policy revision, rule, filter and Observation Policy; `GET /api/v1/observations/cost` returns the aggregation as `policy_objects` and the filters alone, most expensive first, as `filters`.

The CPU time of a stage is the thread CPU time of the call's goroutine in the stage outside its waits (for the filters, the server, the approver and the journal); the inspection stages add the CPU time of their filters, each measured on its own goroutine outside its waits (`pipeline.WaitUnmeasured`). A goroutine is locked to its OS thread only while it runs: one that blocks while locked can resume only on that thread, and on a busy host that delayed every wait of the call by up to a scheduling quantum. Held for the whole call, the lock was most of the FR-11.4 capture overhead the CI job `perf` measured.
