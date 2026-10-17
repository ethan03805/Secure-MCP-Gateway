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

Requirements reported as **partial** are not listed one by one. Their claiming tests state, in the comment next to `reqtest.Partial`, which clauses are missing; `build/reqreport.md` lists the claiming tests of each.

## E-01 Harness Interface Endpoint

- FR-11.5 external: the CI job `perf` measures p95 P-213 for 64 KiB results at eight concurrent calls with synchronous scoring (partial claim, `cmd/smcp-workload`); no measurement on recorded reference hardware.
- FR-12.1 external: no release SBOM license check; needs a release artifact.
- FR-12.8 external: release provenance bundle (commit IDs, digests, recipes, lockfiles, SBOM, notices) not inspected; needs a release.
- SR-4.14-1 missing: `smcpctl remote enable` installs no nftables rules in the Enforced profile.

## E-02 Protocol Mediator


## E-03 Identity & Authentication Service


## E-04 Session Manager


## E-05 Policy Administration Service

- FR-18.5 partial: `internal/policy` `TestPolicyReferenceExamples` compiles every policy example in `docs/policy-reference.md` and checks that every schema field is described; object types, predicate operators and obligations that do not exist (FR-3.1, SR-1.7-1, FR-3.12) cannot be described.
- SR-7.9-1 partial: `TestPolicyRollbackKeepsRevocations` shows a policy rollback leaves credential revocations, principal and server suspensions in effect; rolling back the application version is not exercised, and there are no revocation epochs.

## E-06 Policy Decision Service

- FR-11.2 external: the CI job `perf` measures p95 decision latency for 100,000 decisions with 256 candidate rules and eight callers (partial claim); no measurement on recorded reference hardware.
- SR-1.10-1 partial: obligations combine restrict-only across the permit rule, template, profile, approval predicate, approval floor and taint (`TestObligationPrecedence`); overlapping permits are refused at publication (SR-1.9-1), so several applicable permits are never combined.

## E-08 Access Enforcement Point


## E-12 Enforcement Coordinator

- SR-1.2-2 unverified (partial claim exists): a failed decision-intent commit refuses launch with `-31004` and `JOURNAL_UNAVAILABLE`; no test makes the journal directory unwritable during traffic or stops the graph database during traffic.
- SR-4.1-1 external: distinct CP-46 service identities are prepared by `packaging/linux/install-enforced.sh`; running processes on an Enforced host have not been inspected.

## E-13 Library Trust Verifier

- FR-18.6 external: `docs/packaging-guide.md` exists; nobody has followed it to package a non-reference server.

## E-14 Local Server Registry


## E-15 Server Runtime Manager


## E-18 Egress Broker


## E-20 Secret Broker

- SR-2.13-2 missing: delivery buffers are wiped where they are byte slices, but S4 environment delivery and string conversions keep copies that cannot be overwritten.

## E-21 Audit & Evidence Service

- SR-6.12-1 external: the evidence key and checkpoint directory permissions depend on the Enforced installation's identities; not exercised.

## E-22 Key & Trust Anchor Manager


## E-24 Management Console & Control API

- FR-8.4 to FR-8.8, FR-8.11 to FR-8.13, FR-8.15 to FR-8.17 (G-02 to G-05, G-07 to G-09 view requirements) unverified: every view exists and `console/e2e/views.spec.ts` exercises each; the tests' partial claims reach the requirement report (`console/e2e/reqreport.ts`), but no Demonstration record exists. The G-03, G-04 and G-06 editors publish the Audit Profile, Observation Policy and Anomaly Response Policy objects of FR-3.1.
- FR-8.24 external: the timed first-time-user task has not been run.
- FR-8.29 unverified: `console/e2e/views.spec.ts` covers loading, empty and error states with partial claims; no test covers all three states for every view.
- FR-8.30 external: no browser-support matrix run.
- FR-8.31 unverified: G-01 shows a first-run checklist (`console/src/views/Control.tsx`); no record compares its items with the requirement's list.
- FR-8.32, FR-8.33 unverified (partial claims): `console/e2e/a11y.spec.ts` runs axe on every view as it loads and tabs through every control of every view in Chromium and Firefox; `console/e2e/keyboard.spec.ts` completes a set of actions in seven views with keyboard events only in all three browsers (WebKit with Option+Tab) and runs axe on each of its 21 intermediate states; the manual check is in `FR-8.32.md`. Missing: keyboard-only completion and axe for the remaining actions of the acceptance tests (for example G-04, G-05, G-09, G-12 and G-13 actions).
- FR-11.8 external: the CI job `perf` measures the console's audit queries over a 100,000-event, 30-day journal (partial claim); analytics queries over 30 days of observation data and reference hardware are missing. The journal has no index (E-21 note).
- FR-13.3 external: the `tap` workflow installed v1.0.0-rc.2 from the tap on macOS and Ubuntu and found every binary equal to the release archive (supporting record `FR-13.3.md`), but it is a CI workflow, not a test `tools/reqreport` counts.
- SR-7.5-2 unverified (partial claim exists): bootstrap, hash-password and admin redeem refuse arguments, standard input and files looser than 0600; the interactive prompt is not exercised (no terminal in tests), and there is no separate install command (installation runs bootstrap).

## E-25 Graph Database Engine


## E-26 Data Access Service


## E-28 Data Lifecycle & Memory Manager

- FR-11.9 external: the CI job `perf` samples the idle `smcpd` resident memory 10 minutes after start (partial claim); not on recorded reference hardware.
- FR-12.4 external: CP-46 directories, owners and modes have not been inspected on installed Enforced and Standalone hosts.

## E-29 Observation Collector

- FR-11.4 missing: the CI job `perf` compares p95 P-213 with observation enabled and disabled; the first runs measured a difference of about 8 ms on a CI runner and 15 ms on a developer laptop, above the 1 ms budget, so the measurement is a failing test until capture cost is reduced (and it is not on recorded reference hardware).

## E-31 Anomaly Scorer


## E-33 Harness adapters

- FR-15.9 missing: no dated manual cloud-agent run is recorded; every cloud entry in `docs/clients/matrix.json` is `not-run`.
- FR-16.10 missing: the cloud-agent quick start states each vendor allowlist setting as "not confirmed" rather than naming the setting or stating that none is offered.
- FR-18.3 external: per-client quick starts exist; none has been followed at the pinned version for every client (two local clients fail on the CA name constraints).
