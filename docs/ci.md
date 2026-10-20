# Continuous integration for contributors

The CI workflow (`.github/workflows/ci.yml`) runs on pull requests, pushes to main, release tags and `workflow_dispatch`. Branch protection on main requires the checks `srs`, `go`, `lint`, `site`, `security`, `linux-integration` and `console` (strict: the branch must be up to date with main).

## Which jobs a pull request runs

A full run takes 25 to 35 minutes, almost all of it in `console` (the Playwright tests on three browsers) and `go` (the tests with `-race` and coverage). A pull request that changes only documentation does not need them. The first job, `changes`, lists the files the pull request changes and decides what runs:

| The pull request changes only | `srs`, `lint`, `security`, `site` | `go` | `linux-integration`, `install-standalone`, `windows`, `console`, `graph`, `hostile`, `installers` |
|---|---|---|---|
| Markdown files under `docs/` (`docs/**/*.md`) | run | light | skipped |
| Markdown files at the repository root (README, CHANGELOG, FloorPlan, the SRS, the architecture documents) | run | light | skipped |
| `srs_build/` | run | light | skipped |
| `site/data/` | run | light | skipped |
| `site/` outside `site/data/` | run | skipped | skipped |
| `desktop/` (the desktop application) | run | skipped | skipped |
| anything else, alone or with the above | run | full | run |

- **light**: `go` builds, vets and runs every Go test without `-race` and without coverage, then maps the results with `tools/reqreport`. The Go tests read many of these files: the documentation tests check every `docs/` page and README (commands, links, the index), `tools/reqreport` parses `srs_build/`, `ArchitectureV2.md` and the verification records under `docs/verification/`, the release tests read `docs/install.md`, `docs/release-checklist.md` and SECURITY.md, and `tools/openapi` compares `site/data/openapi.json` with the routes. CHANGELOG is not read by a test today; it is light with the other root Markdown files to keep the rule simple. So `go` still runs for them.
- **full**: everything, as before. Any other file means a full run: Go code, `go.mod`, `go.sum`, `console/`, `scripts/`, `packaging/`, `tools/`, `.github/`, `Makefile`, `install.sh`, test data, configuration, and every file under `docs/` that is not Markdown (`docs/*.go`, `docs/parameters.json`, which the binaries embed, `docs/schemas/`, `docs/status/elements.json`, `docs/clients/matrix.json`).
- `srs`, `lint`, `security` and `site` always run; each takes under two minutes. `lint` also runs `go run ./tools/uilint`, which reads the UI strings and stylesheets under `console/`, `site/src/`, `site/public/` and `desktop/` (docs/design/writing.md), so a pull request that changes only `site/` is still checked by it even though `go` is skipped.
- `desktop` (the desktop application, E-34, SRS FR-20; one job on macOS arm64 and one on Ubuntu 24.04) runs when the pull request changes `desktop/`, any Go file, `go.mod`, `go.sum`, `tools/reqreport/` or this workflow; its macOS leg only for `desktop/`, `tools/reqreport/` or this workflow (see "macOS runners"). It is not a required check. It runs `npm run typecheck`, `npm test` and `npm run build` for the bundled windows, the npm audit gate on `desktop/`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`, and on macOS builds the unsigned `.app` bundle (artifact `desktop-app-macos-arm64`). The Rust tests claim requirements through `desktop/src-tauri/src/claims.rs`; `go run ./tools/reqreport cargo` turns the claims and the `cargo test` results into `go test -json` events (`build/desktop-<platform>-test.json`), which the `status` job merges on pushes to main.
- `console-enforced`, `perf`, `acceptance-enforced`, `offline` and `status` never run on pull requests.
- `windows` (on `windows-latest`) is not a required check; see [windows-port.md](windows-port.md).
- `installers` (the reusable workflow `installers.yml`: build the `.deb`, `.rpm` and macOS `.pkg`, all on Linux, and smoke-test each on Ubuntu, Fedora and macOS) runs with the heavy jobs and is not a required check. The release workflow runs the same workflow with the tag before it publishes, without the macOS smoke test, which it runs after publishing (see "macOS runners"). Before the smoke tests, each Linux runner and the macOS smoke test check that a truncated and an altered copy of their package are refused by the package manager and stop `scripts/package-smoke.sh` (`scripts/package-broken.sh`), and the Ubuntu `.deb` runners upgrade an installed package with `install.sh --package` (`tools/installsh.TestInstallScriptPackageUpgradeOnHost`). The workflow `installers-broken.yml` (manual and weekly) runs `installers.yml` with a deliberately altered `.deb` and checks that a stand-in for the release job does not run (FR-20.24).
- `install-guide` runs on every pull request (it follows `docs/install.md`); `install-standalone` runs with the heavy jobs. The macOS legs of both run only when the pull request can affect them (see "macOS runners").

A job skipped by its `if:` reports the conclusion "skipped", which satisfies a required check, so a docs-only pull request can merge when the jobs that ran pass.

The rule applies to `pull_request` runs only. Pushes to main (whose run publishes `status.json` to the site-data branch and must be complete), release tags and `workflow_dispatch` runs always run every job. If the `changes` job fails or cannot classify the files (no merge commit, an empty diff), every job runs.

## macOS runners

GitHub's macOS arm64 runners are sometimes unavailable for hours: jobs wait, then end with "The job was not acquired by Runner of type hosted even after multiple attempts" (in October 2026 the `macos-14` brownouts pushed load onto the newer images). No workflow uses `macos-latest` or `macos-14`: every macOS job names its image (`macos-26` for `install-standalone`, `install-guide`, the `.pkg` smoke test and `tap`; `macos-15` for `desktop`) and has a `timeout-minutes`. On top of that:

- **Nothing that must ship needs a Mac.** `installers.yml` builds the macOS `.pkg` on Ubuntu: GoReleaser cross-compiles the darwin-arm64 binaries and `packaging/installers/macos/build-pkg-linux.sh` signs each one ad hoc with `rcodesign` (apple-codesign, Apache-2.0) and writes the flat package with `xar` and bomutils' `mkbom`. `scripts/install-pkg-tools.sh` builds `xar` (mackyle/xar) and bomutils from pinned commits and downloads `rcodesign` 0.29.0 with a pinned SHA-256; the job caches the result. The package is the one `build-pkg.sh` builds with `pkgbuild` and `productbuild` on macOS (same payload, paths, root:wheel ownership and modes, identifier, version, PackageInfo, Distribution, no scripts); the only differences are the code-signature page size (rcodesign hashes 4 KiB pages as Go's linker does, codesign 16 KiB, so the cdhash differs; both are complete ad-hoc signatures that `codesign --verify --strict` accepts) and PackageInfo's `generator-version`. `build-pkg.sh` stays for `make installer-pkg` on a Mac.
- **Fewer macOS jobs on pull requests.** The `changes` job decides, for pull requests only (pushes to main, tags and dispatches run every leg):

  | macOS job | runs on a pull request that changes |
  |---|---|
  | `installers` / `smoke pkg (arm64)` (output `macos-pkg`) | `packaging/installers/macos/`, `installers.yml`, `installers-macos-smoke.yml`, `scripts/package-smoke.sh`, `scripts/install-pkg-tools.sh`, `.goreleaser.yaml`, or Go code that builds for darwin (`*.go` except `*_test.go`, `*_linux.go`, `*_windows.go`; `go.mod`, `go.sum`) |
  | `install-standalone (macos-26)`, `install-guide (macos-26)` (output `install-os`) | Go code for darwin and its tests, `go.mod`, `go.sum`, `install.sh`, `docs/install.md`, `scripts/ci-install-guide.sh`, `scripts/ci-install-standalone.sh` |
  | `desktop (macos)` (output `desktop-matrix`) | `desktop/`, `tools/reqreport/` |

  A change to `ci.yml` runs all of them. The Ubuntu legs run as before. The outputs are JSON matrices; when `changes` fails, every leg runs.
- **The macOS `.pkg` smoke test never blocks.** It is the reusable workflow `installers-macos-smoke.yml`: the `smoke pkg (arm64)` job has `continue-on-error`, and its `smoke pkg result` job classifies it as `passed`, `unavailable` (the job never ran its first step, or was cancelled: a warning, the run stays green) or `failed` (the test ran and failed: the job fails, so the run fails). Re-run `smoke pkg (arm64)` to retry; its dependent jobs re-run with it.
- **The release publishes only tested files.** `release.yml` runs `installers.yml` with `macos-smoke: false`, so the release job waits only for Linux runners. It publishes the smoke-tested `.deb` and `.rpm`; the `.pkg` goes to `build/installers-pending/`, which GoReleaser lists in the signed checksum file (`checksum.extra_files`) but does not upload (`release.extra_files` is `build/installers/*` only). After publishing, `smoke-macos` installs that same `.pkg` artifact on macOS, and `macos-pkg` uploads it only when the outcome is `passed` and its SHA-256 is the one in the published checksum file, whose minisign signature it verifies first. When the outcome is `unavailable`, `macos-pkg` opens an issue saying to re-run `smoke-macos / smoke pkg (arm64)`; the re-run uploads the `.pkg`. When it is `failed`, `macos-pkg` opens an issue, adds a "macOS .pkg withheld" note to the release notes and fails. The checksum file can list a `.pkg` that is not (yet) on the release; every file that is on the release was tested.

## How the files are listed

A `pull_request` run checks out the merge commit of the pull request into the current base. `changes` lists `git diff --no-renames --name-only HEAD^1 HEAD`: exactly what merging the pull request would change, with both paths of a rename.

## Changing the workflow

- Do not add `paths-ignore` or `paths` to a workflow that hosts a required check: a required check that never reports blocks the pull request.
- Do not rename a required job.
- A new heavy job gets `needs: changes` and the same `if:` as `console`: `!cancelled() && (needs.changes.result != 'success' || needs.changes.outputs.heavy == 'true')`. The first part makes the job run when `changes` itself failed.
- A new macOS job names its image (never `macos-latest`), sets `timeout-minutes`, is gated on pull requests by a `changes` output as in "macOS runners", and does not block a release.
- When a Go test or tool starts reading a file that is classified as light or skipped (for example a file under `site/` outside `site/data/`), update the `case` patterns in the `changes` job and the table above.
