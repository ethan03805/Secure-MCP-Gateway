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
- `desktop` (the desktop application, E-34, SRS FR-20; one job on macOS arm64 and one on Ubuntu 24.04) runs when the pull request changes `desktop/`, any Go file, `go.mod`, `go.sum`, `tools/reqreport/` or this workflow. It is not a required check. It runs `npm run typecheck`, `npm test` and `npm run build` for the bundled windows, the npm audit gate on `desktop/`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`, and on macOS builds the unsigned `.app` bundle (artifact `desktop-app-macos-arm64`). The Rust tests claim requirements through `desktop/src-tauri/src/claims.rs`; `go run ./tools/reqreport cargo` turns the claims and the `cargo test` results into `go test -json` events (`build/desktop-<platform>-test.json`), which the `status` job merges on pushes to main.
- `console-enforced`, `perf`, `acceptance-enforced`, `offline` and `status` never run on pull requests.
- `windows` (on `windows-latest`) is not a required check; see [windows-port.md](windows-port.md).
- `installers` (the reusable workflow `installers.yml`: build the `.deb`, `.rpm` and macOS `.pkg` and smoke-test each on Ubuntu, Fedora and macOS) runs with the heavy jobs and is not a required check. The release workflow runs the same workflow with the tag before it publishes.

A job skipped by its `if:` reports the conclusion "skipped", which satisfies a required check, so a docs-only pull request can merge when the jobs that ran pass.

The rule applies to `pull_request` runs only. Pushes to main (whose run publishes `status.json` to the site-data branch and must be complete), release tags and `workflow_dispatch` runs always run every job. If the `changes` job fails or cannot classify the files (no merge commit, an empty diff), every job runs.

## How the files are listed

A `pull_request` run checks out the merge commit of the pull request into the current base. `changes` lists `git diff --no-renames --name-only HEAD^1 HEAD`: exactly what merging the pull request would change, with both paths of a rename.

## Changing the workflow

- Do not add `paths-ignore` or `paths` to a workflow that hosts a required check: a required check that never reports blocks the pull request.
- Do not rename a required job.
- A new heavy job gets `needs: changes` and the same `if:` as `console`: `!cancelled() && (needs.changes.result != 'success' || needs.changes.outputs.heavy == 'true')`. The first part makes the job run when `changes` itself failed.
- When a Go test or tool starts reading a file that is classified as light or skipped (for example a file under `site/` outside `site/data/`), update the `case` patterns in the `changes` job and the table above.
