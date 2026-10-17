# Verification records

Records for verification that is not an automated test: Inspection, Analysis and Demonstration results, acceptance scenarios executed by a person, runbook executions and the real-harness approval test. The requirement report counts a requirement as verified from a record only when the record is complete and its result is `pass` (SRS Section 2.6).

## File names

| Record | File |
|---|---|
| Acceptance scenario (FR-19.4) | `AT-nn.md`, for example `AT-18.md` |
| Requirement verified by Inspection, Analysis or Demonstration | `<requirement ID>.md`, for example `FR-13.1.md`, or a section of `inspections.md` |
| Runbook execution (FR-18.8) | `runbook-<name>-<date>.md` |
| Real-harness approval test (FR-3.25) | `FR-3.25.md` with the transcript beside it |

## Required fields

Each record starts with this table:

| Field | Content |
|---|---|
| Requirement or scenario | The ID(s) verified |
| Commit | Full commit SHA of the build under test |
| Profile and platform | Enforced or Standalone; OS and architecture |
| Date | ISO 8601 date |
| Executor | Name or handle of the person who ran it |
| Method | Inspection, Analysis, Demonstration or Test |
| Result | `pass` or `fail` |

It then lists the steps as performed, the observations, and any deviation from the verification statement. Evidence in source is cited as `` `path:line` `` (line numbers of the recorded commit). A record for a failed or partial run is kept; a later passing run is a new record.

## How the report counts records

`tools/reqreport` (`make status`) reads every `*.md` file here except this README. A record starts at its `| Requirement or scenario | ... |` row. It verifies a requirement when:

- every field above is filled in, the commit is a full SHA and the date is ISO 8601;
- the record's method equals the requirement's SRS verification method, and that method is Inspection, Analysis or Demonstration (Test-method requirements are verified only by automated tests);
- an Inspection record cites at least one `` `path:line` ``, and every cited file exists in the tree;
- the record with the latest date for that requirement has result `pass` (a later `fail` makes the requirement failing).

A record that does not meet these rules is reported as a warning and not counted. A record with method `Test` is a supporting record: it documents a manual step that the SRS asks to file next to the automated tests of a Test-method requirement (for example the manual check of FR-8.32). It is validated like any record but never counts as verification. A parent requirement whose Analysis is "Review the verification results of every ... child requirement" is verified automatically when every child requirement is verified.

## Files

- [inspections.md](inspections.md): Inspection and Analysis records.
- [FR-8.32.md](FR-8.32.md): the manual focus-order, target-size and contrast check of the console (supporting record).
- [FR-3.25.md](FR-3.25.md): the real-harness approval run with Claude Code, with its [transcript](FR-3.25-transcript.md).
- [FR-12.12.md](FR-12.12.md): Claude Code and Codex CLI connecting through `smcp-session` (Demonstration).
- [FR-13.3.md](FR-13.3.md): the Homebrew tap installation run of v1.0.0-rc.2 on macOS and Ubuntu (supporting record).
- [gap-list.md](gap-list.md): requirements that are not verified, grouped by element, with what is missing.
