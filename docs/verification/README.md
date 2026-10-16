# Verification records

Records for verification that is not an automated test: Inspection, Analysis and Demonstration results, acceptance scenarios executed by a person, runbook executions and the real-harness approval test. The requirement report counts a requirement as verified from a record only when the record is complete and its result is `pass` (SRS Section 2.6).

## File names

| Record | File |
|---|---|
| Acceptance scenario (FR-19.4) | `AT-nn.md`, for example `AT-18.md` |
| Requirement verified by Inspection, Analysis or Demonstration | `<requirement ID>.md`, for example `FR-13.1.md` |
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

It then lists the steps as performed, the observations, and any deviation from the verification statement. A record for a failed or partial run is kept; a later passing run is a new record.

No records exist yet.
