# Site

The technical reference for the Secure MCP Gateway: a static Next.js export built from the repository on every push to
main and deployed on Vercel (`vercel.json` at the repository root).

Nothing on the site is typed in by hand. Counts, element pages, requirements, controls and diagrams are parsed from the
documents at build time; implementation, test, coverage and verification figures come from the CI status data.

## Commands

```
npm ci
npm run build       # static export to out/
npm run typecheck   # tsc --noEmit
npm run dev
```

## Inputs

| Input | Read by | Notes |
|---|---|---|
| `ArchitectureV2.md` | `src/lib/parse-arch.ts` | The build fails with a named section if an expected heading or table is missing. |
| `srs_build/req*.txt` | `src/lib/parse-reqs.ts` | The requirement source records, not the generated SRS. |
| `MCP_Gateway_Security_SRS.md` | `src/lib/parse-sec.ts` | |
| `docs/flows/*.md` | `src/lib/flows.ts` | Every file becomes a page under Flows. An empty or missing directory is allowed. |
| `status.json`, `history.json` | `src/lib/status.ts` | Published by CI to the `site-data` branch. See below. |

## Status data

`next.config.ts` calls `prepareStatusSnapshot()` once per build, before any page renders. It fetches:

| Variable | Default |
|---|---|
| `SITE_STATUS_URL` | `https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/site-data/status.json` |
| `SITE_HISTORY_URL` | the status URL with `status.json` replaced by `history.json` |

Each request has a 5 second timeout. `file://` URLs work, for local testing. If the status file cannot be fetched,
is not JSON, or is not schema 1, the build uses `data/status.sample.json` and `data/history.sample.json` instead and
every page that shows status figures says "sample data". The build never fails because status data is missing.

The snapshot is written to `.status/snapshot.json` (ignored by git) so every page in one build shows the same data.

The schema is the shared status contract between the CI job and the site; `Status` and `HistoryPoint` in
`src/lib/status.ts` mirror it field for field.

## Testing other inputs

```
SITE_STATUS_URL=http://10.255.255.1/status.json npm run build   # unreachable: falls back to the sample
SITE_STATUS_URL=file:///path/to/status.json npm run build       # a local status file, read as live data
SITE_FLOWS_DIR=/path/to/flows npm run build                     # flow documents from another directory
```

## Charts

Charts are server-rendered SVG in `src/components/charts/`. Each has a title and description for assistive
technology, a legend when it has more than one series, and a data table in a `details` element. The requirement
status colors were checked for adjacent-pair separation under color-vision deficiency in light and dark mode; status
is always also given as a word and a glyph.
