# Console visual rules

Checklist for the management console (E-24). Each view is inspected against it before release (SRS FR-8.35). The rules follow the owner's direction: dense, stark, typographic, tables over cards.

| Rule | Check |
|---|---|
| Lists are tables | Every collection (sessions, servers, approvals, decisions, events, policy revisions) is a `<table>` with a header row and sortable column headers. No card grids. |
| One typeface family | One family for text and one monospaced face for IDs, digests and code, with a fixed type scale of at most five sizes. |
| No decoration | No gradients, drop shadows used for decoration, emoji, illustrations or decorative icon grids. Icons appear only where they carry meaning and have a text label. |
| Color carries state only | Color marks state (fail-closed, degraded, denied, pending) and is never the only cue; each state also has a text label. |
| Density | Table rows at most 32 px high at the default size; no empty hero areas. |
| Text | Plain, specific labels and messages; no marketing language and no exclamation marks. Error states show the control API message and reason code (FR-8.29). |
| Hand-built components | Components are written in the project; no component kit (no Mantine or similar). |
| Accessibility | WCAG 2.2 AA (FR-8.32): contrast at least 4.5:1 for text, visible focus, target size at least 24 by 24 CSS px, every action reachable by keyboard (FR-8.33). |
| Local assets | All scripts, styles and fonts are served by the Gateway (FR-8.26). |
