# Visual design guide

This guide is normative for the look of the management console, the windows of the desktop application (planned for v1.3.0, macOS arm64) and the reference site (SRS FR-20.50, planned v1.3.0). It builds on the [console visual rules](../console-style.md), which stay the checklist each console view is inspected against (FR-8.35); this page states the same direction for every surface and adds the rules the desktop application needs. Text is in the [writing style guide](writing.md).

The direction is the owner's: dense, stark, typographic, tables over cards.

## Layout

- **Dense but calm.** Show the data a person needs to decide without scrolling, in tables with hairline rules (`--rule`), not cards. Table rows at most 32 px high (console: 30 px plus a 1 px rule). White space separates groups; it does not fill a hero area.
- **Left-aligned reading order.** Text, headings, tables and forms align to one left edge and read top to bottom in the order a person acts. Numbers align right in table columns. Center only a single short line inside a small control.
- **Clear hierarchy.** One `h1` per page or window, naming it. Headings go down one level at a time (`h2` under `h1`, never `h1` to `h3`). The hierarchy comes from size, weight and position, not from color or boxes.
- **Containers.** A container is a region with a rule or a `--surface` background. Corner radius at most 4 px (the console uses 2 px on controls and 0 on tables and panels). No container shadows.

## Color

The palette is the token set of `console/src/styles.css`, which follows the reference site tokens of `site/src/app/globals.css`. The desktop application windows use the same tokens. Use the tokens, never literal colors in components.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--paper` | `#f4f5f0` | `#121614` | Page background |
| `--surface` | `#fbfbf8` | `#181d1a` | Raised regions, inputs |
| `--surface-2` | `#e8ebe4` | `#202722` | Table headers, quiet fills |
| `--ink` | `#141a17` | `#e4e8e2` | Body text |
| `--ink-2` | `#3c4842` | `#b7c1ba` | Secondary text |
| `--ink-3` | `#56625b` | `#98a59c` | Tertiary text, neutral state (stopped, unreachable) |
| `--rule` | `#c9cfc7` | `#2e3732` | Hairline rules |
| `--rule-strong` | `#8e998f` | `#5b6760` | Control borders |
| `--moss` | `#2c5a46` | `#93c6ad` | Primary action, links |
| `--ok` | `#1d6a46` | `#74c79f` | State: good |
| `--warn` | `#7a560f` | `#d8b46e` | State: degraded, warning |
| `--bad` | `#a12d4f` | `#f08ca8` | State: failure, refusal, stop |
| `--pending` | `#2b4a8c` | `#a3bcff` | State: pending, waiting for a person |
| `--focus` | `#1f4fc4` | `#8fb0ff` | Focus outline |

Charts add the three validated series tokens `--series-1` to `--series-3` and `--chart-grid` (console-style.md). The site adds its requirement-status tokens (`--st-verified`, `--st-partial`, `--st-failing`, `--st-track`) and `--ochre`.

- **Color carries state only**, and never alone: every state color comes with a text label and a shape. Square: good. Diamond: degraded or warning. Triangle: failure, refusal or stop. Ring: pending.
- **Honest status.** A state color is shown only for a state the product has just read. Stale or missing data is neutral (`--ink-3`) and says so; it is never green.
- **Light and dark follow the operating system** (`prefers-color-scheme`), with the console's explicit `data-theme` override. Every token is redefined for dark; check contrast in both.

## Type

- **One family per surface.** The console and the desktop windows use IBM Plex Sans (400, 600) for text and IBM Plex Mono (400, 500) for IDs, revisions, digests, reason codes and counts, bundled locally (FR-8.26). System fonts (`system-ui`, `ui-monospace`) are the fallback. The reference site is a printed-specification layout: Newsreader for long-form text with IBM Plex Mono, as `site/src/app/globals.css` states.
- **Five sizes**: 12, 13, 14, 16 and 20 px (`--fs-1` to `--fs-5`). Tables and monospaced text 13 px, body 14 px, the `h1` 20 px. No other sizes.
- Weight 600 for headings and emphasis; no italic for emphasis in UI text.

## Accessibility

WCAG 2.2 level AA on every surface (FR-8.32; desktop windows FR-20.15):

- contrast at least 4.5:1 for text and 3:1 for non-text UI parts and state shapes, in light and dark;
- a visible focus indicator on every focusable element: a 2 px outline in `--focus` with an offset, never removed;
- targets at least 24 by 24 CSS px;
- every action reachable by keyboard (FR-8.33), in a logical order that matches the reading order;
- icons only where they carry meaning, and then with a text label or an accessible name.

## Tray states (desktop application)

The tray icon and its accessible name state exactly one of the six states of FR-20.2. Each has a token, a shape and a word; the word is the accessible name, and the `not enforced` label stays beside it on a Standalone installation (FR-20.4).

| State | Token | Shape | Word |
|---|---|---|---|
| healthy | `--ok` | filled square | healthy |
| degraded | `--warn` | diamond | degraded |
| fail-closed | `--bad` | triangle | fail-closed |
| emergency stop | `--bad` | triangle with a bar | emergency stop |
| stopped | `--ink-3` | hollow square | stopped |
| unreachable | `--ink-3` | ring | unreachable |

`unreachable` is shown when no status has been read for 15 seconds; it is never shown as the last known state, and stale data is never green. The monochrome menu-bar template image carries the state by shape alone, so the shapes must differ in silhouette.

## Motion

- Motion only shows a state change (a row appearing, a state label changing), as an opacity fade of at most 150 ms.
- With `prefers-reduced-motion: reduce`, no motion at all (the console and site set `animation: none` and `transition: none`).
- No looping or decorative animation.

## Banned visual patterns

| Banned | Use instead |
|---|---|
| Purple or blue gradients, and any decorative gradient | A flat token color |
| Glassmorphism, backdrop blur | An opaque `--surface` region with a rule |
| Sparkle (✨) or magic-wand icons, "AI" glyphs | A text label stating what the feature does |
| Gratuitous glow, text shadows, drop shadows | A hairline rule or a 3 px inset bar in the state color (as the console's refused rows) |
| Oversized rounded cards; radius over 4 px on containers; card grids | Tables and ruled regions with radius 0 to 4 px |
| Hero blobs, decorative shapes, background patterns | Nothing; start with the content |
| Generic 3D, stock or decorative illustrations | Diagrams that show the real mechanism (the site's system map), or nothing |
| Centered-everything layouts | Left-aligned reading order |
| Decorative or looping animation, pulsing badges | A static state label; a 150 ms fade for a change |
| Skeleton shimmer | A text loading state ("Loading sessions") within 200 ms (FR-8.29) |
| Confetti or celebration effects | A plain confirmation sentence |
| Emoji | A word, or a state shape with its label |

## How this is checked

- `tools/uilint` (CI job `lint`, FR-20.51) checks the UI strings against the writing guide and the stylesheets (`*.css` under `console/src/`, `site/src/` and `desktop/`) for these rules: `css-gradient` (`linear-`, `radial-` and `conic-gradient(`, also in inline style strings), `css-backdrop-filter`, `css-text-shadow`, `css-box-shadow` (any shadow that is not `inset`), `css-filter` (`blur(` or `drop-shadow(`), `css-radius` (a `border-radius` over 4 px; percentages, which draw state shapes, are allowed) and `css-animation` (`infinite`). Exceptions go in `docs/design/ui-string-allowlist.txt` with a reason ([format](writing.md#allowlist)). Today no stylesheet needs one: the only shadows are inset bars and the only radii are 0, 2 px and 50 %.
- `console/e2e/a11y.spec.ts` runs axe-core with the WCAG 2.2 A and AA rule sets on every console view in light and dark schemes.
- `console/e2e/style.spec.ts` checks the computed styles of the console against the console visual rules.
- Each console view is inspected against [console-style.md](../console-style.md) before release (FR-8.35); desktop windows and site pages are reviewed against this page.
