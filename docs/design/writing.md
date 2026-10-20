# Writing style guide

This guide is normative for every string a person reads in the Gateway's user interfaces: the management console, the desktop application (planned for v1.3.0) and the reference site (SRS FR-20.49, planned v1.3.0). It extends the message style of SRS Appendix B, whose reason-code messages are the model for every other message, and the text rule of the [console visual rules](../console-style.md). The desktop application and the console show the same reason-code messages from one shared catalogue, `docs/design/messages.json` (FR-20.48), whose text follows this guide. Layout, color and motion are in the [visual design guide](visual.md).

`tools/uilint` checks the rules a program can check (FR-20.51); see [How this is checked](#how-this-is-checked).

## Scope

A UI string is text the product shows to a person:

- console: `console/src/**/*.ts` and `*.tsx` (string literals, template literal text, JSX text and user-facing attributes such as `title`, `aria-label`, `placeholder` and component props) and `console/index.html`;
- reference site: `site/src/**/*.ts` and `*.tsx` and any HTML page in `site/public/`;
- desktop application (macOS arm64), when `desktop/` exists: `*.ts`, `*.tsx`, `*.js`, `*.jsx`, `*.mjs`, `*.html` and Rust string literals (`*.rs`: window titles, tray labels, notification text), without `target/`, `node_modules/`, `dist/` and `gen/`;
- the shared message catalogue `docs/design/messages.json` (FR-20.48), when it exists: every JSON string value (not the keys) is UI text: reason-code messages, desktop errors and tray states.

Tests (`*.test.*`, `*.spec.*`, `e2e/`) are not UI strings. Neither is the long-form documentation the site renders from `docs/`, the README, the SRS and the architecture documents: that is documentation, held to the same principles by review but not by the lint, because it quotes banned words when it defines them (as this page does) and uses SRS terms such as "harness" verbatim.

## Principles

1. **Use concrete verbs.** Say what happens: "Stop all tool calls", "Publish revision", "Restart the server". A button is named by its action and object: "Approve call", "Deny call", "Sign in", never "OK", "Submit" or "Continue" when a specific verb exists.
2. **Use the user's terms.** Name things as the [terminology table](#terminology) does, the same way on every screen. Explain an SRS term the first time a screen needs it.
3. **State security exactly.** Never claim more protection than exists. On the Standalone profile, the label `not enforced` stays visible wherever the state is shown; do not shorten it, hide it or soften it ("basic protection"). A notification is not an approval: notification text says a call is waiting and where to decide it, and no notification offers approve, deny or reply (SR-2.6-2). Stale data is not current data: when the tray or a view has not heard from the Gateway, it says `unreachable`, never the last known state.
4. **One plain sentence per idea.** Short sentences, active voice, present tense. Put the condition first when it matters: "While the emergency stop is in effect, every tool call is refused."
5. **Sentence case for labels, headings, buttons and messages inside windows.** "Set up a client", "Policy revisions", "Emergency stop". Capitalize proper names (Gateway, Evidence Journal, Claude Code) and role names (Approver, Administrator). Native menu items and window titles follow the platform convention, which is title case on macOS: the tray menu items are fixed by SRS FR-20.2 as Open Console, Approvals, Start, Stop, Restart, Set Up a Client, Check for Updates, Settings and Quit.
6. **Exact numbers and IDs.** Show the count, the revision, the reason code and the correlation ID as they are, in the monospaced face: "3 calls waiting", `rev-2026-10-18.2`, `FAIL_CLOSED`. Do not round counts that drive a decision ("many calls", "a few servers").
7. **No exclamation marks.** Calm text for every outcome, including success: "Policy revision published."
8. **Errors say what happened, why, and what to do.** Follow the Appendix B pattern: the outcome first, then the cause in the user's terms, then the next action, and show the reason code (and the correlation ID when there is one) with the message (FR-8.29; desktop errors FR-20.47, from the catalogue of FR-20.48). The Gateway's `data.message` is the text; do not replace it with a generic one.
9. **Empty states name the next action.** "No call is waiting for approval. A call appears here when a policy rule with approval required is used." (FR-8.29; desktop FR-20.46)
10. **Help text says what a thing does and when to use it.** One or two sentences: what the control changes, and the case it is for (FR-8.25; desktop FR-20.46). Do not restate the label.
11. **Empty values say "none".** A table cell or field with no value shows the word `none`, not a dash.

## Terminology

| Use | Avoid | Note |
|---|---|---|
| Gateway | gateway (for this product), proxy, firewall | Capital G when it names this product. "the Gateway operator" in agent-facing messages, as in Appendix B. |
| agent | harness (in UI text), bot, assistant | The AI client that calls tools through the Gateway (Claude Code, Codex CLI). The SRS calls its runtime the harness; UI text says "agent" and, where the SRS term matters (sign-in approval, adapters), explains it once: "the agent (harness)". |
| MCP server, server | backend (in UI text), plugin, integration | "MCP server" on first use, "server" after. A server provides tools. |
| tool | function, action, skill | A named operation a server offers. |
| tool call | request (alone), invocation, execution | One call of one tool. "call" alone after the first use. |
| approval | confirmation, consent, permission | A person's decision on a held tool call. A notification is not an approval. |
| approve, deny | accept, reject, allow, block (for approvals) | The two decisions. "Approve call", "Deny call". |
| Administrator, Operator, Policy Author, Approver, Session Approver, Auditor, Researcher | admin, approver (lower case), reviewer, superuser | The roles of SRS Appendix C, capitalized. One person may hold several role accounts. |
| policy | rules (alone), config, settings (for policy) | The signed document that decides which tool calls are allowed. |
| policy revision | version, policy version | One published, signed policy document, identified by its revision ID. |
| session | connection, login | An agent's authenticated period of use, bound to a policy template. |
| Evidence Journal | audit log, logs (for the journal) | The append-only, signed record of decisions and outcomes. "journal" after first use; "audit record" for one entry. |
| emergency stop | kill switch, panic button, halt | Stops all tool calls until resumed. Lower case except at the start of a sentence. |
| Standalone profile, Enforced profile | basic mode, secure mode, lite, pro | The two installation profiles (SRS 2.5). |
| `not enforced` | unprotected, insecure, limited mode | The exact label shown beside the state on a Standalone installation. Never omitted where the state is shown. |
| fail-closed | locked, safe mode, down | The Gateway refuses tool calls because a safety check failed. |
| console | dashboard, portal, admin panel | The management console served by the Gateway. |
| desktop app, desktop application | tray app, client app, widget | The Tauri application of FR-20 (planned v1.3.0). |
| tray, tray icon, tray menu | menu-bar widget, status bar thing | The SRS term. macOS shows it in the menu bar; help text may say "the tray icon in the menu bar". |
| sign in (verb), sign-in (noun) | log in, login, logon | "Sign in again." "The sign-in page." Same pattern for sign out and sign-out. |
| set up (verb), setup (noun and adjective) | setup (as a verb), set-up | "Set up a client." "First-run setup." |
| reason code | error type, status code | The `UPPER_SNAKE` code of Appendix B, shown with every error. |
| correlation ID | request ID, trace ID | The ID an operator uses to find the audit record. |

## Banned words and patterns

The lint fails on these in UI strings (case-insensitive, whole words; "just" does not match "justify" or "just-in-time"). A justified exception goes in the allowlist with a reason.

| Banned | Use instead |
|---|---|
| unlock, unlocks | the concrete verb: enable, allow, open, give access to |
| seamless, seamlessly | say what works without a step, or nothing |
| effortless, effortlessly | the number of steps, or nothing |
| supercharge | the measurable change: "checks 2,000 calls a second" |
| elevate, elevates, elevating | improve, raise, or the concrete change. ("elevated" stays: it is the name of an anomaly band.) |
| empower, empowers | let, allow |
| leverage | use |
| delve | read, look at, examine |
| robust | the specific property: tested against X, retries N times, fails closed. Allowlisted where it names robust statistics. |
| cutting-edge, cutting edge | current, or the version |
| game-changer, game changer, game-changing | the change itself |
| revolutionary, revolutionize | the change itself |
| next-generation, next-gen | the version or the property |
| world-class, best-in-class, state-of-the-art | the measured property, or nothing |
| harness the power, unleash | use, run, start |
| harness, harnesses | agent, agents ([terminology](#terminology)). Where the SRS term matters, define it once with an allowlist entry; identifiers such as `harness_version` are not words and do not match. |
| streamline, streamlined | the step that was removed: "in one step", "without restarting" |
| blazing fast | the measured time |
| in today's | nothing: start with the point |
| journey | the task: setup, installation, review |
| Let's get started, Let's go | the first action as a button: "Set up the Gateway" |
| AI-powered, powered by AI, magic, magical, magically, sparkle framing | say what the feature does; the Gateway's checks are deterministic rules and statistics |
| Don't worry, No worries, Rest assured | state the fact that would reassure: "The call was not run." |
| simply, just, easily, basically, actually | delete the word |
| Oops, Whoops, Uh-oh, Oh no, Something went wrong | the Appendix B pattern: what happened, why, what to do, reason code |
| "!" ending a sentence | a period |
| emoji, including ✨ and 🎉 | a word, or a state shape with its label (visual guide) |
| em dash (U+2014) | a period, comma, colon or parentheses. An empty value is `none`. |

The lint also checks the stylesheets for the banned visual patterns of the [visual design guide](visual.md#banned-visual-patterns).

## Examples

**Approval held.** Before: "Heads up! Your AI assistant needs a quick OK ✨". After: "This call needs approval. Open the Approvals view to approve it, then run the same request again." (`APPROVAL_REQUIRED`)

**Approval notification (desktop).** Before: "New request! Tap to approve." After: "3 tool calls are waiting for approval. Open the console to decide." No approve or deny button; the count is the only variable (FR-20.7, SR-2.6-2).

**Fail-closed.** Before: "Oops, something went wrong. Don't worry, we're on it." After: "The Gateway is not accepting tool calls right now because a safety check failed. The operator can see the cause with `smcpctl health`." Reason code `FAIL_CLOSED`.

**Unreachable tray state.** Before: tray stays green with "Healthy" after the Gateway stops answering. After: tray shows the ring shape and "unreachable", and the menu says "No status from the Gateway for 15 seconds. Open the console or restart the service." (FR-20.4)

**Standalone label.** Before: "Protected" on a macOS install. After: "healthy, not enforced" with the `not enforced` label kept beside the state.

**Setup failure.** Before: "Setup failed! Please try again." After: "Setup stopped: port 8443 is already in use by another program. Quit that program or choose another port, then run setup again." The setup window also states before installation that the Standalone profile is labelled `not enforced`.

**Button.** Before: "OK". After: "Approve call".

## Allowlist

`docs/design/ui-string-allowlist.txt` lists justified exceptions, one per line:

```text
path  rule  matched text  # reason
```

- `path` is relative to the repository root;
- `rule` is the rule name the lint printed: `banned-word`, `exclamation`, `emoji`, `em-dash`, or one of the CSS rules of the visual guide;
- the matched text is what the lint printed after the rule, compared ignoring case and runs of white space;
- the reason after ` # ` is required.

An entry covers every finding of that rule and text in that file. An entry that no longer matches anything fails the lint, so the list cannot rot: remove the entry with the string it excused. Prefer fixing the string; allowlist only text fixed by the SRS, a technical term in its technical sense, or a quoted external name.

## How this is checked

- `go run ./tools/uilint` runs in the CI job `lint` on every pull request and push, and `go test ./tools/uilint/` checks the repository at HEAD (FR-20.51). It prints `path:line: rule: matched text` and exits 1 on a finding or a stale allowlist entry. `go run ./tools/uilint -strings` prints every extracted string, to review what the lint sees.
- The rest of this guide (concrete verbs, terminology, the error pattern, empty states, help text) is checked by review and by the inspection of each view against the [console visual rules](../console-style.md) (FR-8.35).
