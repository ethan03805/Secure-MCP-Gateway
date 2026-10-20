// G-01 Gateway control: enforcement state, health causes, active policy
// revision and session count, emergency stop and resume (FR-8.3), policy
// reload, journal verification and the first-run checklist (FR-8.31).
import { useState, type ReactNode } from "react";
import { ApiError, post } from "../api";
import { useResource } from "../data";
import { causeText, stateOf, useHealth } from "../health";
import { usePerm } from "../perm";
import { Link } from "../router";
import type { EventPage, Principals, ServerView, VerifyResult } from "../types";
import { DataTable, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, StateLabel, Time, toneOf, type Column } from "../ui";

export function VerifyPanel() {
  const perm = usePerm();
  const res = useResource<VerifyResult>(perm.can("GET /api/v1/audit/verify") ? "/api/v1/audit/verify" : null, { live: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      await post("/api/v1/audit/verify", {});
      res.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    } finally {
      setBusy(false);
    }
  };
  if (!perm.can("GET /api/v1/audit/verify")) return null;
  return (
    <Section
      title="Journal verification"
      actions={
        perm.can("POST /api/v1/audit/verify") && (
          // aria-disabled, not disabled: a disabled button drops keyboard
          // focus to the page body, the end of the view in G-01.
          <button type="button" onClick={() => void (busy || run())} aria-disabled={busy}>
            {busy ? "Verifying" : "Verify the journal now"}
          </button>
        )
      }
    >
      {error && <ErrorBlock error={error} />}
      <Loaded res={res} what="the last verification" route="/api/v1/audit/verify">
        {(v) =>
          v.status === "not_run" ? (
            <p className="empty">The journal has not been verified since smcpd started. Verify it now to check every segment signature, the hash chain and the anchor.</p>
          ) : (
            <KV
              rows={[
                ["Result", <StateLabel tone={toneOf(v.status)}>{v.status === "verified" ? "verified" : "failed"}</StateLabel>],
                ...(v.error ? ([["Failure", <Mono>{v.error}</Mono>]] as [string, ReactNode][]) : []),
                ["Segments", <Mono>{v.segments}</Mono>],
                ["Events", <Mono>{v.events}</Mono>],
                ["Open segment", v.open_segment ? <Mono>{v.open_segment}</Mono> : "none"],
                ["Anchor segment", <Mono>{v.anchor_segment}</Mono>],
                ["Findings", v.findings.length ? <ul className="plain">{v.findings.map((f) => <li key={f}>{f}</li>)}</ul> : "none"],
                ["Checked", <><Time value={v.checked_at} /> by <Mono>{v.checked_by}</Mono> in {v.duration_ms} ms</>],
              ]}
            />
          )
        }
      </Loaded>
    </Section>
  );
}

function ReloadPolicy() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<{ revision: string; digest: string; changed: boolean } | null>(null);
  const health = useHealth();
  const run = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await post("/admin/v1/policy/reload", {}));
      health?.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="action-row">
      <div>
        <strong>Reload policy</strong>
        <p className="small">Validates the policy file named in the configuration and activates it if its revision is new.</p>
      </div>
      <button type="button" onClick={() => void run()} disabled={busy}>
        {busy ? "Reloading" : "Reload policy"}
      </button>
      {result && (
        <p role="status" className="small">
          {result.changed ? "Activated" : "Unchanged:"} revision <Mono>{result.revision}</Mono>, digest <Mono>{result.digest.slice(0, 19)}</Mono>.
        </p>
      )}
      {error && <ErrorBlock error={error} />}
    </div>
  );
}

interface CheckItem {
  item: string;
  done: boolean | null; // null: cannot be determined in this build
  detail: ReactNode;
  to: string;
  action: string;
}

/** The FR-8.31 items, each marked from Gateway state; the detail of an open item names the step that completes it. */
function useChecklist(): CheckItem[] {
  const health = useHealth();
  const perm = usePerm();
  const ifCan = (route: string, path: string) => (perm.can(route) ? path : null);
  const principals = useResource<Principals>(ifCan("GET /api/v1/sessions/principals", "/api/v1/sessions/principals"));
  const servers = useResource<{ servers: ServerView[] }>(ifCan("GET /api/v1/servers", "/api/v1/servers"));
  const sessions = useResource<EventPage>(ifCan("GET /api/v1/audit/events", "/api/v1/audit/events?class=session&limit=1"));
  const approved = useResource<EventPage>(ifCan("GET /api/v1/audit/events", "/api/v1/audit/events?class=approval&outcome=approved&limit=1"));
  const denied = useResource<EventPage>(ifCan("GET /api/v1/audit/events", "/api/v1/audit/events?class=approval&outcome=denied&limit=1"));
  const backup = useResource<unknown>(ifCan("GET /api/v1/backup", "/api/v1/backup"));
  const h = health?.status === "ok" ? health.data : undefined;
  const approvers = principals.status === "ok" ? principals.data.session_approvers.length : null;
  const srv = servers.status === "ok" ? servers.data.servers : null;
  const packaged = srv ? srv.filter((s) => s.state === "running" && s.verified).length : null;
  const running = srv ? srv.filter((s) => s.state === "running").length : 0;
  const agent = sessions.status === "ok" ? sessions.data.events.length > 0 || (h?.sessions ?? 0) > 0 : null;
  const tested = approved.status === "ok" && denied.status === "ok" ? approved.data.events.length + denied.data.events.length > 0 : null;
  let backupDone: boolean | null = null;
  let backupDetail: ReactNode = "Backups are not available in this build.";
  if (backup.status === "ok") {
    const b = backup.data as Record<string, unknown> | unknown[];
    backupDone = Array.isArray(b) ? b.length > 0 : !!(b && (b["configured"] === true || (Array.isArray(b["backups"]) && (b["backups"] as unknown[]).length > 0)));
    backupDetail = backupDone ? "A backup is configured." : "No backup is configured yet. Take one with a passphrase in Data server and memory.";
  } else if (backup.status === "error" && !backup.error.unavailable) {
    backupDetail = `Backup status could not be read: ${backup.error.message}`;
  }
  const items: CheckItem[] = [
    {
      item: "Administrator created",
      done: true,
      detail: perm.role === "administrator" ? "You are signed in with the administrator account or operator token." : "The Gateway was bootstrapped with an administrator.",
      to: "/sessions",
      action: "Sessions and principals",
    },
    {
      item: "Session Approver created",
      done: approvers === null ? null : approvers > 0,
      detail:
        approvers === null
          ? "Unknown"
          : approvers > 0
            ? `${approvers} Session Approver account${approvers === 1 ? "" : "s"} configured.`
            : "No Session Approver account. Add one in Sessions and principals: an agent cannot sign in without it.",
      to: "/sessions",
      action: "Sessions and principals",
    },
    {
      item: "First server packaged and enabled",
      done: packaged === null ? null : packaged > 0,
      detail:
        packaged === null
          ? "Unknown"
          : packaged > 0
            ? `${packaged} server${packaged === 1 ? "" : "s"} enabled from a verified package.`
            : `${running} server${running === 1 ? "" : "s"} enabled, none from a verified package. Enable a package revision in Servers and library.`,
      to: "/servers",
      action: "Servers and library",
    },
    {
      item: "First policy revision published",
      done: h ? !!h.policy_revision : null,
      detail: h?.policy_revision ? <>Revision <Mono>{h.policy_revision}</Mono> is active.</> : "No policy revision is active, so every call is refused. Publish one in Policy studio.",
      to: "/policy",
      action: "Policy studio",
    },
    {
      item: "First agent connected",
      done: agent,
      detail: agent ? (
        "An agent session has been recorded in the journal."
      ) : (
        <>
          No agent session has been recorded yet. Connect an agent such as Claude Code with <Mono>smcpctl connect</Mono> and sign it in as a Session
          Approver (docs/quickstart.md).
        </>
      ),
      to: "/sessions",
      action: "Sessions and principals",
    },
    {
      item: "Approval tested",
      done: tested,
      detail: tested
        ? "An approval has been decided."
        : "No tool-call approval has been decided yet. Call a tool whose policy rule requires approval, then approve or deny it in Approvals.",
      to: "/approvals",
      action: "Approvals",
    },
    { item: "Backup configured", done: backupDone, detail: backupDetail, to: "/data-server", action: "Data server and memory" },
  ];
  return items;
}

function Checklist({ items }: { items: CheckItem[] }) {
  const columns: Column<CheckItem>[] = [
    { key: "item", label: "Item", render: (r) => r.item },
    {
      key: "state",
      label: "State",
      render: (r) =>
        r.done === null ? <StateLabel tone="neutral">unknown</StateLabel> : r.done ? <StateLabel tone="ok">done</StateLabel> : <StateLabel tone="pending">to do</StateLabel>,
      className: "nowrap",
    },
    { key: "detail", label: "From Gateway state", render: (r) => r.detail },
    { key: "to", label: "Where", render: (r) => <Link to={r.to}>{r.action}</Link>, className: "nowrap" },
  ];
  const left = items.filter((i) => i.done !== true).length;
  return (
    <Section title={left ? `First-run checklist: ${left} of ${items.length} open` : "First-run checklist: complete"}>
      <p className="small">The steps to a working installation, in order. Each is marked from Gateway state; the link opens the view where it is done.</p>
      <DataTable caption="First-run checklist" columns={columns} rows={items} rowKey={(r) => r.item} empty="" />
    </Section>
  );
}

interface MonitorCause {
  name: string;
  critical: boolean;
  detail: string;
  active: boolean;
  since?: string;
  cleared_at?: string;
  ack_required?: boolean;
  acked_by?: string;
}

/** One row of the merged causes table: a cause of the health report, the health monitor's record of it, or both. */
interface CauseRow {
  name: string;
  monitor?: MonitorCause;
}

/**
 * The causes that reduce enforcement, in one table (CA-12): the causes of
 * the health report (the state shown in the status bar) merged by name with
 * the health monitor's causes, which add cleared causes still latched for
 * acknowledgment (FR-7.13), the time each began and the acknowledgment.
 * Roles that cannot read the monitor see the report's causes only.
 */
function Causes({ causes }: { causes: string[] }) {
  const perm = usePerm();
  const canMonitor = perm.can("GET /api/v1/health/status");
  const res = useResource<{ state: string; causes: MonitorCause[]; checked_at: string }>(canMonitor ? "/api/v1/health/status" : null);
  const [error, setError] = useState<ApiError | null>(null);
  const ack = async (cause: string) => {
    setError(null);
    try {
      await post("/api/v1/health/ack", { cause });
      res.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    }
  };
  const table = (monitor: MonitorCause[] | null) => {
    const byName = new Map<string, CauseRow>(causes.map((c) => [c, { name: c }]));
    for (const m of monitor ?? []) byName.set(m.name, { name: m.name, monitor: m });
    const rows = [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
    const columns: Column<CauseRow>[] = [
      { key: "name", label: "Cause", sort: (c) => c.name, render: (c) => <Mono>{c.name}</Mono> },
      {
        key: "state",
        label: "State",
        sort: (c) => (c.monitor && !c.monitor.active ? 1 : 0),
        className: "nowrap",
        render: (c) =>
          !c.monitor || c.monitor.active ? (
            <StateLabel tone={c.monitor?.critical ? "bad" : "warn"}>{c.monitor?.critical ? "active, critical" : "active"}</StateLabel>
          ) : (
            <StateLabel tone="ok">cleared</StateLabel>
          ),
      },
      { key: "meaning", label: "Meaning", render: (c) => causeText[c.name] ?? c.monitor?.detail ?? "See docs/troubleshooting.md." },
    ];
    if (monitor) {
      columns.push(
        { key: "since", label: "Since", render: (c) => (c.monitor?.since ? <Time value={c.monitor.since} /> : "none") },
        {
          key: "ack",
          label: "Acknowledgment",
          render: (c) =>
            c.monitor?.ack_required ? (
              perm.can("POST /api/v1/health/ack") ? (
                <button type="button" className="link" onClick={() => void ack(c.name)}>
                  Acknowledge {c.name}
                </button>
              ) : (
                "required"
              )
            ) : c.monitor?.acked_by ? (
              <Mono>{c.monitor.acked_by}</Mono>
            ) : (
              <span className="muted">not needed</span>
            ),
        },
      );
    }
    return (
      <DataTable
        caption="Health causes"
        rows={rows}
        rowKey={(c) => c.name}
        empty="No cause reduces enforcement. A cause appears here when a monitored condition degrades the Gateway or holds it fail-closed."
        columns={columns}
      />
    );
  };
  return (
    <Section title="Causes">
      <p className="small">
        Why the state is not healthy. A cleared integrity cause stays listed, and keeps the Gateway fail-closed, until an Administrator acknowledges it.
      </p>
      {error && <ErrorBlock error={error} />}
      {canMonitor ? (
        <Loaded res={res} what="the health monitor" route="/api/v1/health/status">
          {(h) => table(h.causes)}
        </Loaded>
      ) : (
        table(null)
      )}
    </Section>
  );
}

/** Why the installation runs the Standalone profile, with the next step (CA-13). */
function ProfileReasons({ reasons }: { reasons: string[] }) {
  if (reasons.length === 1 && reasons[0] === "standalone profile configured") {
    return (
      <>
        <h3 className="sub">Why this installation is Standalone</h3>
        <p className="small">
          The configuration selects it: <Mono>[profile] mode = "standalone"</Mono> in smcp.toml. To contain servers, install the Enforced profile on a Linux
          host by following docs/enforced-profile.md.
        </p>
      </>
    );
  }
  return (
    <>
      <h3 className="sub">Why this installation is Standalone</h3>
      <p className="small">
        The Enforced profile needs Linux on amd64 or arm64 with rootless Podman, nftables, cgroup v2, systemd and a confining launcher. Not met on this
        host:
      </p>
      <ul className="plain">
        {reasons.map((r) => (
          <li key={r}>
            <Mono>{r}</Mono>
          </li>
        ))}
      </ul>
      <p className="small">
        To contain servers, install the Enforced profile on a Linux host that meets these requirements: docs/enforced-profile.md lists each one and how to
        check it. On macOS the Standalone profile is the only one.
      </p>
    </>
  );
}

export function Control() {
  const health = useHealth();
  const perm = usePerm();
  const checklist = useChecklist();
  // While setup steps are open the checklist comes first: it is what a new
  // installation needs next. Once complete it moves to the end.
  const open = checklist.some((i) => i.done !== true);
  return (
    <>
      <PageHeader code="G-01" title="Gateway control">
        <p>
          The Gateway stands between your agents (AI clients such as Claude Code) and the MCP servers it launches: it decides each tool call against the
          active policy, holds calls that need a person's approval, and records every step in a signed journal. This view shows whether that is in force, why,
          and the controls that change it. Emergency stop is in the bar at the top of every view.
        </p>
      </PageHeader>
      <Help>
        <p>
          <strong>Emergency stop</strong> refuses every tool call until someone resumes. Use it when an agent or server behaves in a way policy did not
          anticipate. <strong>Reload policy</strong> activates the policy file after you edit it. Health states: healthy (all controls active), degraded (the
          Gateway runs with a reduced guarantee, listed under causes) and fail-closed (every call is refused).
        </p>
        <p>
          Terms: an <strong>agent</strong> is the AI client that calls tools through the Gateway (the SRS calls its runtime the harness); when it connects, a person signs it in on the Gateway's sign-in page
          with a <strong>Session Approver</strong> account. A <strong>server</strong> is a backend MCP server the Gateway launches. An <strong>approval</strong> is a
          held tool call that an <strong>Approver</strong> or the Administrator approves or denies in Approvals. The <strong>profile</strong> is Standalone (not
          enforced: servers run without a sandbox) or Enforced (Linux with rootless Podman: each server is contained).
        </p>
      </Help>
      {open && <Checklist items={checklist} />}
      {health && (
        <Section title="Enforcement">
          <Loaded res={health} what="health" route="/admin/v1/health">
            {(h) => (
              <>
                <KV
                  rows={[
                    ["State", <StateLabel tone={stateOf(h).tone}>{stateOf(h).word}</StateLabel>],
                    ["Profile", <>{h.profile} <span className="muted">({h.release_label})</span></>],
                    ["Policy revision", h.policy_revision ? <Mono>{h.policy_revision}</Mono> : <span className="muted">none</span>],
                    ["Active sessions", <Mono>{h.sessions}</Mono>],
                    ["Launcher", <Mono>{h.launcher}</Mono>],
                    ["Servers", h.servers.length ? h.servers.map((s) => <Mono key={s}>{s} </Mono>) : "none"],
                    ["Version", <Mono>{h.version}</Mono>],
                  ]}
                />
                {h.profile === "standalone" && (
                  <div className="notice notice-warn" data-testid="not-enforced">
                    <p>
                      <strong>Not enforced.</strong> The Standalone profile decides, filters and records the tool calls that go through the Gateway, but it does
                      not contain the servers. Each server runs as your user without a sandbox and can read and write your files and reach the network
                      directly; the agent also runs as your user and its own tools (shell, file editing) never pass through the Gateway. Servers rated high
                      risk are refused. Health reports degraded with the cause unconfined; while that is the only cause the console and the desktop app show
                      the state as running, not enforced. Containment needs the Enforced profile on Linux. Details:
                      docs/security-limitations.md.
                    </p>
                  </div>
                )}
                {h.profile_reasons && h.profile_reasons.length > 0 && <ProfileReasons reasons={h.profile_reasons} />}
              </>
            )}
          </Loaded>
        </Section>
      )}
      <Causes causes={health?.status === "ok" ? health.data.causes : []} />
      {perm.can("POST /admin/v1/policy/reload") && (
        <Section title="Actions">
          <ReloadPolicy />
        </Section>
      )}
      <VerifyPanel />
      {!open && <Checklist items={checklist} />}
    </>
  );
}
