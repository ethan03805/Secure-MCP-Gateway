// G-11 Sessions and principals: active harness sessions with inspect and
// terminate, configured principals, OAuth clients and Session Approvers.
import { useState, type ReactNode } from "react";
import { ApiError, post } from "../api";
import { useNow, useResource } from "../data";
import { Link, match } from "../router";
import type { Principals, SessionView } from "../types";
import { Crumbs, DataTable, Dialog, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, ShortId, StateLabel, Time, toneOf, type Column } from "../ui";

function SessionList() {
  const res = useResource<{ sessions: SessionView[] }>("/api/v1/sessions");
  const now = useNow(5000);
  const columns: Column<SessionView>[] = [
    { key: "id", label: "Session", sort: (s) => s.id, render: (s) => <Link to={`/sessions/${s.id}`}><ShortId id={s.id} /></Link> },
    { key: "principal", label: "Principal", sort: (s) => s.principal_id, render: (s) => <Mono>{s.principal_id}</Mono> },
    { key: "template", label: "Template", sort: (s) => s.template, render: (s) => <Mono>{s.template}</Mono> },
    { key: "approved", label: "Approved by", sort: (s) => s.approved_by ?? "", render: (s) => s.approved_by || <span className="muted">session API</span> },
    { key: "created", label: "Created", sort: (s) => s.created_at, render: (s) => <Time value={s.created_at} now={now} /> },
    { key: "idle", label: "Idle deadline", sort: (s) => s.idle_deadline ?? "", render: (s) => <Time value={s.idle_deadline} now={now} /> },
    { key: "rev", label: "Policy", sort: (s) => s.policy_revision ?? "", render: (s) => <Mono>{s.policy_revision}</Mono> },
  ];
  return (
    <Section title="Active sessions">
      <Loaded res={res} what="sessions" route="/api/v1/sessions">
        {(d) => (
          <DataTable
            caption="Active sessions"
            columns={columns}
            rows={d.sessions}
            rowKey={(s) => s.id}
            initialSort="created"
            initialDir="desc"
            empty="No harness is connected. A session appears here when a harness signs in through OAuth or the session API."
          />
        )}
      </Loaded>
    </Section>
  );
}

function PrincipalTables() {
  const res = useResource<Principals>("/api/v1/sessions/principals");
  return (
    <Loaded res={res} what="principals" route="/api/v1/sessions/principals">
      {(d) => (
        <>
          <Section title="Principals">
            <DataTable
              caption="Principals"
              rows={d.principals}
              rowKey={(p) => p.id}
              initialSort="id"
              empty="No principal is configured. Add a [[principal]] table to smcp.toml."
              columns={[
                { key: "id", label: "Principal", sort: (p) => p.id, render: (p) => <Mono>{p.id}</Mono> },
                { key: "name", label: "Display name", sort: (p) => p.display_name ?? "", render: (p) => p.display_name || <span className="muted">none</span> },
                { key: "fw", label: "Framework", sort: (p) => p.framework, render: (p) => <Mono>{p.framework}</Mono> },
                { key: "profile", label: "Framework profile", sort: (p) => p.profile, render: (p) => <Mono>{p.profile}</Mono> },
                { key: "enabled", label: "Enabled", sort: (p) => String(p.enabled), render: (p) => <StateLabel tone={p.enabled ? "ok" : "bad"}>{p.enabled ? "enabled" : "disabled"}</StateLabel> },
                { key: "active", label: "Active sessions", sort: (p) => p.active_sessions, render: (p) => <Mono>{p.active_sessions}</Mono>, className: "num" },
              ]}
            />
          </Section>
          <Section title="OAuth clients">
            <DataTable
              caption="OAuth clients"
              rows={d.clients}
              rowKey={(c) => c.client_id}
              initialSort="principal"
              empty="No OAuth client is registered."
              columns={[
                { key: "id", label: "Client ID", sort: (c) => c.client_id, render: (c) => <Mono>{c.client_id}</Mono> },
                { key: "principal", label: "Principal", sort: (c) => c.principal, render: (c) => <Mono>{c.principal}</Mono> },
                { key: "type", label: "Type", sort: (c) => String(c.confidential), render: (c) => (c.confidential ? "confidential" : "public") },
                { key: "redirects", label: "Redirect URIs", render: (c) => <Mono>{c.redirect_uris.join(" ")}</Mono> },
              ]}
            />
          </Section>
          <Section title="Session Approvers">
            <DataTable
              caption="Session Approver accounts"
              rows={d.session_approvers}
              rowKey={(a) => a.username}
              initialSort="user"
              empty="No Session Approver account exists, so no harness can sign in through OAuth. Create one with smcpctl hash-password and an [[approver]] table."
              columns={[{ key: "user", label: "Username", sort: (a) => a.username, render: (a) => <Mono>{a.username}</Mono> }]}
            />
          </Section>
        </>
      )}
    </Loaded>
  );
}

function SessionDetail({ id }: { id: string }) {
  const res = useResource<SessionView>(`/api/v1/sessions/${encodeURIComponent(id)}`);
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const terminate = async () => {
    setBusy(true);
    setError(null);
    try {
      await post(`/api/v1/sessions/${encodeURIComponent(id)}/terminate`, { reason: reason.trim() });
      setOpen(false);
      res.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Crumbs items={[["Sessions and principals", "/sessions"], [`Session ${id.slice(0, 8)}`, null]]} />
      <PageHeader
        code="G-11"
        title="Session"
        actions={
          res.status === "ok" && res.data.state === "active" ? (
            <button type="button" className="btn-danger" onClick={() => setOpen(true)}>
              Terminate session
            </button>
          ) : undefined
        }
      >
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      <Loaded res={res} what="the session" route="/api/v1/sessions/{id}">
        {(s) => (
          <Section title="Binding" actions={<Link to={`/audit?session_id=${encodeURIComponent(s.id)}`}>Journal events of this session</Link>}>
            <KV
              rows={[
                ["State", <StateLabel tone={toneOf(s.state)}>{s.state}</StateLabel>],
                ...(s.end_reason ? ([["End reason", <Mono>{s.end_reason}</Mono>]] as [string, ReactNode][]) : []),
                ["Principal", <Mono>{s.principal_id}</Mono>],
                ["Framework", <Mono>{s.framework}</Mono>],
                ["Framework profile", <Mono>{s.profile}</Mono>],
                ["Client", <Mono>{s.client_id}</Mono>],
                ["Template", <Mono>{s.template}</Mono>],
                ["Policy revision", <Mono>{s.policy_revision}</Mono>],
                ["Purpose", s.purpose || <span className="muted">none</span>],
                ["Project", s.project || <span className="muted">none</span>],
                ["End user", s.end_user || <span className="muted">none</span>],
                ["Approved by", s.approved_by || <span className="muted">session API</span>],
                ["Harness version", s.harness_version || <span className="muted">not reported</span>],
                ["Listener", <Mono>{s.listener}</Mono>],
                ["Created", <Time value={s.created_at} />],
                ["Idle deadline", <Time value={s.idle_deadline} />],
                ["Maximum lifetime", <Time value={s.max_deadline} />],
                ...(s.ended_at ? ([["Ended", <Time value={s.ended_at} />]] as [string, ReactNode][]) : []),
              ]}
            />
          </Section>
        )}
      </Loaded>
      <Dialog open={open} onClose={() => setOpen(false)} title="Terminate this session">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void terminate();
          }}
        >
          <p>The harness loses access at once: its calls in flight are cancelled and its tokens stop working. It has to sign in again to continue.</p>
          <label className="field">
            <span>Reason (recorded in the journal)</span>
            <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} autoFocus />
          </label>
          {error && <ErrorBlock error={error} />}
          <div className="dialog-actions">
            <button type="button" onClick={() => setOpen(false)}>
              Cancel
            </button>
            <button type="submit" className="btn-danger" disabled={busy}>
              Terminate session
            </button>
          </div>
        </form>
      </Dialog>
    </>
  );
}

export function Sessions({ path }: { path: string }) {
  const m = match("/sessions/:id", path);
  if (m?.id) return <SessionDetail id={m.id} />;
  return (
    <>
      <PageHeader code="G-11" title="Sessions and principals">
        <p>Harness sessions open now, and the framework instances, OAuth clients and Session Approvers configured in smcp.toml.</p>
      </PageHeader>
      <Help>
        <p>
          A session binds one framework instance (principal) to one Session Allow template for a bounded time. Terminating a session cancels its calls and
          revokes its tokens; the harness must sign in again. Principals, clients and Session Approvers are edited in smcp.toml and take effect after a
          restart.
        </p>
      </Help>
      <SessionList />
      <PrincipalTables />
    </>
  );
}
