// G-14 Audit investigation: the evidence journal browser with filters,
// paging, export and verification status, and per-event drill-down to the
// other phases of the same call and to the graph mirror when installed.
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ApiError, download } from "../api";
import { useResource } from "../data";
import { Link, match, navigate, useLocation } from "../router";
import type { AuditEvent, EventPage } from "../types";
import { Crumbs, DataTable, ErrorBlock, Help, JsonBlock, KV, Loaded, Mono, PageHeader, Section, ShortId, StateLabel, Time, toneOf, type Column } from "../ui";
import { VerifyPanel } from "./Control";

const filterKeys = ["class", "outcome", "reason_code", "origin", "session_id", "correlation_id", "principal_id", "decision_id", "q", "since", "until"] as const;
const primaryFilters: readonly (typeof filterKeys)[number][] = ["class", "outcome", "reason_code", "session_id", "q"];
const filterLabels: Record<(typeof filterKeys)[number], string> = {
  class: "Class",
  outcome: "Outcome",
  reason_code: "Reason code",
  origin: "Origin element",
  session_id: "Session ID",
  correlation_id: "Correlation ID",
  principal_id: "Principal",
  decision_id: "Decision ID",
  q: "Text",
  since: "From (RFC 3339)",
  until: "Until (RFC 3339)",
};

function eventColumns(): Column<AuditEvent>[] {
  return [
    { key: "time", label: "Time (UTC)", sort: (e) => e.time, render: (e) => <Link to={`/audit/events/${e.event_id}`}><Mono>{e.time.slice(0, 19).replace("T", " ")}</Mono></Link> },
    { key: "class", label: "Class", sort: (e) => e.class, render: (e) => <Mono>{e.class}</Mono> },
    { key: "phase", label: "Phase", sort: (e) => e.phase ?? "", render: (e) => (e.phase ? <Mono>{e.phase}</Mono> : <span className="muted">none</span>) },
    { key: "outcome", label: "Outcome", sort: (e) => e.outcome ?? "", render: (e) => (e.outcome ? <StateLabel tone={toneOf(e.outcome)}>{e.outcome}</StateLabel> : <span className="muted">none</span>) },
    { key: "reason", label: "Reason code", sort: (e) => e.reason_code ?? "", render: (e) => <Mono>{e.reason_code}</Mono> },
    { key: "origin", label: "Origin", sort: (e) => e.origin, render: (e) => <Mono>{e.origin}</Mono> },
    { key: "session", label: "Session", sort: (e) => e.session_id ?? "", render: (e) => (e.session_id ? <ShortId id={e.session_id} /> : <span className="muted">none</span>) },
    { key: "corr", label: "Call", sort: (e) => e.correlation_id ?? "", render: (e) => (e.correlation_id ? <ShortId id={e.correlation_id} /> : <span className="muted">none</span>) },
  ];
}

function query(params: URLSearchParams, extra: Record<string, string>): string {
  const q = new URLSearchParams();
  for (const k of filterKeys) {
    const v = params.get(k);
    if (v) q.set(k, v);
  }
  for (const [k, v] of Object.entries(extra)) if (v) q.set(k, v);
  return q.toString();
}

function Journal() {
  const { query: params } = useLocation();
  const [form, setForm] = useState<Record<string, string>>(() => Object.fromEntries(filterKeys.map((k) => [k, params.get(k) ?? ""])));
  const [pages, setPages] = useState<string[]>([""]);
  const base = query(params, {});
  useEffect(() => {
    setForm(Object.fromEntries(filterKeys.map((k) => [k, params.get(k) ?? ""])));
    setPages([""]);
  }, [base]);
  const before = pages[pages.length - 1] ?? "";
  const res = useResource<EventPage>(`/api/v1/audit/events?${query(params, { limit: "100", before })}`, { live: pages.length === 1 });
  const [exportError, setExportError] = useState<ApiError | null>(null);
  const apply = (e: FormEvent) => {
    e.preventDefault();
    const q = new URLSearchParams();
    for (const k of filterKeys) if (form[k]?.trim()) q.set(k, form[k]!.trim());
    navigate(`/audit${q.toString() ? `?${q}` : ""}`);
  };
  const exp = async (format: "csv" | "jsonl") => {
    setExportError(null);
    try {
      await download(`/api/v1/audit/export?${query(params, { format })}`, `journal.${format}`);
    } catch (e) {
      setExportError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    }
  };
  const active = filterKeys.filter((k) => params.get(k));
  const field = (k: (typeof filterKeys)[number]) => (
    <label key={k} className="field">
      <span>{filterLabels[k]}</span>
      <input name={k} value={form[k] ?? ""} onChange={(e) => setForm({ ...form, [k]: e.target.value })} spellCheck={false} autoComplete="off" />
    </label>
  );
  return (
    <>
      <Section title="Filter">
        <form className="filters" onSubmit={apply} aria-label="Journal filter">
          {primaryFilters.map(field)}
          <details className="more-filters" open={filterKeys.some((k) => !primaryFilters.includes(k) && params.get(k))}>
            <summary>More filters</summary>
            <div className="filters">{filterKeys.filter((k) => !primaryFilters.includes(k)).map(field)}</div>
          </details>
          <div className="filter-actions">
            <button type="submit" className="btn-primary">
              Apply filter
            </button>
            {active.length > 0 && (
              <button type="button" onClick={() => navigate("/audit")}>
                Clear filter
              </button>
            )}
          </div>
        </form>
      </Section>
      <Section
        title={active.length ? `Events matching ${active.map((k) => `${filterLabels[k].toLowerCase()} ${params.get(k)}`).join(", ")}` : "Events, newest first"}
        actions={
          <>
            <button type="button" onClick={() => void exp("csv")}>
              Export CSV
            </button>
            <button type="button" onClick={() => void exp("jsonl")}>
              Export JSON Lines
            </button>
          </>
        }
      >
        {exportError && <ErrorBlock error={exportError} what="the export" />}
        <Loaded res={res} what="journal events" route="/api/v1/audit/events">
          {(p) => (
            <>
              <p className="small muted">
                {p.journal_events} events in the journal. Page {pages.length}, {p.events.length} shown.
              </p>
              <DataTable
                caption="Journal events"
                columns={eventColumns()}
                rows={p.events}
                rowKey={(e) => e.event_id}
                rowClass={(e) => (e.outcome === "deny" || e.phase === "denied" ? "row-bad" : undefined)}
                empty={active.length ? "No event matches this filter. Clear the filter or widen the time range." : "The journal holds no events yet."}
              />
              <div className="pager">
                {pages.length > 1 && (
                  <button type="button" onClick={() => setPages(pages.slice(0, -1))}>
                    Newer events
                  </button>
                )}
                {p.next_before && (
                  <button type="button" onClick={() => setPages([...pages, p.next_before])}>
                    Older events
                  </button>
                )}
              </div>
            </>
          )}
        </Loaded>
      </Section>
    </>
  );
}

function EventDetail({ id }: { id: string }) {
  const res = useResource<{ event: AuditEvent; position: number; related: AuditEvent[] }>(`/api/v1/audit/events/${encodeURIComponent(id)}`, { live: false });
  const graph = useResource<unknown>(`/api/v1/graph/events/${encodeURIComponent(id)}`, { live: false });
  const link = (k: string, v?: string): ReactNode => (v ? <Link to={`/audit?${k}=${encodeURIComponent(v)}`}><Mono>{v}</Mono></Link> : <span className="muted">none</span>);
  return (
    <>
      <Crumbs items={[["Audit investigation", "/audit"], [`Event ${id.slice(0, 8)}`, null]]} />
      <PageHeader code="G-14" title="Evidence event">
        <p>
          <Mono>{id}</Mono>
        </p>
      </PageHeader>
      <Loaded res={res} what="the event" route="/api/v1/audit/events/{id}">
        {({ event: e, position, related }) => (
          <>
            <Section title="Event">
              <KV
                rows={[
                  ["Time", <Time value={e.time} />],
                  ["Position in journal", <Mono>{position}</Mono>],
                  ["Class", <Mono>{e.class}</Mono>],
                  ["Phase", e.phase ? <Mono>{e.phase}</Mono> : <span className="muted">none</span>],
                  ["Outcome", e.outcome ? <StateLabel tone={toneOf(e.outcome)}>{e.outcome}</StateLabel> : <span className="muted">none</span>],
                  ["Reason code", e.reason_code ? <Mono>{e.reason_code}</Mono> : <span className="muted">none</span>],
                  ["Origin element", <Mono>{e.origin}</Mono>],
                  ["Policy status", <Mono>{e.policy_status}</Mono>],
                  ["Decision", link("decision_id", e.decision_id)],
                  ["Call", link("correlation_id", e.correlation_id)],
                  ["Session", e.session_id ? <Link to={`/sessions/${e.session_id}`}><Mono>{e.session_id}</Mono></Link> : <span className="muted">none</span>],
                  ["Principal", link("principal_id", e.principal_id)],
                  ["Policy revision", e.policy_revision ? <Mono>{e.policy_revision}</Mono> : <span className="muted">none</span>],
                  ["Server revision", e.server_revision ? <Mono>{e.server_revision}</Mono> : <span className="muted">none</span>],
                  ["Tool revision", e.tool_revision ? <Mono>{e.tool_revision}</Mono> : <span className="muted">none</span>],
                ]}
              />
              {e.detail !== undefined && <JsonBlock value={e.detail} label="Detail (as recorded)" />}
            </Section>
            {related.length > 0 && (
              <Section title={`Phases of this call (${related.length})`}>
                <DataTable caption="Events of the same call" columns={eventColumns()} rows={related} rowKey={(r) => r.event_id} rowClass={(r) => (r.event_id === e.event_id ? "row-current" : undefined)} empty="" />
              </Section>
            )}
          </>
        )}
      </Loaded>
      <Section title="Investigation graph">
        <Loaded res={graph} what="the investigation graph" route="/api/v1/graph">
          {(g) => <JsonBlock value={g} label="Graph neighbourhood of this event" />}
        </Loaded>
      </Section>
    </>
  );
}

export function Audit({ path }: { path: string }) {
  const m = match("/audit/events/:id", path);
  if (m?.id) return <EventDetail id={m.id} />;
  return (
    <>
      <PageHeader code="G-14" title="Audit investigation">
        <p>The signed evidence journal: every decision, call phase and administrative action, with its verification status.</p>
      </PageHeader>
      <Help>
        <p>
          Events are read from the journal files on disk, newest first. Filters match exact values, except Text, which matches any part of the event. Select
          an event's time to see all phases of the same call. Exports are recorded in the journal; spreadsheet formulas in CSV cells are neutralised with a
          leading apostrophe.
        </p>
      </Help>
      <VerifyPanel />
      <Journal />
    </>
  );
}
