// G-08 Data server & memory (FR-8.16): graph mirror memory against its
// budget, Observation Store memory against its budget, cache hit ratios,
// store sizes and counts, observation queue use and degradation
// stage, storage quota levels, the last backups and taking one, and the key
// inventory with rotation. Routes: /api/v1/graph/status,
// /api/v1/graph/rebuild, /api/v1/observations/status,
// /api/v1/health/status (quotas), /api/v1/backup, /api/v1/keys*.
import { ObjectState, Publish, useObjects } from "./objects";
import { useState, type ReactNode } from "react";
import { post } from "../api";
import { Meter } from "../charts";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { DataTable, Done, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, SelectField, StateLabel, TextField, Time, bytes, compact, useAction } from "../ui";
import type { ObsStatus } from "./Observations";

interface GraphStatus {
  enabled: boolean;
  state: string;
  uri: string;
  error?: string;
  schema_version: number;
  checkpoint: { segment: number; events: number };
  live_applied: number;
  live_dropped: number;
  last_catch_up?: string;
  last_retention?: string;
  hardening: { setting: string; value: string; want: string; reason: string }[];
  memory: { budget: { heap_bytes: number; page_cache_bytes: number }; heap_used: number; heap_max: number; page_cache_configured: number; pressure: boolean; sampled_at?: string };
  counts?: Record<string, number>;
}

interface Backup {
  path: string;
  sha256: string;
  size: number;
  created_at: string;
  components: string[];
  result: string;
}

function Graph() {
  const res = useResource<GraphStatus>("/api/v1/graph/status");
  const perm = usePerm();
  const rebuild = useAction<{ status: string }>();
  return (
    <Section
      title="Graph mirror"
      actions={
        perm.can("POST /api/v1/graph/rebuild") && (
          <button type="button" disabled={rebuild.busy} onClick={() => void rebuild.run(() => post("/api/v1/graph/rebuild", {}), res.reload)}>
            Rebuild from the journal
          </button>
        )
      }
    >
      {rebuild.error && <ErrorBlock error={rebuild.error} doing="the rebuild" />}
      {rebuild.result && <Done>A rebuild is queued.</Done>}
      <Loaded res={res} what="the graph mirror" route="/api/v1/graph/status">
        {(g) => (
          <>
            <KV
              rows={[
                ["State", <StateLabel tone={g.state === "ready" ? "ok" : g.state === "disabled" ? "neutral" : "warn"}>{g.state}</StateLabel>],
                ["Database", <Mono>{g.uri}</Mono>],
                ...(g.error ? ([["Error", <Mono>{g.error}</Mono>]] as [string, ReactNode][]) : []),
                ["Journal checkpoint", <Mono>segment {g.checkpoint.segment}, {compact(g.checkpoint.events)} events</Mono>],
                ["Live events applied / dropped", <Mono>{compact(g.live_applied)} / {compact(g.live_dropped)}</Mono>],
                ["Memory budget in force", <Mono>{bytes(g.memory.budget.heap_bytes)} heap, {bytes(g.memory.budget.page_cache_bytes)} page cache</Mono>],
                ["Last catch-up", <Time value={g.last_catch_up} />],
                ["Last retention run", <Time value={g.last_retention} />],
              ]}
            />
            {!g.enabled && <p className="empty">The graph mirror is disabled ([graph] enabled = false). Enforcement never depends on it. To use it, install Neo4j and set [graph] enabled = true (docs/graph.md).</p>}
            {g.enabled && (
              <>
                <Meter label="Heap in use against budget" used={g.memory.heap_used} budget={g.memory.budget.heap_bytes} format={bytes} />
                <Meter label="Page cache configured against budget" used={g.memory.page_cache_configured} budget={g.memory.budget.page_cache_bytes} format={bytes} />
                {g.memory.pressure && <p className="notice notice-warn">The database reports memory pressure.</p>}
              </>
            )}
            {g.counts && (
              <DataTable
                caption="Mirrored nodes"
                rows={Object.entries(g.counts)}
                rowKey={(r) => r[0]}
                initialSort="n"
                initialDir="desc"
                empty=""
                columns={[
                  { key: "k", label: "Kind", sort: (r) => r[0], render: (r) => <Mono>{r[0]}</Mono> },
                  { key: "n", label: "Count", sort: (r) => r[1], render: (r) => <Mono>{compact(r[1])}</Mono>, className: "num" },
                ]}
              />
            )}
            {g.hardening.length > 0 && (
              <>
                <h3 className="sub">Database settings that differ from the hardening profile</h3>
                <DataTable
                  caption="Hardening findings"
                  rows={g.hardening}
                  rowKey={(h) => h.setting}
                  empty=""
                  columns={[
                    { key: "s", label: "Setting", render: (h) => <Mono>{h.setting}</Mono> },
                    { key: "v", label: "Value", render: (h) => <Mono>{h.value}</Mono> },
                    { key: "w", label: "Wanted", render: (h) => <Mono>{h.want}</Mono> },
                    { key: "r", label: "Why", render: (h) => h.reason },
                  ]}
                />
              </>
            )}
          </>
        )}
      </Loaded>
    </Section>
  );
}

const MiB = 1 << 20;
const mibOf = (b: number | undefined, dflt: number) => String(b ? Math.round(b / MiB) : dflt);
const wholeIn = (v: string, lo: number, hi: number) => {
  const n = Number(v);
  return Number.isInteger(n) && n >= lo && n <= hi;
};

/**
 * The memory budgets (FR-8.16), published as one revision: the Observation
 * Store's and the graph engine's heap and page cache. Both take effect at
 * the next start of smcpd.
 */
function MemoryBudget() {
  const objects = useObjects();
  const eff = objects.status === "ok" ? objects.data.effective : undefined;
  const obs = eff?.memory_limit_bytes as number | undefined;
  const heap = eff?.graph_heap_bytes as number | undefined;
  const pc = eff?.graph_page_cache_bytes as number | undefined;
  const [mib, setMib] = useState<string | null>(null);
  const [heapMib, setHeapMib] = useState<string | null>(null);
  const [pcMib, setPcMib] = useState<string | null>(null);
  const value = mib ?? mibOf(obs, 512);
  const heapValue = heapMib ?? mibOf(heap, 1024);
  const pcValue = pcMib ?? mibOf(pc, 1024);
  const ok = wholeIn(value, 64, 65536);
  const heapOk = wholeIn(heapValue, 256, 65536);
  const pcOk = wholeIn(pcValue, 64, 65536);
  return (
    <Section title="Memory budget">
      <Loaded res={objects} what="the memory budget" route="/api/v1/observations/objects">
        {(o) => (
          <>
            <KV
              rows={[
                ["Observation Store budget (published or configured)", <Mono>{obs ? bytes(obs) : "default 512 MiB"}</Mono>],
                ["Graph budget (published or configured)", <Mono>{heap ? bytes(heap) : "default 1 GiB"} heap, {pc ? bytes(pc) : "default 1 GiB"} page cache</Mono>],
              ]}
            />
            <ObjectState objects={o} kind="memory_budget" label="memory budget" />
            <div className="rule-grid">
              <TextField label="Observation Store memory budget (MiB)" value={value} onChange={setMib} type="number" hint="64 MiB to 64 GiB; DuckDB memory_limit" />
              <TextField label="Graph heap budget (MiB)" value={heapValue} onChange={setHeapMib} type="number" hint="256 MiB to 64 GiB; Neo4j server.memory.heap.max_size" />
              <TextField label="Graph page cache budget (MiB)" value={pcValue} onChange={setPcMib} type="number" hint="64 MiB to 64 GiB; Neo4j server.memory.pagecache.size" />
            </div>
            {!ok && (
              <p className="notice notice-bad" role="alert">
                The budget must be a whole number of MiB from 64 to 65536.
              </p>
            )}
            {!heapOk && (
              <p className="notice notice-bad" role="alert">
                The graph heap budget must be a whole number of MiB from 256 to 65536.
              </p>
            )}
            {!pcOk && (
              <p className="notice notice-bad" role="alert">
                The graph page cache budget must be a whole number of MiB from 64 to 65536.
              </p>
            )}
            <p className="small">The graph budget is what the graph mirror checks the database's memory settings against; set the same values in Neo4j (smcpctl graph engine config).</p>
            <Publish
              route="/api/v1/observations/memory-budget"
              label="memory budget"
              body={{ observation_memory_limit_bytes: Number(value) * MiB, graph_heap_bytes: Number(heapValue) * MiB, graph_page_cache_bytes: Number(pcValue) * MiB }}
              disabled={!ok || !heapOk || !pcOk}
              onPublished={objects.reload}
            />
          </>
        )}
      </Loaded>
    </Section>
  );
}

function ObservationStore() {
  const res = useResource<ObsStatus>("/api/v1/observations/status");
  return (
    <Section title="Observation Store">
      <Loaded res={res} what="the observation store" route="/api/v1/observations/status">
        {(s) =>
          !s.enabled ? (
            <p className="empty">Observation is disabled.</p>
          ) : (
            <>
              <KV
                rows={[
                  ["Backend", s.store ? <Mono>{s.store.backend}</Mono> : <StateLabel tone="bad">{s.store_error ?? "unavailable"}</StateLabel>],
                  ["Size", s.store ? <Mono>{bytes(s.store.bytes)} in {s.store.files} files</Mono> : "none"],
                  ["Rows written", <Mono>{Object.entries(s.store?.rows_written ?? {}).map(([k, v]) => `${k} ${compact(v)}`).join(", ") || "none"}</Mono>],
                  ["Retention", <Mono>{s.retention}</Mono>],
                  ["Dropped", <Mono>{Object.entries(s.collector?.drops ?? {}).map(([k, v]) => `${k} ${compact(v)}`).join(", ") || "none"}</Mono>],
                  [
                    "Degradation stage",
                    s.degradation ? (
                      <>
                        <StateLabel tone={s.degradation.stage === 0 ? "ok" : "warn"}>{s.degradation.name}</StateLabel>
                        {s.degradation.reason && <span className="muted small"> {s.degradation.reason}</span>}
                      </>
                    ) : (
                      "not reported"
                    ),
                  ],
                ]}
              />
              {s.store?.memory && <Meter label="Memory in use against the budget in force" used={s.store.memory.used_bytes} budget={s.store.memory.limit_bytes} format={bytes} />}
              {s.collector && <Meter label="Collector queue" used={s.collector.queue_depth} budget={s.collector.queue_capacity} />}
            </>
          )
        }
      </Loaded>
    </Section>
  );
}

interface CacheStat {
  name: string;
  description: string;
  hits: number;
  misses: number;
  hit_ratio: number | null;
  entries?: number;
}

/** Hit ratios of the in-process caches since smcpd started (FR-8.16). */
function Caches() {
  const res = useResource<{ info?: { caches?: CacheStat[] } }>("/api/v1/health/status");
  return (
    <Section title="Caches">
      <Loaded res={res} what="the cache counts" route="/api/v1/health/status">
        {(h) => (
          <DataTable
            caption="Cache hit ratios"
            rows={h.info?.caches ?? []}
            rowKey={(c) => c.name}
            initialSort="name"
            empty="No cache is reported."
            columns={[
              { key: "name", label: "Cache", sort: (c) => c.name, render: (c) => <><Mono>{c.name}</Mono> <span className="muted small">{c.description}</span></> },
              {
                key: "ratio",
                label: "Hit ratio",
                sort: (c) => c.hit_ratio ?? -1,
                render: (c) => (c.hit_ratio === null ? <span className="muted">no lookups</span> : <Mono>{`${(c.hit_ratio * 100).toFixed(1)}%`}</Mono>),
                className: "num",
              },
              { key: "hits", label: "Hits", sort: (c) => c.hits, render: (c) => <Mono>{compact(c.hits)}</Mono>, className: "num" },
              { key: "misses", label: "Misses", sort: (c) => c.misses, render: (c) => <Mono>{compact(c.misses)}</Mono>, className: "num" },
              { key: "entries", label: "Entries", sort: (c) => c.entries ?? -1, render: (c) => (c.entries === undefined ? <span className="muted">not counted</span> : <Mono>{compact(c.entries)}</Mono>), className: "num" },
            ]}
          />
        )}
      </Loaded>
      <p className="small">Counted since smcpd started.</p>
    </Section>
  );
}

interface QuotaLevel {
  name: string;
  bytes: number;
  limit_bytes: number;
  percent: number;
  warning: boolean;
  measured_at: string;
  error?: string;
}

/** Storage quota levels the Health & Safety Monitor reports (FR-9.15, CP-26). */
function Quotas() {
  const res = useResource<{ quotas?: QuotaLevel[] }>("/api/v1/health/status");
  return (
    <Section title="Storage quotas">
      <Loaded res={res} what="the quota levels" route="/api/v1/health/status">
        {(h) => (
          <DataTable
            caption="Storage quotas"
            rows={h.quotas ?? []}
            rowKey={(q) => q.name}
            initialSort="pct"
            initialDir="desc"
            empty="No store has a quota."
            columns={[
              { key: "name", label: "Store", sort: (q) => q.name, render: (q) => <Mono>{q.name}</Mono> },
              { key: "used", label: "Used", sort: (q) => q.bytes, render: (q) => <Mono>{bytes(q.bytes)}</Mono>, className: "num" },
              { key: "limit", label: "Quota", sort: (q) => q.limit_bytes, render: (q) => <Mono>{bytes(q.limit_bytes)}</Mono>, className: "num" },
              {
                key: "pct",
                label: "Percent of quota",
                sort: (q) => q.percent,
                render: (q) => <StateLabel tone={q.warning ? "warn" : "ok"}>{`${q.percent.toFixed(1)}%`}</StateLabel>,
                className: "num",
              },
              { key: "at", label: "Measured", sort: (q) => q.measured_at, render: (q) => (q.error ? <StateLabel tone="bad">{q.error}</StateLabel> : <Time value={q.measured_at} />) },
            ]}
          />
        )}
      </Loaded>
    </Section>
  );
}

function Backups() {
  const res = useResource<{ dir: string; backups: Backup[] }>("/api/v1/backup");
  const perm = usePerm();
  const [mode, setMode] = useState("passphrase");
  const [secret, setSecret] = useState("");
  const take = useAction<{ path: string; sha256: string; size: number }>();
  return (
    <Section title="Backups">
      <Loaded res={res} what="backups" route="/api/v1/backup">
        {(d) => (
          <>
            <p className="small">
              Backups are written to <Mono>{d.dir}</Mono>. Last result:{" "}
              {d.backups[0] ? <StateLabel tone={d.backups[0].result === "ok" ? "ok" : "bad"}>{d.backups[0].result}</StateLabel> : <span className="muted">no backup yet</span>}
            </p>
            <DataTable
              caption="Backups"
              rows={d.backups}
              rowKey={(b) => b.path}
              initialSort="created"
              initialDir="desc"
              empty="No backup has been taken. Take one below or with smcpctl backup."
              columns={[
                { key: "created", label: "Taken", sort: (b) => b.created_at, render: (b) => <Time value={b.created_at} /> },
                { key: "result", label: "Result", sort: (b) => b.result, render: (b) => <StateLabel tone={b.result === "ok" ? "ok" : "bad"}>{b.result}</StateLabel> },
                { key: "size", label: "Size", sort: (b) => b.size, render: (b) => <Mono>{bytes(b.size)}</Mono>, className: "num" },
                { key: "components", label: "Components", render: (b) => b.components.join(", ") },
                { key: "sha", label: "SHA-256", render: (b) => <Mono>{b.sha256.slice(0, 12)}</Mono> },
              ]}
            />
          </>
        )}
      </Loaded>
      {perm.can("POST /api/v1/backup") && (
        <form
          className="inline-form"
          aria-label="Take a backup"
          onSubmit={(e) => {
            e.preventDefault();
            const v = secret;
            setSecret("");
            void take.run(() => post("/api/v1/backup", mode === "passphrase" ? { passphrase: v } : { recipients: v.split(/[\s,]+/).filter(Boolean) }), res.reload);
          }}
        >
          <SelectField label="Encrypt to" value={mode} onChange={setMode} options={[["passphrase", "a passphrase"], ["recipients", "age recipients"]]} />
          {mode === "passphrase" ? (
            <TextField label="Passphrase" value={secret} onChange={setSecret} type="password" autoComplete="new-password" required />
          ) : (
            <TextField label="Recipients (age1…)" value={secret} onChange={setSecret} mono required />
          )}
          <button type="submit" className="btn-primary" disabled={take.busy || !secret}>
            {take.busy ? "Taking backup" : "Take a backup now"}
          </button>
        </form>
      )}
      <p className="small">A backup briefly stops tool calls while it drains in-flight calls, then resumes.</p>
      {take.error && <ErrorBlock error={take.error} doing="the backup" />}
      {take.result && <Done>Backup written: {take.result.path} ({bytes(take.result.size)}).</Done>}
    </Section>
  );
}

function Keys() {
  const res = useResource<Record<string, unknown>>("/api/v1/keys");
  const perm = usePerm();
  const rotate = useAction<Record<string, unknown>>();
  const cert = (v: unknown): ReactNode => {
    const c = v as { subject?: string; not_after?: string; sha256?: string } | undefined;
    return c ? <><Mono>{c.subject}</Mono>, until <Time value={c.not_after} /></> : <span className="muted">none</span>;
  };
  return (
    <Section title="Keys">
      <Loaded res={res} what="the key inventory" route="/api/v1/keys">
        {(k) => (
          <KV
            rows={[
              ["Server CA", cert(k.server_ca)],
              ["Listener certificate", cert(k.listener_certificate)],
              ["CA rotation", k.ca_rotation ? <Mono>{JSON.stringify(k.ca_rotation)}</Mono> : "none in progress"],
              ["Renewal due", <>{k.ca_due ? <StateLabel tone="warn">CA due</StateLabel> : "CA not due"}; {k.listener_due ? <StateLabel tone="warn">listener due</StateLabel> : "listener not due"}</>],
              ["Evidence public key", <Mono>{String(k.evidence_public_key ?? "").slice(0, 24)}</Mono>],
              ["Installation", <Mono>{String(k.installation_id ?? "")}</Mono>],
            ]}
          />
        )}
      </Loaded>
      {perm.can("POST /api/v1/keys/rotate") && (
        <div className="filter-actions">
          <button type="button" disabled={rotate.busy} onClick={() => void rotate.run(() => post("/api/v1/keys/rotate", { kind: "tls" }), res.reload)}>
            Rotate the listener certificate
          </button>
          <button type="button" disabled={rotate.busy} onClick={() => void rotate.run(() => post("/api/v1/keys/rotate", { kind: "evidence" }), res.reload)}>
            Rotate the evidence key
          </button>
        </div>
      )}
      {rotate.error && <ErrorBlock error={rotate.error} doing="the rotation" />}
      {rotate.result && <Done>Rotated: {String(rotate.result.kind)}.</Done>}
    </Section>
  );
}

export function DataServer() {
  const perm = usePerm();
  return (
    <>
      <PageHeader code="G-08" title="Data server and memory">
        <p>Memory use against budget, cache hit ratios, store sizes, queue use, degradation stage, quota levels, backups and keys.</p>
      </PageHeader>
      <Help>
        <p>
          The Data Server (graph mirror and Observation Store) is optional: enforcement never waits for it, and when it is full or down, observations are
          dropped and counted rather than slowing calls. The Observation Store and graph memory budgets are published here and take effect at the next start of smcpd. Backups are encrypted with
          age; keep the passphrase or identity elsewhere.
        </p>
      </Help>
      {perm.can("GET /api/v1/graph/status") && <Graph />}
      {perm.can("GET /api/v1/observations/status") && <ObservationStore />}
      {perm.can("GET /api/v1/observations/objects") && <MemoryBudget />}
      {perm.can("GET /api/v1/health/status") && <Caches />}
      {perm.can("GET /api/v1/health/status") && <Quotas />}
      {perm.can("GET /api/v1/backup") && <Backups />}
      {perm.can("GET /api/v1/keys") && <Keys />}
    </>
  );
}
