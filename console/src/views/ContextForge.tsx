// G-15 ContextForge catalog (E-36, SRS FR-22, planned v1.3.0): the
// catalog of the pinned ContextForge release with each entry's class and
// import state, the import of a local entry with its trust decision, and
// the bundled instance. Every catalog value is third-party text: it is
// rendered as React text only and no logo or other remote media is loaded
// (FR-22.4). Routes: /api/v1/contextforge/*.
import { useEffect, useState } from "react";
import { get, post } from "../api";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { Link, match } from "../router";
import { Crumbs, DataTable, Done, ErrorBlock, Help, KV, Loaded, Mono, PageHeader, Section, SelectField, StateLabel, TextField, useAction, type Tone } from "../ui";

interface Entry {
  id: string;
  name: string;
  provider: string;
  category: string;
  class: "local" | "hosted" | "unsupported";
  unsupported_reasons?: string[];
  auth_type: string;
  url?: string;
  install?: string;
  repo?: string;
  tags: string[];
  description?: string;
  entry_sha256: string;
  import_state: "not_imported" | "imported" | "changed";
  revisions?: string[];
}

interface Instance {
  state: string;
  detail?: string;
  version: string;
  image: string;
  verified?: string;
  restarts: number;
  reason_code?: string;
  unconfined: boolean;
}

interface Status {
  bundled: boolean;
  catalog_origin?: string;
  catalog_release?: string;
  catalog_sha256?: string;
  catalog_entries: number;
  catalog_error?: string;
  catalog_reason_code?: string;
  release_lock: { version: string; image_index_digest: string; starter_set: string[] };
  import_key: { key_id: string; public_key: string; enrolled: boolean; classes?: string[] };
  instance: Instance;
}

interface Decision {
  text: string;
  sha256: string;
}

interface Proposal {
  proposal_id: string;
  entry_id: string;
  state: "building" | "ready" | "failed" | "decided";
  created: string;
  reason_code?: string;
  error?: string;
  decision?: Decision;
  outcome?: string;
  server_id?: string;
  revision?: string;
}

const classTone: Record<string, Tone> = { local: "ok", hosted: "pending", unsupported: "neutral" };
const importTone: Record<string, Tone> = { not_imported: "neutral", imported: "ok", changed: "warn" };
const instanceTone: Record<string, Tone> = { healthy: "ok", starting: "pending", unhealthy: "bad", unavailable: "bad", stopped: "neutral", disabled: "neutral" };

function Tabs({ current }: { current: "catalog" | "instance" }) {
  return (
    <nav aria-label="ContextForge sections" className="tabs">
      <Link to="/contextforge" aria-current={current === "catalog" ? "page" : undefined}>
        Catalog
      </Link>
      <Link to="/contextforge/instance" aria-current={current === "instance" ? "page" : undefined}>
        Bundled instance
      </Link>
    </nav>
  );
}

function CatalogList() {
  const [form, setForm] = useState({ class: "", category: "", auth_type: "", q: "" });
  const [q, setQ] = useState(form);
  const qs = new URLSearchParams(Object.entries(q).filter(([, v]) => v.trim()) as [string, string][]).toString();
  const res = useResource<{ catalog_sha256: string; origin: string; release: string; total: number; entries: Entry[] }>(`/api/v1/contextforge/catalog${qs ? `?${qs}` : ""}`);
  return (
    <Section title="Catalog">
      <form
        className="filters"
        aria-label="Catalog filter"
        onSubmit={(e) => {
          e.preventDefault();
          setQ(form);
        }}
      >
        <SelectField label="Class" value={form.class} onChange={(v) => setForm({ ...form, class: v })} options={[["", "any"], "local", "hosted", "unsupported"]} />
        <TextField label="Category" value={form.category} onChange={(v) => setForm({ ...form, category: v })} />
        <SelectField label="Auth type" value={form.auth_type} onChange={(v) => setForm({ ...form, auth_type: v })} options={[["", "any"], "Open", "API Key", "OAuth2.1"]} />
        <TextField label="Search" value={form.q} onChange={(v) => setForm({ ...form, q: v })} hint="Matches name, provider, description, URL, install text and tags." />
        <div className="filter-actions">
          <button type="submit" className="btn-primary">
            Apply filter
          </button>
        </div>
      </form>
      <Loaded res={res} what="the ContextForge catalog" route="/api/v1/contextforge/catalog">
        {(d) => (
          <>
            <p className="small">
              {d.origin === "pinned" ? `Catalog of ContextForge ${d.release}, pinned by this Gateway release` : "Operator-supplied catalog"}, SHA-256 <Mono>{d.catalog_sha256}</Mono>.
              Showing {d.entries.length} of {d.total} entries.
            </p>
            <DataTable
              caption="ContextForge catalog entries"
              rows={d.entries}
              rowKey={(e) => e.id}
              initialSort="name"
              empty="No catalog entry matches the filter. Clear the filter to see every entry."
              columns={[
                { key: "name", label: "Name", sort: (e) => e.name.toLowerCase(), render: (e) => <Link to={`/contextforge/entry/${encodeURIComponent(e.id)}`}>{e.name || e.id}</Link> },
                { key: "provider", label: "Provider", sort: (e) => e.provider.toLowerCase(), render: (e) => e.provider },
                { key: "category", label: "Category", sort: (e) => e.category.toLowerCase(), render: (e) => e.category },
                { key: "class", label: "Class", sort: (e) => e.class, render: (e) => <StateLabel tone={classTone[e.class] ?? "neutral"}>{e.class}</StateLabel> },
                { key: "auth", label: "Auth type", sort: (e) => e.auth_type, render: (e) => e.auth_type },
                { key: "ref", label: "URL or install", render: (e) => <Mono>{e.class === "local" ? e.install : e.url}</Mono> },
                { key: "repo", label: "Repository", render: (e) => (e.repo ? <Mono>{e.repo}</Mono> : <span className="muted">none</span>) },
                { key: "tags", label: "Tags", render: (e) => (e.tags.length ? e.tags.join(", ") : <span className="muted">none</span>) },
                { key: "state", label: "Import", sort: (e) => e.import_state, render: (e) => <StateLabel tone={importTone[e.import_state] ?? "neutral"}>{e.import_state.replace("_", " ")}</StateLabel> },
              ]}
            />
          </>
        )}
      </Loaded>
    </Section>
  );
}

function linesOf(s: string): string[] {
  return s
    .split("\n")
    .map((x) => x.trim())
    .filter(Boolean);
}

function ImportForm({ entry, onStarted }: { entry: Entry; onStarted: (id: string) => void }) {
  const [f, setF] = useState({ version: "", digest: "", type: "", pkg: "", argv: "", licenses: "", risk: "moderate" });
  const a = useAction<{ proposal: Proposal }>();
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const digest = f.digest.trim();
        const body = {
          version: f.version.trim(),
          integrity: digest.startsWith("sha512-") ? digest : "",
          artifact_sha256: digest.startsWith("sha512-") ? "" : digest,
          artifact_type: f.type,
          package: f.pkg.trim(),
          argv: linesOf(f.argv),
          licenses: f.licenses
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean),
          risk_class: f.risk,
        };
        void a.run(() => post(`/api/v1/contextforge/catalog/${encodeURIComponent(entry.id)}/import`, body), (r) => onStarted(r.proposal.proposal_id));
      }}
    >
      <p>
        The catalog names only a runner command (<Mono>{entry.install}</Mono>). Give the exact version and digest of the artifact, the command that starts it inside
        the artifact and its licenses. The Gateway fetches that artifact, starts it once without network access to read its tools, and shows the trust decision.
      </p>
      <TextField label="Exact version" value={f.version} onChange={(v) => setF({ ...f, version: v })} mono required hint="For example 0.0.41. A tag such as latest is refused." />
      <TextField label="Digest" value={f.digest} onChange={(v) => setF({ ...f, digest: v })} mono required hint="npm: the registry integrity (sha512-...). PyPI: the SHA-256 of the wheel." />
      <SelectField label="Artifact type" value={f.type} onChange={(v) => setF({ ...f, type: v })} options={[["", "from the install text"], "npm", "pypi"]} />
      <TextField label="Package (when the install text does not name it)" value={f.pkg} onChange={(v) => setF({ ...f, pkg: v })} mono />
      <div className="field">
        <label htmlFor="cf-argv">Launch command, one argument per line</label>
        <textarea id="cf-argv" className="mono" rows={3} value={f.argv} onChange={(e) => setF({ ...f, argv: e.target.value })} spellCheck={false} required />
      </div>
      <TextField label="Licenses (SPDX, comma-separated)" value={f.licenses} onChange={(v) => setF({ ...f, licenses: v })} mono required />
      <SelectField label="Risk class" value={f.risk} onChange={(v) => setF({ ...f, risk: v })} options={["moderate", "high"]} />
      {a.error && <ErrorBlock error={a.error} doing="the import" />}
      <button type="submit" className="btn-primary" disabled={a.busy}>
        Fetch and probe
      </button>
    </form>
  );
}

function HostedForm({ entry, onStarted }: { entry: Entry; onStarted: (id: string) => void }) {
  const [risk, setRisk] = useState("moderate");
  const a = useAction<{ proposal: Proposal }>();
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        void a.run(() => post(`/api/v1/contextforge/catalog/${encodeURIComponent(entry.id)}/import`, { risk_class: risk }), (r) => onStarted(r.proposal.proposal_id));
      }}
    >
      <p>
        A hosted server runs at <Mono>{entry.url}</Mono> and its code cannot be inspected. The Gateway registers it in the bundled ContextForge instance, reads its
        tools with a token scoped to it, removes the registration again and shows the trust decision. Every tool is marked untrusted.
      </p>
      <SelectField label="Risk class" value={risk} onChange={setRisk} options={["moderate", "high"]} hint="A hosted package is moderate or high." />
      {a.error && <ErrorBlock error={a.error} doing="the probe" />}
      <button type="submit" className="btn-primary" disabled={a.busy}>
        Probe hosted server
      </button>
    </form>
  );
}

function ProposalPanel({ id }: { id: string }) {
  const [p, setP] = useState<Proposal | null>(null);
  const [tick, setTick] = useState(0);
  const a = useAction<{ proposal: Proposal }>();
  useEffect(() => {
    let stop = false;
    void get<{ proposal: Proposal }>(`/api/v1/contextforge/proposals/${encodeURIComponent(id)}`).then((r) => {
      if (stop) return;
      setP(r.proposal);
      if (r.proposal.state === "building") setTimeout(() => setTick((t) => t + 1), 1000);
    });
    return () => {
      stop = true;
    };
  }, [id, tick]);
  if (!p) return <p className="muted">Reading the proposal.</p>;
  if (p.state === "building") return <p role="status">Reading the server's tools. This can take a few minutes.</p>;
  if (p.state === "failed")
    return (
      <p className="notice notice-bad" role="alert">
        The import was refused: {p.error} <Mono>{p.reason_code}</Mono>
      </p>
    );
  const done = a.result?.proposal ?? (p.state === "decided" ? p : null);
  if (done)
    return done.outcome === "imported" ? (
      <Done>
        Imported <Mono>{done.server_id}</Mono> revision <Mono>{done.revision}</Mono>, disabled. An Administrator enables it in Servers and library, and a policy rule
        grants its tools.
      </Done>
    ) : (
      <Done>Declined. Nothing was signed or imported.</Done>
    );
  const d = p.decision!;
  return (
    <>
      <h3 className="sub">Trust decision</h3>
      <pre className="block" aria-label="Trust decision text">
        {d.text}
      </pre>
      <p className="small">
        SHA-256 of this text <Mono>{d.sha256}</Mono>. Accepting signs the package with this Gateway's catalog import key and records your decision in its provenance.
      </p>
      {a.error && <ErrorBlock error={a.error} doing="the decision" />}
      <div className="dialog-actions">
        <button type="button" disabled={a.busy} onClick={() => void a.run(() => post(`/api/v1/contextforge/proposals/${encodeURIComponent(id)}/decision`, { accept: false }))}>
          Decline
        </button>
        <button
          type="button"
          className="btn-primary"
          disabled={a.busy}
          onClick={() => void a.run(() => post(`/api/v1/contextforge/proposals/${encodeURIComponent(id)}/decision`, { accept: true, presented_sha256: d.sha256 }))}
        >
          Accept and import
        </button>
      </div>
    </>
  );
}

function EntryDetail({ id }: { id: string }) {
  const res = useResource<{ entry: Entry; fields: Record<string, unknown> }>(`/api/v1/contextforge/catalog/${encodeURIComponent(id)}`);
  const perm = usePerm();
  const [proposal, setProposal] = useState<string | null>(null);
  return (
    <>
      <Crumbs items={[["ContextForge catalog", "/contextforge"], [id, null]]} />
      <Loaded res={res} what="the catalog entry" route="/api/v1/contextforge/catalog/{id}">
        {({ entry: e, fields }) => (
          <>
            <PageHeader code="G-15" title={e.name || e.id}>
              <p>One entry of the ContextForge catalog. Its text comes from a third party and is shown as written.</p>
            </PageHeader>
            <Section title="Entry">
              <KV
                rows={[
                  ["ID", <Mono>{e.id}</Mono>],
                  ["Provider", e.provider],
                  ["Category", e.category],
                  ["Class", <StateLabel tone={classTone[e.class] ?? "neutral"}>{e.class}</StateLabel>],
                  ...(e.unsupported_reasons?.length ? ([["Unsupported because", e.unsupported_reasons.join("; ")]] as [string, React.ReactNode][]) : []),
                  ["Auth type", e.auth_type],
                  ["URL", e.url ? <Mono>{e.url}</Mono> : <span className="muted">none</span>],
                  ["Install text (never run)", e.install ? <Mono>{e.install}</Mono> : <span className="muted">none</span>],
                  ["Repository", e.repo ? <Mono>{e.repo}</Mono> : <span className="muted">none</span>],
                  ["Logo (not loaded)", typeof fields.logo_url === "string" ? <Mono>{fields.logo_url}</Mono> : <span className="muted">none</span>],
                  ["Tags", e.tags.length ? e.tags.join(", ") : <span className="muted">none</span>],
                  ["Description", e.description ?? <span className="muted">none</span>],
                  ["Entry SHA-256", <Mono>{e.entry_sha256}</Mono>],
                  ["Import", <StateLabel tone={importTone[e.import_state] ?? "neutral"}>{e.import_state.replace("_", " ")}</StateLabel>],
                  ["Imported revisions", e.revisions?.length ? <Mono>{e.revisions.join(" ")}</Mono> : <span className="muted">none</span>],
                ]}
              />
            </Section>
            {e.class === "local" && perm.can("POST /api/v1/contextforge/catalog/{id}/import") && (
              <Section title="Import">{proposal ? <ProposalPanel id={proposal} /> : <ImportForm entry={e} onStarted={setProposal} />}</Section>
            )}
            {e.class === "hosted" && perm.can("POST /api/v1/contextforge/catalog/{id}/import") && (
              <Section title="Import">{proposal ? <ProposalPanel id={proposal} /> : <HostedForm entry={e} onStarted={setProposal} />}</Section>
            )}
          </>
        )}
      </Loaded>
    </>
  );
}

function InstancePanel() {
  const res = useResource<Status>("/api/v1/contextforge/status");
  const perm = usePerm();
  const a = useAction<{ instance: Instance }>();
  const starter = useAction<{ proposals: Proposal[] }>();
  return (
    <Loaded res={res} what="the ContextForge Connector" route="/api/v1/contextforge/status">
      {(s) => (
        <>
          <Section title="Bundled instance">
            <KV
              rows={[
                ["State", <StateLabel tone={instanceTone[s.instance.state] ?? "neutral"}>{s.instance.state}</StateLabel>],
                ...(s.instance.detail ? ([["Detail", s.instance.detail]] as [string, React.ReactNode][]) : []),
                ["Version", <Mono>{s.instance.version}</Mono>],
                ["Image", <Mono>{s.instance.image}</Mono>],
                ["Image verified", s.instance.verified ? <Mono>{s.instance.verified}</Mono> : <span className="muted">not yet</span>],
                ["Restarts", <Mono>{s.instance.restarts}</Mono>],
                ["Containment", s.instance.unconfined ? "not enforced: the Standalone profile does not sandbox the instance" : "Enforced profile"],
              ]}
            />
            {!s.bundled && <p>The bundled instance is off. Set [contextforge] bundled = true in smcp.toml to use hosted catalog entries.</p>}
            {s.bundled && perm.can("POST /api/v1/contextforge/instance/start") && (
              <div className="dialog-actions">
                <button type="button" disabled={a.busy} onClick={() => void a.run(() => post("/api/v1/contextforge/instance/stop", {}), () => res.reload())}>
                  Stop instance
                </button>
                <button type="button" className="btn-primary" disabled={a.busy} onClick={() => void a.run(() => post("/api/v1/contextforge/instance/start", {}), () => res.reload())}>
                  Start instance
                </button>
              </div>
            )}
            {a.error && <ErrorBlock error={a.error} doing="the instance action" />}
            {s.bundled && perm.can("POST /api/v1/contextforge/starter-set") && (
              <>
                <h3 className="sub">Starter set</h3>
                <p>
                  The starter set of this release (<Mono>{s.release_lock.starter_set.join(" ")}</Mono>) are hosted documentation servers with read-only tools. Importing it
                  probes each entry and gives each its own trust decision on its entry page; none is enabled.
                </p>
                <button type="button" disabled={starter.busy} onClick={() => void starter.run(() => post("/api/v1/contextforge/starter-set", {}))}>
                  Import the starter set
                </button>
                {starter.error && <ErrorBlock error={starter.error} doing="the starter set" />}
                {starter.result && (
                  <Done>
                    Started {starter.result.proposals.length} imports. Open each entry to read and decide its trust decision.
                  </Done>
                )}
              </>
            )}
          </Section>
          <Section title="Catalog and release lock">
            <KV
              rows={[
                ["Catalog", s.catalog_error ? <>refused: {s.catalog_error} <Mono>{s.catalog_reason_code}</Mono></> : <>{s.catalog_origin} {s.catalog_release}, {s.catalog_entries} entries</>],
                ["Catalog SHA-256", <Mono>{s.catalog_sha256 ?? "none"}</Mono>],
                ["Pinned ContextForge", <Mono>{s.release_lock.version}</Mono>],
                ["Image index digest", <Mono>{s.release_lock.image_index_digest}</Mono>],
                ["Starter set", <Mono>{s.release_lock.starter_set.join(" ")}</Mono>],
                ["Catalog import key", <Mono>{s.import_key.key_id}</Mono>],
                ["Import key enrolled", s.import_key.enrolled ? `yes, for ${(s.import_key.classes ?? []).join(", ")}` : "no: an Administrator enrolls it once in Servers and library"],
              ]}
            />
            {!s.import_key.enrolled && (
              <p className="small">
                Public key to enroll: <Mono>{s.import_key.public_key}</Mono>
              </p>
            )}
          </Section>
        </>
      )}
    </Loaded>
  );
}

export function ContextForge({ path }: { path: string }) {
  const m = match("/contextforge/entry/:id", path);
  if (m) return <EntryDetail id={m.id!} />;
  const instance = path === "/contextforge/instance";
  return (
    <>
      <PageHeader code="G-15" title="ContextForge catalog">
        <p>Servers listed in the IBM ContextForge catalog, imported into the library only through packaging and an explicit trust decision.</p>
      </PageHeader>
      <Help>
        <p>
          A local entry names a repository and an install command; you import it by pinning the exact artifact, and it then runs like any other package. A hosted
          entry is a remote server reached through the bundled ContextForge instance. Unsupported entries cannot be imported. An imported package starts
          disabled; enabling it and granting its tools are separate steps.
        </p>
      </Help>
      <Tabs current={instance ? "instance" : "catalog"} />
      {instance ? <InstancePanel /> : <CatalogList />}
    </>
  );
}
