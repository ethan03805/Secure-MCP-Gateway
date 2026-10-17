// Views whose control API belongs to another element. The console does not
// assume more of a route than that it answers JSON: a list of records is
// shown as a table of its scalar fields, anything else as escaped text. A
// route this build does not serve shows "Not available in this build".
import { useState } from "react";
import { useResource } from "../data";
import { DataTable, Help, JsonBlock, KV, Loaded, PageHeader, Section, type Column } from "../ui";

export interface Endpoint {
  label: string;
  route: string;
}

type Row = Record<string, unknown>;

function isRecord(v: unknown): v is Row {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Finds the list of records in a response: the array itself or its first array field. */
export function recordsOf(data: unknown): { key: string; rows: Row[] } | null {
  if (Array.isArray(data)) return data.every(isRecord) ? { key: "", rows: data } : null;
  if (!isRecord(data)) return null;
  for (const [k, v] of Object.entries(data)) {
    if (Array.isArray(v) && v.every(isRecord)) return { key: k, rows: v };
  }
  return null;
}

function scalar(v: unknown): boolean {
  return v === null || ["string", "number", "boolean"].includes(typeof v);
}

export function columnsOf(rows: Row[], max = 8): string[] {
  const seen: string[] = [];
  for (const r of rows.slice(0, 50)) {
    for (const [k, v] of Object.entries(r)) {
      if (scalar(v) && !seen.includes(k)) seen.push(k);
    }
  }
  const pref = ["id", "name", "alias", "state", "status"];
  seen.sort((a, b) => {
    const x = pref.indexOf(a);
    const y = pref.indexOf(b);
    return (x < 0 ? 99 : x) - (y < 0 ? 99 : y);
  });
  return seen.slice(0, max);
}

function cell(v: unknown) {
  if (v === null || v === undefined || v === "") return <span className="muted">none</span>;
  if (typeof v === "boolean") return v ? "yes" : "no";
  const s = String(v);
  return /^[0-9a-f-]{20,}$|^sha256:/.test(s) ? (
    <span className="mono" title={s}>
      {s.length > 18 ? `${s.slice(0, 12)}…` : s}
    </span>
  ) : (
    s
  );
}

function Browser({ ep }: { ep: Endpoint }) {
  const res = useResource<unknown>(ep.route);
  const [open, setOpen] = useState<number | null>(null);
  return (
    <Section title={ep.label} actions={<span className="mono small muted">GET {ep.route}</span>}>
      <Loaded res={res} what={ep.label.toLowerCase()} route={ep.route}>
        {(data) => {
          const rec = recordsOf(data);
          if (!rec) {
            const pairs = isRecord(data) ? Object.entries(data).filter(([, v]) => scalar(v)) : [];
            return (
              <>
                {pairs.length > 0 && <KV rows={pairs.map(([k, v]) => [k, cell(v)])} />}
                <JsonBlock value={data} label="Response" />
              </>
            );
          }
          const cols = columnsOf(rec.rows);
          const indexed = rec.rows.map((r, i) => ({ r, i }));
          const columns: Column<{ r: Row; i: number }>[] = [
            ...cols.map((k) => ({ key: k, label: k.replace(/_/g, " "), sort: (x: { r: Row }) => String(x.r[k] ?? ""), render: (x: { r: Row }) => cell(x.r[k]) })),
            {
              key: "_detail",
              label: "Record",
              render: (x) => (
                <button type="button" className="link" aria-expanded={open === x.i} onClick={() => setOpen(open === x.i ? null : x.i)}>
                  {open === x.i ? "Hide" : "Show"}
                </button>
              ),
            },
          ];
          return (
            <>
              <DataTable caption={ep.label} columns={columns} rows={indexed} rowKey={(x) => String(x.i)} empty={`The route answered with no ${ep.label.toLowerCase()}.`} />
              {open !== null && rec.rows[open] && <JsonBlock value={rec.rows[open]} label={`Record ${open + 1}`} />}
            </>
          );
        }}
      </Loaded>
    </Section>
  );
}

export function Generic({ code, title, lede, help, endpoints }: { code?: string; title: string; lede: string; help: string; endpoints: Endpoint[] }) {
  return (
    <>
      <PageHeader code={code} title={title}>
        <p>{lede}</p>
      </PageHeader>
      <Help>
        <p>{help}</p>
        <p>
          This view reads {endpoints.map((e) => e.route).join(" and ")}. It shows the records as the owning element returns them; actions on them are
          available with smcpctl until the console gains editors for this element.
        </p>
      </Help>
      {endpoints.map((ep) => (
        <Browser key={ep.route} ep={ep} />
      ))}
    </>
  );
}
