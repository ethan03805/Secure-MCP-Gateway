import Link from "next/link";
import { DocHead, GeneratedAt, ImplBadge, Note, ReqBadge, SampleNotice, Sec } from "@/components/Sheet";
import VerificationBars, { type VerificationRow } from "@/components/charts/VerificationBars";
import TrendChart from "@/components/charts/TrendChart";
import { loadArch } from "@/lib/parse-arch";
import { loadStatus, type ReqStatus } from "@/lib/status";
import {
  REQ_STATUSES,
  REQ_STATUS_MEANING,
  buildCommit,
  chapter,
  elementStatusMap,
  fmtDate,
  fmtDateTime,
  fmtPct,
  plural,
  shortSha,
} from "@/lib/site";

export const metadata = { title: "Status" };

const CH = chapter("/status/");

export default function StatusPage() {
  const arch = loadArch();
  const snap = loadStatus();
  const s = snap.status;
  const els = elementStatusMap(s);
  const byEl = new Map(s.requirements.byElement.map((b) => [b.element, b]));
  const covBy = new Map(s.coverage.packages.map((c) => [c.name, c.pct]));
  const r = s.requirements;

  const implCount = (k: string) => arch.elements.filter((e) => els.get(e.id)?.implementation === k).length;
  const noData = arch.elements.filter((e) => !els.has(e.id));
  const extra = s.elements.filter((e) => !arch.elements.some((a) => a.id === e.id));

  const rows: VerificationRow[] = arch.subsystems.flatMap((ss) =>
    arch.elements
      .filter((e) => e.subsystemId === ss.id)
      .map((e) => {
        const b = byEl.get(e.id);
        const counts: Record<ReqStatus, number> = b
          ? {
              verified: b.verified,
              partial: b.partial,
              failing: b.failing,
              unverified: Math.max(0, b.total - b.verified - b.partial - b.failing),
            }
          : { verified: 0, partial: 0, failing: 0, unverified: 0 };
        return {
          id: e.id,
          name: e.name,
          group: `${ss.id} ${ss.name}`,
          counts,
          note: b ? undefined : "not in status data",
        };
      }),
  );

  const hist = snap.history;
  const points = hist.map((h) => ({ commit: shortSha(h.commit), date: fmtDate(h.generatedAt) }));
  const histEmpty =
    snap.source === "remote" && snap.historyReason
      ? `No history to plot: ${snap.historyReason}.`
      : "No history yet. Each CI run on main adds one point.";

  const pkgNames = Array.from(new Set([...s.tests.packages.map((p) => p.name), ...s.coverage.packages.map((c) => c.name)])).sort();
  const pkgTests = new Map(s.tests.packages.map((p) => [p.name, p]));

  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Status"
        left={["Secure MCP Gateway", "Implementation and verification status", snap.source === "remote" ? "Source: status.json from CI" : "Source: sample data"]}
        right={[
          snap.source === "remote" ? `commit ${shortSha(s.commit)}` : "commit: none (sample)",
          <GeneratedAt key="g" snap={snap} />,
          `site build ${buildCommit()}`,
        ]}
      >
        <p>
          What exists in code, what its tests show, and which requirements those tests verify. CI writes these figures
          on every push to main; this page is rebuilt from them.
        </p>
      </DocHead>

      <SampleNotice snap={snap} />

      <Sec no={`${CH.n}.1`} id="run" title="Run under report">
        <Note label="Status rules">
          {REQ_STATUSES.map((k) => (
            <p key={k}>
              <ReqBadge status={k} /> {REQ_STATUS_MEANING[k]}
            </p>
          ))}
        </Note>
        <dl className="facts">
          <dt>Data source</dt>
          <dd>
            {snap.source === "remote" ? (
              <a href={snap.statusUrl}>{snap.statusUrl}</a>
            ) : (
              <>
                <code>site/data/status.sample.json</code>. {snap.reason}
              </>
            )}
          </dd>
          <dt>Commit</dt>
          <dd>
            {s.commitUrl ? <a href={s.commitUrl}>{snap.source === "remote" ? s.commit : "sample, no commit"}</a> : s.commit}
          </dd>
          <dt>CI run</dt>
          <dd>
            {s.runUrl ? <a href={s.runUrl}>{s.ci.workflow || "workflow run"}</a> : "not recorded"}
            {s.ci.conclusion ? `, concluded ${s.ci.conclusion}` : ""}
          </dd>
          <dt>Generated</dt>
          <dd>
            <GeneratedAt snap={snap} />
          </dd>
          <dt>Read by this build</dt>
          <dd>{fmtDateTime(snap.fetchedAt)}</dd>
          <dt>History</dt>
          <dd>{plural(hist.length, "run")} recorded{hist.length ? `, ${fmtDate(hist[0].generatedAt)} to ${fmtDate(hist[hist.length - 1].generatedAt)}` : ""}</dd>
        </dl>
      </Sec>

      <Sec no={`${CH.n}.2`} id="implementation" title="Implementation by subsystem">
        <Note label="Totals">
          <p>
            {implCount("implemented")} implemented, {implCount("partial")} partial, {implCount("not-started")} not
            started, of {arch.elements.length} elements.
          </p>
          {noData.length > 0 && <p>No status entry for {noData.map((e) => e.id).join(", ")}.</p>}
          {extra.length > 0 && <p>Status data names elements not in the architecture: {extra.map((e) => e.id).join(", ")}.</p>}
        </Note>
        <p>
          Each element of the architecture with the implementation state recorded in <code>docs/status/elements.json</code>.
          An element is implemented when the code covers its allocated functions, partial when some are covered.
        </p>
        <div className="table-wrap wide">
          <table className="matrix">
            <caption>Elements by subsystem, in architecture order.</caption>
            <tbody>
              {arch.subsystems.map((ss) => {
                const mine = arch.elements.filter((e) => e.subsystemId === ss.id);
                return (
                  <tr key={ss.id}>
                    <th scope="row">
                      {ss.id}
                      <br />
                      {ss.name}
                    </th>
                    <td>
                      <ul>
                        {mine.map((e) => (
                          <li key={e.id}>
                            <span className="id">{e.id}</span>
                            <Link href={`/elements/${e.id}/`}>{e.name}</Link>
                            <ImplBadge impl={els.get(e.id)?.implementation} />
                          </li>
                        ))}
                      </ul>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${CH.n}.3`} id="verification" title="Requirement verification by element">
        <Note label="Totals">
          <p>
            {r.verified} verified, {r.partial} partial, {r.failing} failing, {r.unverified} unverified, of {r.total}{" "}
            requirements.
          </p>
        </Note>
        <p>
          Tests claim requirements with <code>reqtest.Verifies</code> (in full) or <code>reqtest.Partial</code>. Each
          requirement counts once, under the element it is allocated to.
        </p>
        <VerificationBars
          id="verif"
          title="Requirements per element by verification status"
          desc={`Horizontal stacked bars for ${rows.length} elements. In total ${r.verified} verified, ${r.partial} partial, ${r.failing} failing and ${r.unverified} unverified of ${r.total}. The data table below lists every value.`}
          rows={rows}
        />
      </Sec>

      <Sec no={`${CH.n}.4`} id="tests" title="Tests and coverage">
        <Note label="Run">
          <p>
            {s.tests.total} tests in {plural(s.tests.packages.length, "package")}, {s.tests.durationSec.toFixed(1)} s of
            package time.
          </p>
        </Note>
        <p>
          {s.tests.passed} passed, {s.tests.failed} failed, {s.tests.skipped} skipped. Total statement coverage as
          reported by CI is {fmtPct(s.coverage.totalPct)}.
        </p>
        <div className="table-wrap wide">
          <table>
            <caption>Go packages, from go test -json and -cover.</caption>
            <thead>
              <tr>
                <th scope="col">Package</th>
                <th scope="col" className="num">passed</th>
                <th scope="col" className="num">failed</th>
                <th scope="col" className="num">skipped</th>
                <th scope="col" className="num">coverage</th>
              </tr>
            </thead>
            <tbody>
              {pkgNames.map((name) => {
                const t = pkgTests.get(name);
                const c = covBy.get(name);
                return (
                  <tr key={name}>
                    <td className="id">{name}</td>
                    <td className="num">{t?.passed ?? 0}</td>
                    <td className="num">{t?.failed ? <strong>{t.failed}</strong> : 0}</td>
                    <td className="num">{t?.skipped ?? 0}</td>
                    <td className="num">{c === undefined ? <span className="nil">none</span> : fmtPct(c)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${CH.n}.5`} id="trends" title="Trends">
        <p>
          One point per CI run on main, from history.json, which keeps the last 200 runs. Points are spaced by run, not
          by time, because runs are irregular.
        </p>
        <TrendChart
          id="trend-tests"
          title="Tests passed and failed per run"
          desc={`Two lines over ${plural(points.length, "run")}. Latest: ${hist.at(-1)?.testsPassed ?? 0} passed, ${hist.at(-1)?.testsFailed ?? 0} failed.`}
          points={points}
          series={[
            { key: "passed", label: "passed", tone: "passed", values: hist.map((h) => h.testsPassed) },
            { key: "failed", label: "failed", tone: "failed", values: hist.map((h) => h.testsFailed) },
          ]}
          empty={histEmpty}
        />
        <TrendChart
          id="trend-cov"
          title="Statement coverage per run, percent"
          desc={`One line over ${plural(points.length, "run")}. Latest: ${fmtPct(hist.at(-1)?.coveragePct ?? 0)}.`}
          points={points}
          series={[{ key: "cov", label: "coverage", tone: "ink", values: hist.map((h) => h.coveragePct) }]}
          unit="%"
          yMax={100}
          empty={histEmpty}
        />
        <TrendChart
          id="trend-reqs"
          title="Requirements by verification status per run"
          desc={`Three lines over ${plural(points.length, "run")}. Latest: ${hist.at(-1)?.verified ?? 0} verified, ${hist.at(-1)?.partial ?? 0} partial, ${hist.at(-1)?.unverified ?? 0} unverified.`}
          points={points}
          series={[
            { key: "verified", label: "verified", tone: "verified", values: hist.map((h) => h.verified) },
            { key: "partial", label: "partial", tone: "partial", values: hist.map((h) => h.partial) },
            { key: "unverified", label: "unverified", tone: "unverified", values: hist.map((h) => h.unverified) },
          ]}
          empty={histEmpty}
        />
      </Sec>

      <Sec no={`${CH.n}.6`} id="agents" title="Real-agent compatibility">
        <p>
          Shipping agent harnesses connected to a running Gateway: whether each can authenticate, list tools and complete
          a call.
        </p>
        {s.agents.length === 0 ? (
          <p className="empty-state">Not yet run. The compatibility job has not reported results for any client.</p>
        ) : (
          <div className="table-wrap wide">
            <table>
              <thead>
                <tr>
                  <th scope="col">Client</th>
                  <th scope="col">Version</th>
                  <th scope="col">Mode</th>
                  <th scope="col">Result</th>
                  <th scope="col">Detail</th>
                </tr>
              </thead>
              <tbody>
                {s.agents.map((a, i) => (
                  <tr key={`${a.client}-${a.mode}-${i}`}>
                    <td>{a.client}</td>
                    <td className="id">{a.version}</td>
                    <td>{a.mode}</td>
                    <td>
                      <ResultMark result={a.result} />
                    </td>
                    <td>{a.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Sec>

      <Sec no={`${CH.n}.7`} id="hostile" title="Hostile fixtures">
        <p>Deliberately malicious MCP servers and requests, each with the behaviour the Gateway must show.</p>
        {s.hostile.length === 0 ? (
          <p className="empty-state">Not yet run. No hostile-fixture results have been reported.</p>
        ) : (
          <div className="table-wrap wide">
            <table>
              <caption>
                {s.hostile.filter((h) => h.pass).length} of {s.hostile.length} fixtures behaved as expected.
              </caption>
              <thead>
                <tr>
                  <th scope="col">Fixture</th>
                  <th scope="col">Attack</th>
                  <th scope="col">Expected</th>
                  <th scope="col">Observed</th>
                  <th scope="col">Result</th>
                </tr>
              </thead>
              <tbody>
                {s.hostile.map((h, i) => (
                  <tr key={`${h.fixture}-${i}`}>
                    <td className="id">{h.fixture}</td>
                    <td>{h.attack}</td>
                    <td>{h.expected}</td>
                    <td>{h.observed}</td>
                    <td>
                      <ResultMark result={h.pass ? "pass" : "fail"} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Sec>
    </article>
  );
}

function ResultMark({ result }: { result: "pass" | "fail" | "not-run" }) {
  if (result === "pass") return <ReqBadge status="verified" text="pass" />;
  if (result === "fail") return <ReqBadge status="failing" text="fail" />;
  return <ReqBadge status="unverified" text="not run" />;
}
