// Results and requirement claims of the desktop end-to-end tests (SRS
// FR-12.10). Each check belongs to a named test that claims requirements,
// declared up front so a test that never ran (the run stopped earlier)
// still reports as failed. write() produces the two files
// `go run ./tools/reqreport cargo` reads for the Rust tests:
//
//   SMCP_E2E_RESULTS  "test <name> ... ok|FAILED" lines
//   SMCP_CLAIMS_FILE  "<name>\tPARTIAL\t<ids>" lines
//
// so the CI status job counts them like the other claims.
import fs from "node:fs";

export class Results {
  /** @param {string} prefix test name prefix, e.g. "e2e::linux" @param {Record<string, string[]>} tests name -> requirement IDs */
  constructor(prefix, tests) {
    this.prefix = prefix;
    /** @type {Map<string, { ids: string[], started: boolean, failed: boolean }>} */
    this.tests = new Map(Object.entries(tests).map(([n, ids]) => [n, { ids, started: false, failed: false }]));
    /** @type {string | null} */
    this.current = null;
    this.failures = 0;
  }

  /** Starts the named test; the checks after it belong to it. @param {string} name */
  begin(name) {
    const t = this.tests.get(name);
    if (!t) throw new Error(`undeclared test ${name}`);
    t.started = true;
    this.current = name;
  }

  /** @param {string} m */
  ok(m) {
    console.log(`ok   ${m}`);
  }

  /** @param {string} m */
  fail(m) {
    this.failures++;
    console.log(`FAIL ${m}`);
    const t = this.current && this.tests.get(this.current);
    if (t) t.failed = true;
  }

  /** Writes the result and claim files named by the environment, if any. */
  write() {
    const out = process.env.SMCP_E2E_RESULTS;
    const claims = process.env.SMCP_CLAIMS_FILE;
    const lines = [];
    const claimLines = [];
    for (const [name, t] of this.tests) {
      const full = `${this.prefix}::${name}`;
      const passed = t.started && !t.failed;
      lines.push(`test ${full} ... ${passed ? "ok" : "FAILED"}`);
      claimLines.push(`${full}\tPARTIAL\t${t.ids.join(" ")}`);
      if (!t.started) console.log(`FAIL ${full}: did not run`);
    }
    if (out) fs.appendFileSync(out, lines.join("\n") + "\n");
    if (claims) fs.appendFileSync(claims, claimLines.join("\n") + "\n");
    return [...this.tests.values()].every((t) => t.started && !t.failed) && this.failures === 0;
  }
}
