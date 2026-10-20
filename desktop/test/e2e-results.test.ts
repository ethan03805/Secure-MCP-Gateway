// The end-to-end results module (e2e/results.mjs): the files it writes are
// the format `go run ./tools/reqreport cargo` reads (FR-12.10).
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

type ResultsT = {
  begin(name: string): void;
  ok(m: string): void;
  fail(m: string): void;
  write(): boolean;
  failures: number;
};
const { Results } = (await import(new URL("../e2e/results.mjs", import.meta.url).href)) as {
  Results: new (prefix: string, tests: Record<string, string[]>) => ResultsT;
};

test("results: passed, failed and unstarted tests with their claims", () => {
  const dir = mkdtempSync(join(tmpdir(), "e2e-results-"));
  const out = join(dir, "results.txt");
  const claims = join(dir, "claims.tsv");
  process.env.SMCP_E2E_RESULTS = out;
  process.env.SMCP_CLAIMS_FILE = claims;
  try {
    const r = new Results("e2e::test", { a: ["FR-20.6", "SR-2.8-5"], b: ["FR-20.28"], c: ["FR-20.10"] });
    r.begin("a");
    r.ok("fine");
    r.begin("b");
    r.fail("broken");
    assert.throws(() => r.begin("undeclared"));
    assert.equal(r.write(), false);
    assert.deepEqual(readFileSync(out, "utf8").trim().split("\n"), [
      "test e2e::test::a ... ok",
      "test e2e::test::b ... FAILED",
      "test e2e::test::c ... FAILED",
    ]);
    assert.deepEqual(readFileSync(claims, "utf8").trim().split("\n"), [
      "e2e::test::a\tPARTIAL\tFR-20.6 SR-2.8-5",
      "e2e::test::b\tPARTIAL\tFR-20.28",
      "e2e::test::c\tPARTIAL\tFR-20.10",
    ]);
  } finally {
    delete process.env.SMCP_E2E_RESULTS;
    delete process.env.SMCP_CLAIMS_FILE;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("results: all passed", () => {
  const r = new Results("e2e::test", { a: ["FR-20.6"] });
  r.begin("a");
  r.ok("fine");
  assert.equal(r.write(), true);
});
