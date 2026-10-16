import { afterAll } from '@jest/globals';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Conformance receipts (contract bundle, schema gm.contract.receipt/1). With
 * GM_CONFORMANCE_RECEIPTS set to a directory, a runner of a core conformance suite writes
 * `<dir>/<suite>.<runner-slug>.json` after its vectors ran: how many vectors of each kind it
 * ran, and how many it does not run by design (`not_run`, such as the NA-only kinds).
 * `gm_contract.py receipt-check` compares them with the pinned bundle: a required kind run
 * short, or a kind neither run nor declared not run, fails. Unset, nothing is written.
 *
 * A vector counts as run only once its assertions passed, so a failing or filtered-out
 * vector is unaccounted for rather than reported.
 */
export interface Receipt {
  /** Record a vector whose assertions passed (call it last in the vector's test). */
  ran(vector: object): void;
  /** Record a vector this runner does not run by design. */
  notRun(vector: object): void;
}

/** Vectors without a `kind` count under "*". */
function kindOf(vector: object): string {
  const kind = (vector as { kind?: unknown }).kind;
  return typeof kind === 'string' ? kind : '*';
}

/**
 * The receipt of one runner: `suite` is the suite name, read from
 * tests/fixtures/conformance/<suite>.json; `slug` names the runner in the file name (its
 * test file); `runner` says where it is. Call it in the runner's `describe`: it writes the
 * receipt after the runner's tests.
 */
export function conformanceReceipt(suite: string, slug: string, runner: string): Receipt {
  const run: Record<string, number> = {};
  const notRun: Record<string, number> = {};
  const count = (into: Record<string, number>) => (vector: object) => {
    into[kindOf(vector)] = (into[kindOf(vector)] ?? 0) + 1;
  };
  afterAll(() => {
    const dir = process.env.GM_CONFORMANCE_RECEIPTS;
    if (!dir) return;
    mkdirSync(dir, { recursive: true });
    const receipt = {
      schema: 'gm.contract.receipt/1',
      suite,
      file: `tests/fixtures/conformance/${suite}.json`,
      runner,
      run,
      not_run: notRun,
    };
    writeFileSync(join(dir, `${suite}.${slug}.json`), `${JSON.stringify(receipt, null, 2)}\n`);
  });
  return { ran: count(run), notRun: count(notRun) };
}
