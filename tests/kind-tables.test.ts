import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { fileURLToPath } from 'node:url';
import { ENTRY_KINDS } from '../src/canonical-registry.js';

/**
 * The verifier's kind tables (src/verify.ts) are typed against `EntryKind`, which is derived from the
 * registry's `ENTRY_KINDS`: a table that misses a kind, or a kind the registry adds, fails to compile
 * instead of skipping a check for that kind (a missing envelope map once meant no `envelope_mismatch`
 * check, a missing record-ID field the ID "undefined"). Each case compiles a copy of src/verify.ts with
 * one change and expects tsc to name the kind.
 */
const src = fileURLToPath(new URL('../src/', import.meta.url)).replace(/\\/g, '/');
const VERIFY = `${src}verify.ts`;
const REGISTRY = `${src}canonical-registry.ts`;
const options: ts.CompilerOptions = {
  target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext,
  strict: true, skipLibCheck: true, noEmit: true, isolatedModules: true, types: ['node'],
};
const read = (path: string) => readFileSync(path, 'utf8').replace(/\r\n/g, '\n');

/** tsc's errors in each of the given files (paths in src/), compiled with them and the given replacements. */
function errors(files: Record<string, string>): Record<string, string[]> {
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  const readFile = host.readFile.bind(host);
  const virtual = (name: string) => files[name.replace(/\\/g, '/')];
  host.fileExists = name => virtual(name) !== undefined || fileExists(name);
  host.readFile = name => virtual(name) ?? readFile(name);
  host.getSourceFile = (name, language, onError, create) => {
    const text = virtual(name);
    return text !== undefined ? ts.createSourceFile(name, text, language) : getSourceFile(name, language, onError, create);
  };
  const program = ts.createProgram({ rootNames: Object.keys(files), options, host });
  return Object.fromEntries(Object.keys(files).map(name => [name,
    ts.getPreEmitDiagnostics(program, program.getSourceFile(name)).map(d => ts.flattenDiagnosticMessageText(d.messageText, ' '))]));
}

/** src/verify.ts without one exact line. */
function without(line: string): string {
  const lines = read(VERIFY).split('\n');
  const at = lines.indexOf(line);
  if (at < 0 || lines.lastIndexOf(line) !== at) throw new Error(`not one line of src/verify.ts: ${line}`);
  lines.splice(at, 1);
  return lines.join('\n');
}

const REMOVALS: [table: string, line: string, kind: string][] = [
  ['PAYLOAD_CHECKS', '  grant_revocation: validGrantRevocation,', 'grant_revocation'],
  ['RECORD_ID', "  grant_revocation: 'revocation_id',", 'grant_revocation'],
  ['ENVELOPE_FIELDS', "  grant_revocation: { record_id: 'revocation_id', subject_id: 'grant_id', outcome: 'reason' },",
    'grant_revocation'],
  ['ENVELOPE_FIELDS (a kind with no envelope field)', '  execution: {},', 'execution'],
  ['PAYLOAD_MODELS', "  key_succession: 'KeySuccessionRecord',", 'key_succession'],
  ['OUT_OF_BAND_MODELS', "  archive: 'ArchiveRecord',", 'archive'],
];

describe('kind tables', () => {
  it('derive EntryKind from the registry suite', () => {
    const suite = JSON.parse(read(fileURLToPath(new URL('./fixtures/conformance/field_registry.json', import.meta.url))));
    expect([...ENTRY_KINDS]).toEqual(suite.registry.entry_kinds);
    expect(Object.isFrozen(ENTRY_KINDS)).toBe(true);
  });

  it('refuse a table without a kind, and a kind the registry adds until every table and the switch handle it', () => {
    // One program: src/verify.ts as it is, one copy per removal next to it, and one copy that reads a
    // registry with a new kind (through copies of types.ts and canonical-registry.ts).
    const copies = Object.fromEntries(REMOVALS.map(([, line], i) => [`${src}verify-without-${i}.ts`, without(line)]));
    const registry = read(REGISTRY);
    const head = 'export const ENTRY_KINDS = freeze([\n';
    expect(registry).toContain(head);
    const types = read(`${src}types.ts`);
    expect(types).toContain("from './canonical-registry.js';");
    expect(read(VERIFY)).toContain("} from './types.js';");
    const found = errors({
      [VERIFY]: read(VERIFY),
      ...copies,
      [`${src}registry-new-kind.ts`]: registry.replace(head, `${head}  "new_kind",\n`),
      [`${src}types-new-kind.ts`]: types.replace("from './canonical-registry.js';", "from './registry-new-kind.js';"),
      [`${src}verify-new-kind.ts`]: read(VERIFY).replace("} from './types.js';", "} from './types-new-kind.js';"),
    });
    expect(found[VERIFY]).toEqual([]);
    REMOVALS.forEach(([table, , kind], i) => {
      const messages = found[`${src}verify-without-${i}.ts`]!;
      expect({ table, named: messages.some(m => m.includes(`'${kind}'`)) }).toEqual({ table, named: true });
    });
    const named = found[`${src}verify-new-kind.ts`]!.filter(m => m.includes('"new_kind"') || m.includes("'new_kind'"));
    // PAYLOAD_CHECKS, RECORD_ID, ENVELOPE_FIELDS, PAYLOAD_MODELS, and the switch's `satisfies never`.
    expect(named.length).toBeGreaterThanOrEqual(5);
    expect(named.some(m => m.includes('never'))).toBe(true);
  }, 60_000);
});
