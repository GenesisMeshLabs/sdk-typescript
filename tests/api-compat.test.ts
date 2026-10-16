import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * scripts/api-compat.mjs: what counts as an incompatible change to the API report, and the
 * pull request gate (workflow "API compatibility"): an incompatible change the pull request
 * introduces needs the `breaking` label and a changelog fragment with `### Upgrading`.
 */
const root = fileURLToPath(new URL('..', import.meta.url));
const script = join(root, 'scripts', 'api-compat.mjs');

const report = (body: string) => [
  '## API Report File for "genesis-mesh-sdk"', '', '```ts', '', body.trim(), '', '```', '',
].join('\n');

const BASE = report(`
// @public
export interface GetParams {
    // (undocumented)
    id: string;
    limit?: number;
}

// @public
export interface Record_ {
    // (undocumented)
    id: string;
}

// @public
export type Kind = 'a' | 'b';

// @public
export function fetchIt(id: string, options?: GetParams): Promise<Record_>;

// @public
export class Client {
    constructor(http: string);
    get(id: string): Promise<Record_>;
    readonly name: string;
}

// @public
type Event_2 = 'x' | 'y';
export { Event_2 as Event }
`);

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'gm-api-compat-')); });
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function file(name: string, text: string): string {
  const path = join(dir, name);
  writeFileSync(path, text);
  return path;
}

function run(args: string[], env: Record<string, string> = {}) {
  const { EVENT: _e, BREAKING: _b, BASE_SHA: _bs, HEAD_SHA: _hs, ...base } = process.env;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env: { ...base, ...env } });
}

function compare(after: string) {
  const result = run(['compare', file('old.api.md', BASE), file('new.api.md', report(after)), '--json']);
  const out = JSON.parse(result.stdout) as { incompatible: { key: string; change: string }[]; review: { key: string }[] };
  return { status: result.status, incompatible: out.incompatible.map(f => `${f.key}: ${f.change}`), review: out.review.map(f => f.key) };
}

/** BASE with one replacement. */
const edit = (from: string, to: string) => {
  const body = /```ts\n([\s\S]*?)\n```/.exec(BASE)![1]!;
  expect(body).toContain(from);
  return body.replace(from, to);
};

describe('API report comparison', () => {
  it('finds no change in the same report, and parses the committed report', () => {
    expect(compare(/```ts\n([\s\S]*?)\n```/.exec(BASE)![1]!)).toEqual({ status: 0, incompatible: [], review: [] });
    const committed = join(root, 'etc', 'genesis-mesh-sdk.api.md');
    expect(run(['compare', committed, committed]).status).toBe(0);
  });

  it('accepts additions: a new export, an optional member, a widened union, a trailing optional parameter', () => {
    let after = edit("export type Kind = 'a' | 'b';", "export type Kind = 'a' | 'b' | 'c';\n\n// @public\nexport const LIMIT = 5;");
    after = after.replace('    limit?: number;', '    limit?: number;\n    cursor?: string;');
    after = after.replace('get(id: string): Promise<Record_>;', 'get(id: string, signal?: AbortSignal): Promise<Record_>;');
    after = after.replace("type Event_2 = 'x' | 'y';", "type Event_2 = 'x' | 'y' | 'z';");
    expect(compare(after)).toEqual({ status: 0, incompatible: [], review: [] });
  });

  it('reads a union derived from a literal tuple as that union', () => {
    // `EntryKind = (typeof ENTRY_KINDS)[number]` names the same kinds as the union it replaced.
    const derived = "// @public\nconst KINDS: readonly [\"b\", \"a\", \"c\"];\n\n// @public\nexport type Kind = (typeof KINDS)[number];";
    expect(compare(edit("// @public\nexport type Kind = 'a' | 'b';", derived)).incompatible).toEqual([]);
    const narrowed = derived.replace('"b", "a", "c"', '"b"');
    expect(compare(edit("// @public\nexport type Kind = 'a' | 'b';", narrowed)).incompatible).toEqual(['Kind: changed']);
  });

  it('lists a new required member of an output type for review, not as incompatible', () => {
    const after = edit('export interface Record_ {\n    // (undocumented)\n    id: string;',
      'export interface Record_ {\n    // (undocumented)\n    id: string;\n    created_at: string;');
    expect(compare(after)).toEqual({ status: 0, incompatible: [], review: ['Record_.created_at'] });
  });

  it.each([
    ['a removed export', edit("// @public\nexport type Kind = 'a' | 'b';\n", ''), ['Kind: removed']],
    ['a narrowed union', edit("'a' | 'b'", "'a'"), ['Kind: changed']],
    ['a removed member', edit('    readonly name: string;\n', ''), ['Client.name: member removed']],
    ['a changed member type', edit('    id: string;\n    limit?', '    id: number;\n    limit?'), ['GetParams.id: member changed']],
    ['an optional member made required', edit('limit?: number', 'limit: number'), ['GetParams.limit: member changed']],
    ['a new required parameter', edit('fetchIt(id: string, options?: GetParams)', 'fetchIt(id: string, mode: string, options?: GetParams)'),
      ['fetchIt: signature changed']],
    ['a new required member of an input type', edit('    limit?: number;', '    limit?: number;\n    tenant: string;'),
      ['GetParams.tenant: new required member of an input type']],
    ['an export made internal', edit('export class Client {', 'class Client {'), ['Client: no longer exported']],
    ['a narrowed re-exported alias', edit("type Event_2 = 'x' | 'y';", "type Event_2 = 'x';"), ['Event: changed']],
  ])('flags %s', (_name, after, expected) => {
    const result = compare(after);
    expect(result.status).toBe(1);
    expect(result.incompatible).toEqual(expected);
  });
});

describe('API compatibility gate (check)', () => {
  const removed = edit("// @public\nexport type Kind = 'a' | 'b';\n", '');
  const gate = (opts: { base?: string | null; head: string; fragments?: string[]; env?: Record<string, string> }) => {
    const args = ['check', '--release', file('release.api.md', BASE), '--head', file('head.api.md', report(opts.head))];
    if (opts.base !== null) args.push('--base', file('base.api.md', report(opts.base ?? /```ts\n([\s\S]*?)\n```/.exec(BASE)![1]!)));
    args.push('--fragments', (opts.fragments ?? []).join(','));
    return run(args, { EVENT: 'pull_request', ...opts.env });
  };

  it('passes a pull request without an incompatible change', () => {
    const result = gate({ head: edit("'a' | 'b'", "'a' | 'b' | 'c'") });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no incompatible change');
  });

  it('fails an incompatible change without the label and an Upgrading note', () => {
    const result = gate({ head: removed });
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('Kind: removed');
    expect(result.stdout).toContain('the label `breaking`');
    expect(result.stdout).toContain('### Upgrading');
  });

  it('fails a labelled change whose fragments have no Upgrading section', () => {
    const fragment = file('note.md', '### Changed\n\n- **Kind is gone.**\n');
    const result = gate({ head: removed, fragments: [fragment], env: { BREAKING: 'true' } });
    expect(result.status).toBe(1);
    expect(result.stdout).not.toContain('the label `breaking`');
  });

  it('passes a labelled change with an Upgrading note', () => {
    const fragment = file('note.md', '### Removed\n\n- Kind.\n\n### Upgrading\n\n- Use the string literals.\n');
    const result = gate({ head: removed, fragments: [fragment], env: { BREAKING: 'true' } });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('Labelled breaking');
  });

  it('does not charge a pull request with a change its base already made', () => {
    expect(gate({ base: removed, head: removed }).status).toBe(0);
  });

  it('passes the pull request that introduces the report, and the merge queue', () => {
    expect(gate({ base: null, head: removed }).status).toBe(0);
    expect(gate({ head: removed, env: { EVENT: 'merge_group' } }).status).toBe(0);
  });
});
