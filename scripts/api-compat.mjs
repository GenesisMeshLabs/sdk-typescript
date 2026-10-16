/**
 * Public-API compatibility against the latest release, from API Extractor reports
 * (etc/genesis-mesh-sdk.api.md; `npm run api:update` writes it, `npm run api:check`
 * fails when it is out of date, so the committed report is the reviewed API).
 *
 *   node scripts/api-compat.mjs compare <old.api.md> <new.api.md> [--json]
 *   node scripts/api-compat.mjs check [--release F] [--base F] [--head F] [--fragments F,F]
 *
 * A change is incompatible when the release's report has a declaration or member the
 * new report removes or changes, or when an input type (a name ending in Params,
 * Options, Input, Request, Submission, Init or Config) gains a required member.
 * Compatible: new declarations, new optional members, new required members of other
 * types (reported for review), a union or literal tuple that only gains members (a
 * `(typeof TUPLE)[number]` type counts as the union of the tuple), and a function or
 * method that only gains trailing optional parameters. The rules are a reviewer's aid,
 * not a type checker: the committed report's diff is what review reads.
 *
 * `check` is the pull request gate (workflow "API compatibility"). It compares the
 * release's report (`git show <tag>:etc/genesis-mesh-sdk.api.md` for the latest `v*`
 * tag, or etc/baseline/<tag>.api.md for a release made before the report existed) with
 * the base branch's and the pull request's. An incompatible change the pull request
 * introduces passes only when the pull request is labelled `breaking` (env BREAKING=true)
 * and adds or changes a changelog fragment with an `### Upgrading` section. Other events
 * (push, merge queue) print the changes and pass: the pull request was checked.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const REPORT = 'etc/genesis-mesh-sdk.api.md';
const INPUT_TYPE = /(Params|Options|Input|Request|Submission|Init|Config)(_\d+)?$/;
const DECLARATION = /^(export\s+)?(?:declare\s+)?(?:abstract\s+)?(class|interface|type|function|const|let|var|enum|namespace)\s+([A-Za-z_$][\w$]*)/;
const REEXPORT = /^export\s*\{\s*([\w$]+)(?:\s+as\s+([\w$]+))?\s*\}/;
const MODIFIERS = /^(?:(?:public|protected|private|static|readonly|abstract|declare|override)\s+)*/;

const squash = text => text.replace(/\s+/g, ' ').replace(/\s*;\s*$/, '').trim();

/** Split `text` at top-level occurrences of `separator` (outside brackets and quotes). */
function splitTop(text, separator) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
    } else if (c === '\'' || c === '"' || c === '`') quote = c;
    else if ('([{<'.includes(c)) depth++;
    else if (')]}'.includes(c) || (c === '>' && text[i - 1] !== '=')) depth--;
    else if (depth === 0 && text.startsWith(separator, i)) {
      parts.push(text.slice(start, i).trim());
      start = i + separator.length;
      i += separator.length - 1;
    }
  }
  parts.push(text.slice(start).trim());
  return parts.filter(part => part !== '');
}

/** The key of a class or interface member line: its name, with `static`, `get`, `set` and signature kinds. */
function memberKey(line) {
  const text = line.trim();
  const isStatic = /^(?:(?:public|protected|private|readonly|abstract|override)\s+)*static\s/.test(text);
  const rest = text.replace(MODIFIERS, '');
  if (rest.startsWith('[')) return `${isStatic ? 'static ' : ''}[${squash(rest.slice(1, rest.indexOf(']')).replace(/^\w+\s*:/, ''))}]`;
  if (rest.startsWith('new ') || rest.startsWith('new(')) return 'new()';
  if (rest.startsWith('(') || rest.startsWith('<')) return '()';
  const accessor = /^(get|set)\s+([\w$]+)/.exec(rest);
  if (accessor) return `${isStatic ? 'static ' : ''}${accessor[1]} ${accessor[2]}`;
  const name = /^(['"]?)([\w$-]+)\1/.exec(rest);
  return `${isStatic ? 'static ' : ''}${name ? name[2] : rest}`;
}

/**
 * The declarations of an API Extractor report: name -> { kind, exported, header, members, signatures }.
 * Top-level declarations are separated by blank lines; members of a class or interface are the lines
 * indented by four spaces (deeper lines continue the member above). Comments are ignored.
 */
export function parseReport(text) {
  const body = /```ts\r?\n([\s\S]*?)\r?\n```/.exec(text);
  if (!body) throw new Error('not an API Extractor report: no ```ts block');
  const declarations = new Map();
  for (const chunk of body[1].split(/\r?\n\s*\r?\n/)) {
    const all = chunk.split(/\r?\n/).filter(line => line.trim() !== '' && !/^\s*\/\//.test(line));
    // `type X_2 = ...` followed by `export { X_2 as X }`: the declaration is exported as X.
    const aliases = new Map();
    for (const line of all) {
      const reexport = REEXPORT.exec(line);
      if (reexport) aliases.set(reexport[1], reexport[2] ?? reexport[1]);
    }
    const lines = all.filter(line => !REEXPORT.test(line));
    if (lines.length === 0) {
      for (const [source, alias] of aliases) {
        declarations.set(alias, { kind: 'reexport', exported: true, header: `export { ${source} as ${alias} }`, members: null, signatures: [] });
      }
      continue;
    }
    const match = DECLARATION.exec(lines[0]);
    if (!match) throw new Error(`unrecognised declaration in the API report: ${lines[0]}`);
    const [, exportKeyword, kind, declared] = match;
    const name = aliases.get(declared) ?? declared;
    const exported = Boolean(exportKeyword) || aliases.has(declared);
    if (aliases.has(declared)) lines[0] = lines[0].replace(declared, name);
    const block = (kind === 'class' || kind === 'interface' || kind === 'namespace') && lines[0].trimEnd().endsWith('{');
    if (!block) {
      const existing = declarations.get(name);
      const signature = squash(lines.join(' '));
      if (existing && existing.kind === kind && kind === 'function') existing.signatures.push(signature);
      else declarations.set(name, { kind, exported, header: signature, members: null, signatures: [signature] });
      continue;
    }
    const members = new Map();
    let current = null;
    for (const line of lines.slice(1)) {
      if (/^\}/.test(line)) break;
      if (/^ {4}\S/.test(line) && !/^ {4}[}\])]/.test(line)) {
        current = memberKey(line);
        if (!members.has(current)) members.set(current, []);
        members.get(current).push(line.trim());
      } else if (current) {
        const list = members.get(current);
        list[list.length - 1] += ` ${line.trim()}`;
      }
    }
    for (const [key, list] of members) members.set(key, list.map(squash));
    declarations.set(name, { kind, exported, header: squash(lines[0]), members, signatures: [] });
  }
  // `type K = (typeof KINDS)[number]` over `const KINDS: readonly ["a", "b"]` is compared as the union 'a' | 'b'.
  for (const [name, declaration] of declarations) {
    const derived = /^((?:export\s+)?type\s+[\w$]+\s*=)\s*\(typeof\s+([\w$]+)\)\[number\]$/.exec(declaration.header);
    const tuple = derived && /:\s*readonly\s*\[(.*)\]$/.exec(declarations.get(derived[2])?.header ?? '');
    if (!tuple) continue;
    const header = `${derived[1]} ${splitTop(tuple[1], ',').map(literal).join(' | ')}`;
    declarations.set(name, { ...declaration, header, signatures: [header] });
  }
  return declarations;
}

/** A string literal type in one spelling: "a" and 'a' are the same type. */
function literal(part) {
  const quoted = /^"((?:[^"\\']|\\.)*)"$/.exec(part);
  return quoted ? `'${quoted[1]}'` : part;
}

/** A union (`A | B`) or readonly literal tuple whose members are a superset of the old one's. */
function widened(oldText, newText) {
  const parts = text => {
    const type = /^(?:export\s+)?(?:declare\s+)?(?:type\s+[\w$]+(?:<[^=]*>)?\s*=|const\s+[\w$]+\s*:)\s*(.*)$/.exec(text);
    const value = type ? type[1] : text.replace(/^[^:]*:\s*/, '');
    const tuple = /^readonly\s*\[(.*)\]$/.exec(value);
    return (tuple ? splitTop(tuple[1], ',') : splitTop(value, '|')).map(literal);
  };
  const prefix = text => text.slice(0, text.indexOf(text.includes('=') ? '=' : ':'));
  if (prefix(oldText) !== prefix(newText)) return false;
  const before = parts(oldText);
  const after = new Set(parts(newText));
  return before.length > 0 && before.every(part => after.has(part)) && after.size >= before.length;
}

/** `name<T>(a: A, b?: B): R` -> { head: 'name<T>', params: ['a: A', 'b?: B'], tail: ': R' }, or null. */
function signature(text) {
  const open = text.indexOf('(');
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0) {
      return { head: text.slice(0, open), params: splitTop(text.slice(open + 1, i), ','), tail: text.slice(i + 1) };
    }
  }
  return null;
}

/** A call signature that only gained trailing optional (or rest) parameters. */
function extendedSignature(oldText, newText) {
  const before = signature(oldText);
  const after = signature(newText);
  if (!before || !after || before.head !== after.head || before.tail !== after.tail) return false;
  if (after.params.length < before.params.length) return false;
  if (!before.params.every((param, i) => param === after.params[i])) return false;
  return after.params.slice(before.params.length).every(param => /^(\.\.\.|[\w$]+\?\s*:)/.test(param));
}

function compatibleChange(oldText, newText) {
  return widened(oldText, newText) || extendedSignature(oldText, newText);
}

/**
 * Compare two parsed reports. Returns { incompatible, review }: each finding is
 * { key, change, old, new } where key names the declaration or member.
 */
export function compare(oldReport, newReport) {
  const incompatible = [];
  const review = [];
  const flag = (list, key, change, before, after) => list.push({ key, change, old: before ?? null, new: after ?? null });
  for (const [name, before] of oldReport) {
    const after = newReport.get(name);
    if (!after) { flag(incompatible, name, 'removed', before.header); continue; }
    if (before.exported && !after.exported) { flag(incompatible, name, 'no longer exported', before.header, after.header); continue; }
    if (before.kind !== after.kind) { flag(incompatible, name, `${before.kind} became ${after.kind}`, before.header, after.header); continue; }
    if (before.members === null || after.members === null) {
      if (before.kind === 'function') {
        for (const old of before.signatures) {
          if (!after.signatures.some(sig => sig === old || extendedSignature(old, sig))) {
            flag(incompatible, name, 'signature changed', old, after.signatures.join(' / '));
          }
        }
      } else if (before.header !== after.header && !compatibleChange(before.header, after.header)) {
        flag(incompatible, name, 'changed', before.header, after.header);
      }
      continue;
    }
    if (before.header !== after.header) flag(incompatible, name, 'declaration changed', before.header, after.header);
    for (const [member, oldLines] of before.members) {
      const newLines = after.members.get(member);
      const key = `${name}.${member}`;
      if (!newLines) { flag(incompatible, key, 'member removed', oldLines.join(' / ')); continue; }
      for (const old of oldLines) {
        if (!newLines.some(line => line === old || compatibleChange(old, line))) {
          flag(incompatible, key, 'member changed', old, newLines.join(' / '));
        }
      }
    }
    if (before.kind !== 'interface') continue;
    for (const [member, newLines] of after.members) {
      if (before.members.has(member)) continue;
      const required = newLines.some(line => !/^(?:readonly\s+)?['"]?[\w$-]+['"]?\?\s*:/.test(line) && !/^\[/.test(line) && !/^[\w$]+\?\s*\(/.test(line));
      if (!required) continue;
      const key = `${name}.${member}`;
      if (INPUT_TYPE.test(name)) flag(incompatible, key, 'new required member of an input type', null, newLines.join(' / '));
      else flag(review, key, 'new required member', null, newLines.join(' / '));
    }
  }
  return { incompatible, review };
}

const identity = finding => `${finding.key}\u0000${finding.change}\u0000${finding.new}`;

function print(title, findings) {
  if (findings.length === 0) return;
  console.log(`${title} (${findings.length}):`);
  for (const f of findings) {
    console.log(`  ${f.key}: ${f.change}`);
    if (f.old !== null) console.log(`    - ${f.old}`);
    if (f.new !== null) console.log(`    + ${f.new}`);
  }
}

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function gitShow(ref, path) {
  try { return git(['show', `${ref}:${path}`]); } catch { return null; }
}

function latestReleaseTag() {
  const tags = git(['tag', '--list', 'v*', '--sort=-v:refname', '--merged', 'HEAD'])
    .split('\n').map(tag => tag.trim()).filter(tag => /^v\d+\.\d+\.\d+$/.test(tag));
  if (tags.length === 0) throw new Error('no release tag v* is reachable from HEAD (fetch with tags and full history)');
  return tags[0];
}

function releaseReport() {
  const tag = latestReleaseTag();
  const atTag = gitShow(tag, REPORT);
  if (atTag !== null) return { label: `${tag} (${REPORT})`, text: atTag };
  const baseline = join(ROOT, 'etc', 'baseline', `${tag}.api.md`);
  if (existsSync(baseline)) return { label: `${tag} (etc/baseline/${tag}.api.md)`, text: readFileSync(baseline, 'utf8') };
  throw new Error(`the release ${tag} has no ${REPORT}, and etc/baseline/${tag}.api.md does not exist: generate it from the tag`);
}

function upgradingFragments(baseSha, headSha) {
  const changed = git(['diff', '--no-renames', '--name-only', '--diff-filter=AM', `${baseSha}...${headSha}`, '--', 'changelog.d/'])
    .split('\n').map(path => path.trim()).filter(path => path.endsWith('.md') && path !== 'changelog.d/README.md');
  return changed.map(path => ({ path, text: gitShow(headSha, path) ?? '' }));
}

function options(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') opts.json = true;
    else if (arg.startsWith('--')) opts[arg.slice(2)] = argv[++i];
    else (opts._ ??= []).push(arg);
  }
  return opts;
}

function check(opts) {
  const event = process.env.EVENT ?? 'pull_request';
  const release = opts.release
    ? { label: opts.release, text: readFileSync(opts.release, 'utf8') }
    : releaseReport();
  const head = readFileSync(opts.head ?? join(ROOT, REPORT), 'utf8');
  const vsRelease = compare(parseReport(release.text), parseReport(head));
  console.log(`Public API compared with the release ${release.label}.`);
  print('Incompatible with the release', vsRelease.incompatible);
  print('Compatible, for review: new required members of output types', vsRelease.review);

  if (event !== 'pull_request') {
    console.log(`Event ${event}: the pull request was checked before it merged; passing.`);
    return 0;
  }
  const baseSha = process.env.BASE_SHA;
  const headSha = process.env.HEAD_SHA;
  let baseText = null;
  if (opts.base) baseText = readFileSync(opts.base, 'utf8');
  else if (baseSha) baseText = gitShow(baseSha, REPORT);
  if (baseText === null) {
    console.log('The base branch has no API report: this pull request introduces it; passing.');
    return 0;
  }
  const already = new Set(compare(parseReport(release.text), parseReport(baseText)).incompatible.map(identity));
  const introduced = vsRelease.incompatible.filter(finding => !already.has(identity(finding)));
  if (introduced.length === 0) {
    console.log('This pull request makes no incompatible change to the released API.');
    return 0;
  }
  print('Introduced by this pull request', introduced);
  const fragments = opts.fragments !== undefined
    ? opts.fragments.split(',').filter(Boolean).map(path => ({ path, text: readFileSync(path, 'utf8') }))
    : upgradingFragments(baseSha, headSha);
  const upgrading = fragments.filter(({ text }) => /^### Upgrading\s*$/m.test(text)).map(({ path }) => path);
  const labelled = process.env.BREAKING === 'true';
  if (labelled && upgrading.length > 0) {
    console.log(`Labelled breaking, with an Upgrading note in ${upgrading.join(', ')}: passing.`);
    return 0;
  }
  const missing = [
    labelled ? null : 'the label `breaking` (the Maintainer applies it)',
    upgrading.length > 0 ? null : 'a changelog fragment in changelog.d/<version>/ with an `### Upgrading` section saying what callers must change',
  ].filter(Boolean);
  console.log(`::error::This pull request changes the released public API incompatibly (listed above). It needs ${missing.join(' and ')}, or keep the old API (add, deprecate, remove at a major).`);
  return 1;
}

function main(argv) {
  const [command, ...rest] = argv;
  const opts = options(rest);
  if (command === 'compare') {
    const [oldPath, newPath] = opts._ ?? [];
    if (!oldPath || !newPath) throw new Error('usage: api-compat.mjs compare <old.api.md> <new.api.md> [--json]');
    const result = compare(parseReport(readFileSync(oldPath, 'utf8')), parseReport(readFileSync(newPath, 'utf8')));
    if (opts.json) console.log(JSON.stringify(result, null, 2));
    else {
      print('Incompatible', result.incompatible);
      print('Compatible, for review: new required members of output types', result.review);
      if (result.incompatible.length === 0) console.log('No incompatible change.');
    }
    return result.incompatible.length === 0 ? 0 : 1;
  }
  if (command === 'check') return check(opts);
  throw new Error('usage: api-compat.mjs compare <old> <new> [--json] | check [--release F] [--base F] [--head F] [--fragments F,F]');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(`::error::${error.message}`);
    process.exitCode = 2;
  }
}
