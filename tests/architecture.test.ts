import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

/**
 * The layer rule of docs/architecture.md, enforced on every import and re-export in src/
 * (type-only ones included): a module may import from its own layer or a lower one, never
 * a higher one; the runtime imports (type-only ones excluded) have no cycle; and src/
 * imports nothing but its own modules and Node built-ins (no runtime dependencies).
 *
 * Today's exceptions are listed in ALLOWED_UPWARD_IMPORTS. The list may only shrink: the
 * test fails on an upward import it does not list, and on a listed one that no longer
 * exists (delete its line). A new src/ file fails until it is given a layer below.
 */
const LAYERS: readonly (readonly [string, readonly string[]])[] = [
  // Pure declarations, errors, strict JSON, signing primitives, metadata guards and the
  // generated registry: no protocol logic, no HTTP.
  ['leaf', ['types.ts', 'errors.ts', 'strict-json.ts', 'auth.ts', 'metadata.ts', 'canonical-registry.ts']],
  // Canonical forms, validation, signing and offline verification of protocol records; outboxes. No HTTP.
  ['protocol', [
    'canonical.ts', 'strict.ts', 'validation.ts', 'execution.ts', 'data_intent.ts', 'out-of-band.ts',
    'remediation.ts', 'grants.ts', 'key-history.ts', 'anchors.ts', 'verify.ts', 'audit-pack.ts', 'outbox.ts',
  ]],
  // HTTP transport and the sub-clients, one per NA route group.
  ['transport', [
    'client.ts', 'agreement.ts', 'attestation.ts', 'boundary.ts', 'consensus.ts', 'data_usage.ts',
    'disclosure.ts', 'evidence.ts', 'health.ts', 'network_authority.ts', 'policy.ts', 'grants-client.ts',
    'evidence_store.ts',
  ]],
  // Flows that compose sub-clients, the recorder and the verifier.
  ['orchestration', ['governance.ts', 'grant-holder.ts']],
  // The package entry: GenesisMeshClient and every public export.
  ['entry', ['index.ts']],
];

/** Upward imports that exist today, as "from -> to". Remove a line when its import goes; never add one. */
const ALLOWED_UPWARD_IMPORTS: readonly string[] = [
  // The generated registry names its type, declared in strict.ts (type-only).
  'canonical-registry.ts -> strict.ts',
];

const SRC = fileURLToPath(new URL('../src/', import.meta.url));
const rank = new Map(LAYERS.flatMap(([, files], i) => files.map(file => [file, i] as const)));
const layerOf = (file: string) => LAYERS[rank.get(file)!][0];

interface Edge { from: string; to: string; typeOnly: boolean }

/** Every import and re-export of each src/ file: relative ones as edges, others as specifiers. */
function scan(): { files: string[]; edges: Edge[]; external: string[] } {
  const files = readdirSync(SRC).filter(name => name.endsWith('.ts')).sort();
  const edges: Edge[] = [];
  const external: string[] = [];
  for (const file of files) {
    const source = ts.createSourceFile(file, readFileSync(SRC + file, 'utf8'), ts.ScriptTarget.ES2022, true);
    const visit = (node: ts.Node): void => {
      let specifier: ts.Expression | undefined;
      let typeOnly = false;
      if (ts.isImportDeclaration(node)) {
        specifier = node.moduleSpecifier;
        const clause = node.importClause;
        typeOnly = !!clause && (clause.isTypeOnly || (!clause.name && !!clause.namedBindings
          && ts.isNamedImports(clause.namedBindings) && clause.namedBindings.elements.length > 0
          && clause.namedBindings.elements.every(element => element.isTypeOnly)));
      } else if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
        specifier = node.moduleSpecifier;
        typeOnly = node.isTypeOnly || (!!node.exportClause && ts.isNamedExports(node.exportClause)
          && node.exportClause.elements.length > 0 && node.exportClause.elements.every(element => element.isTypeOnly));
      } else if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword
        || (ts.isIdentifier(node.expression) && node.expression.text === 'require'))) {
        specifier = node.arguments[0];
      } else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument)) {
        specifier = node.argument.literal;
        typeOnly = true;
      }
      if (specifier) {
        if (!ts.isStringLiteral(specifier)) throw new Error(`${file}: a non-literal import`);
        const target = specifier.text;
        if (target.startsWith('./')) edges.push({ from: file, to: target.slice(2).replace(/\.js$/, '.ts'), typeOnly });
        else external.push(`${file}: ${target}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return { files, edges, external };
}

/** The strongly connected components with more than one module (Tarjan). */
function cycles(edges: readonly Edge[]): string[][] {
  const next = new Map<string, Set<string>>();
  for (const { from, to } of edges) {
    if (!next.has(from)) next.set(from, new Set());
    next.get(from)!.add(to);
  }
  const index = new Map<string, number>();
  const low = new Map<string, number>();
  const stack: string[] = [];
  const onStack = new Set<string>();
  const found: string[][] = [];
  const connect = (node: string): void => {
    index.set(node, index.size);
    low.set(node, index.get(node)!);
    stack.push(node);
    onStack.add(node);
    for (const target of next.get(node) ?? []) {
      if (!index.has(target)) {
        connect(target);
        low.set(node, Math.min(low.get(node)!, low.get(target)!));
      } else if (onStack.has(target)) {
        low.set(node, Math.min(low.get(node)!, index.get(target)!));
      }
    }
    if (low.get(node) === index.get(node)) {
      const component: string[] = [];
      let member: string;
      do {
        member = stack.pop()!;
        onStack.delete(member);
        component.push(member);
      } while (member !== node);
      if (component.length > 1) found.push(component.sort());
    }
  };
  for (const node of [...next.keys()].sort()) if (!index.has(node)) connect(node);
  return found;
}

describe('architecture', () => {
  const { files, edges, external } = scan();

  it('gives every src/ module exactly one layer', () => {
    const listed = LAYERS.flatMap(([, layerFiles]) => layerFiles);
    expect(new Set(listed).size).toBe(listed.length);
    expect(files.filter(file => !rank.has(file))).toEqual([]);
    expect(listed.filter(file => !files.includes(file))).toEqual([]);
  });

  it('imports only its own modules and Node built-ins (no runtime dependencies)', () => {
    expect(external.filter(entry => !/: node:[\w/]+$/.test(entry))).toEqual([]);
  });

  it('imports nothing from a higher layer, beyond the shrinking allowlist', () => {
    const upward = [...new Set(edges
      .filter(({ from, to }) => rank.get(to)! > rank.get(from)!)
      .map(({ from, to }) => `${from} -> ${to}`))].sort();
    const describe = (edge: string) => {
      const [from, to] = edge.split(' -> ');
      return `${edge} (${layerOf(from)} -> ${layerOf(to)})`;
    };
    // A new upward import: move the shared code down a layer instead of listing it.
    expect(upward.filter(edge => !ALLOWED_UPWARD_IMPORTS.includes(edge)).map(describe)).toEqual([]);
    // A listed import that is gone: delete its line from ALLOWED_UPWARD_IMPORTS.
    expect(ALLOWED_UPWARD_IMPORTS.filter(edge => !upward.includes(edge))).toEqual([]);
  });

  it('has no runtime import cycle', () => {
    expect(cycles(edges.filter(edge => !edge.typeOnly))).toEqual([]);
  });

  it('finds the imports it checks', () => {
    // The scan itself: a known runtime edge, a known type-only edge, and a cycle on a sample graph.
    expect(edges).toContainEqual({ from: 'verify.ts', to: 'auth.ts', typeOnly: false });
    expect(edges).toContainEqual({ from: 'canonical-registry.ts', to: 'strict.ts', typeOnly: true });
    expect(external).toContain('auth.ts: node:crypto');
    expect(cycles([
      { from: 'a', to: 'b', typeOnly: false }, { from: 'b', to: 'c', typeOnly: false },
      { from: 'c', to: 'a', typeOnly: false }, { from: 'c', to: 'd', typeOnly: false },
    ])).toEqual([['a', 'b', 'c']]);
  });
});
