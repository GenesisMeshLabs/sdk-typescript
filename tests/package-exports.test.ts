import { readFileSync } from 'node:fs';

/**
 * The package's `exports` map, as TypeScript and Node read it. TypeScript takes the first
 * condition that matches, so `types` must come first in each one; a CommonJS consumer needs
 * CommonJS declarations (`.d.cts`), or the types say ESM while `require` loads CommonJS.
 * `npm run check:types` (arethetypeswrong on the packed tarball) checks the built package.
 */
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
  exports: Record<string, Record<string, unknown>>;
};

describe('package exports', () => {
  const conditions = Object.entries(pkg.exports).flatMap(([subpath, entry]) =>
    Object.entries(entry).map(([condition, target]) => ({ subpath, condition, target })));

  it('nests every import and require condition with types first', () => {
    expect(conditions.map(c => c.condition).sort()).toEqual(['import', 'require']);
    for (const { subpath, condition, target } of conditions) {
      expect({ subpath, condition, keys: Object.keys(target as object) })
        .toEqual({ subpath, condition, keys: ['types', 'default'] });
    }
  });

  it('gives require CommonJS declarations and import ESM declarations', () => {
    const entry = pkg.exports['.']!;
    expect(entry['import']).toEqual({ types: './dist/types/index.d.ts', default: './dist/esm/index.js' });
    expect(entry['require']).toEqual({ types: './dist/cjs/index.d.cts', default: './dist/cjs/index.js' });
  });
});
