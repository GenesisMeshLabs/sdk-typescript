/**
 * Finish the CommonJS build in dist/cjs: mark the directory CommonJS, and turn the
 * declarations tsc wrote next to the JavaScript into `.d.cts` files, the CommonJS
 * declarations `require` resolves through the package's `exports` (`./x.js` imports
 * become `./x.cjs`, which TypeScript resolves to `./x.d.cts`). The JavaScript is unchanged.
 */
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const dir = new URL('../dist/cjs/', import.meta.url);
writeFileSync(new URL('package.json', dir), '{"type":"commonjs"}\n');

const relative = /((?:from|import)\s*\(?\s*)(['"])(\.{1,2}\/[^'"]*?)\.js\2/g;
let count = 0;
for (const name of readdirSync(dir)) {
  if (!name.endsWith('.d.ts')) continue;
  const source = new URL(name, dir);
  const text = readFileSync(source, 'utf8').replace(relative, '$1$2$3.cjs$2');
  writeFileSync(new URL(name.replace(/\.d\.ts$/, '.d.cts'), dir), text);
  rmSync(source);
  count += 1;
}
if (count === 0) throw new Error('dist/cjs holds no declarations: is declaration on in tsconfig.cjs.json?');
