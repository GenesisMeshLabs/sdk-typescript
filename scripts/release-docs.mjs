/**
 * The documentation the npm package ships (README.md and docs/) must not mark a
 * released feature "*Unreleased.*". A page for a feature still in development may
 * carry the marker; the release removes it. check-version.mjs runs this check in a
 * release: on a `release/<version>` pull request and when the publish workflow
 * checks a tag.
 *
 *   node scripts/release-docs.mjs [root]
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** An italic "Unreleased" marker, such as `*Unreleased.*` or `_Unreleased_`. */
const MARKER = /(\*|_)Unreleased\b[^*_\n]*\1/i;

function markdownFiles(path) {
  if (!existsSync(path)) return [];
  if (!statSync(path).isDirectory()) return path.endsWith('.md') ? [path] : [];
  return readdirSync(path).sort().flatMap(name => markdownFiles(join(path, name)));
}

/** Each line of the shipped documentation under `root` that carries an "Unreleased" marker. */
export function unreleasedMarkers(root) {
  return [join(root, 'README.md'), ...markdownFiles(join(root, 'docs'))]
    .filter(file => existsSync(file))
    .flatMap(file => readFileSync(file, 'utf8').split(/\r?\n/)
      .map((text, i) => ({ file: relative(root, file).replace(/\\/g, '/'), line: i + 1, text }))
      .filter(({ text }) => MARKER.test(text)));
}

/** Throw when the shipped documentation under `root` still marks something unreleased. */
export function checkReleaseDocs(root) {
  const found = unreleasedMarkers(root);
  for (const { file, line, text } of found) console.error(`${file}:${line}: ${text.trim()}`);
  if (found.length > 0) {
    throw new Error('the shipped documentation marks a feature "Unreleased": remove the marker before the release');
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(process.argv[2] ?? join(fileURLToPath(import.meta.url), '..', '..'));
  try {
    checkReleaseDocs(root);
    console.log('The shipped documentation carries no "Unreleased" marker.');
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
