import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The documentation the package ships marks no released feature "*Unreleased.*" (scripts/release-docs.mjs). */
const root = fileURLToPath(new URL('..', import.meta.url));
const version = readFileSync(join(root, 'VERSION'), 'utf8').trim();

function run(script: string, args: string[], env: Record<string, string>) {
  const { GITHUB_HEAD_REF: _ref, RELEASE_TAG: _tag, ...base } = process.env;
  return spawnSync(process.execPath, [join(root, 'scripts', script), ...args], {
    cwd: root, encoding: 'utf8', env: { ...base, ...env },
  });
}

describe('release documentation', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'gm-release-docs-'));
    mkdirSync(join(dir, 'docs', 'guides'), { recursive: true });
    writeFileSync(join(dir, 'README.md'), '# SDK\r\n\r\nSee the guides.\r\n');
    writeFileSync(join(dir, 'docs', 'grants.md'), '# Grants\n\nFrom 1.6.0 the NA issues grants.\n');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('passes documentation without a marker', () => {
    const result = run('release-docs.mjs', [dir], {});
    expect(result.status).toBe(0);
  });

  it.each([
    ['README.md', '# SDK\r\n\r\n### Grants\r\n\r\n*Unreleased.*\r\n', 'README.md:5'],
    ['docs/guides/new.md', '# New\n\n_Unreleased: ships in 1.8.0._\n', 'docs/guides/new.md:3'],
  ])('refuses a marker in %s', (file, text, where) => {
    writeFileSync(join(dir, file), text);
    const result = run('release-docs.mjs', [dir], {});
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(where);
  });

  it('holds no marker in the documentation this repository ships', () => {
    const result = run('release-docs.mjs', [], {});
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
  });

  it('runs in a release: the publish tag and a release branch', () => {
    const releases: Record<string, string>[] = [{ RELEASE_TAG: `v${version}` }, { GITHUB_HEAD_REF: `release/${version}` }];
    for (const env of releases) {
      const result = run('check-version.mjs', [], env);
      expect({ env, status: result.status, stderr: result.stderr }).toEqual({ env, status: 0, stderr: '' });
    }
  });
});
