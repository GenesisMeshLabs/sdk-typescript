import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const releaseVersion = readFileSync(resolve(root, 'VERSION'), 'utf8').trim();
const packageJson = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const packageLock = JSON.parse(readFileSync(resolve(root, 'package-lock.json'), 'utf8'));

const versions = new Map([
  ['VERSION', releaseVersion],
  ['package.json', packageJson.version],
  ['package-lock.json', packageLock.version],
  ['package-lock.json root package', packageLock.packages[''].version],
]);

if (new Set(versions.values()).size !== 1) {
  for (const [source, version] of versions) console.error(`${source}: ${version}`);
  throw new Error('TypeScript SDK version sources do not match');
}

const releaseTag = process.env.RELEASE_TAG;
if (releaseTag && releaseTag.replace(/^v/, '') !== releaseVersion) {
  throw new Error(`release tag ${releaseTag} does not match package version ${releaseVersion}`);
}

console.log(`TypeScript SDK release version verified: ${releaseVersion}`);
