import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const localPython = fileURLToPath(new URL(process.platform === 'win32'
  ? '../../genesismesh/.venv/Scripts/python.exe'
  : '../../genesismesh/.venv/bin/python', import.meta.url));
const python = process.env.GM_E2E_PYTHON ?? (existsSync(localPython) ? localPython : undefined);
if (!python && !process.env.GM_E2E_BASE_URL) {
  throw new Error('Set GM_E2E_PYTHON to a Python interpreter with the Genesis Mesh core installed.');
}
const child = spawn(process.execPath, ['--experimental-vm-modules', 'node_modules/jest/bin/jest.js',
  '--config', 'jest.config.cjs', '--runInBand', '--testPathPatterns=e2e(-ha)?\\.test\\.ts'], {
  stdio: 'inherit', env: { ...process.env, ...(python ? { GM_E2E_PYTHON: python } : {}) },
});
child.on('error', error => { console.error(error.message); process.exitCode = 1; });
child.on('exit', code => { process.exitCode = code ?? 1; });
