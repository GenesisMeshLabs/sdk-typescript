/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: { '^(\\.{1,2}/.*)\\.js$': '$1' },
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: {
          isolatedModules: true,
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          strict: true,
          esModuleInterop: true,
          skipLibCheck: true,
        },
      },
    ],
  },
  testMatch: ['**/tests/**/*.test.ts'],
  // `npm run test:coverage` (CI): floors at the coverage measured when they were set (2026-10-16,
  // rounded down to a whole percent). Raise a floor when coverage rises; never lower one.
  // The critical files have their own floors; `global` covers the other src/ files.
  collectCoverageFrom: ['src/**/*.ts'],
  coverageReporters: ['text', 'text-summary'],
  coverageThreshold: {
    global: { statements: 94, branches: 86, functions: 97, lines: 95 },
    './src/verify.ts': { statements: 93, branches: 87, functions: 97, lines: 94 },
    './src/audit-pack.ts': { statements: 87, branches: 78, functions: 91, lines: 91 },
    './src/grants.ts': { statements: 95, branches: 92, functions: 100, lines: 98 },
    './src/strict-json.ts': { statements: 97, branches: 94, functions: 100, lines: 99 },
    './src/canonical.ts': { statements: 100, branches: 90, functions: 100, lines: 100 },
  },
};
