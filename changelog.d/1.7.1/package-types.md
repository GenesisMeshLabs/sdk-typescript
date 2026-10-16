### Fixed

- **TypeScript resolves the package's types through the right condition, for
  ESM and CommonJS.** The `exports` map listed `types` after `import` and
  `require`, so TypeScript found the declarations only through a fallback
  (a TypeScript bug the compiler may stop honouring), and a CommonJS
  consumer got ESM declarations for a CommonJS module. Each condition now
  names its declarations first, and `require` gets CommonJS declarations
  (`dist/cjs/*.d.cts`). The JavaScript, the entry points and the ESM
  declarations are unchanged. `npm run check:types` runs arethetypeswrong on
  the packed tarball (node10, node16 from CJS and ESM, bundler).
