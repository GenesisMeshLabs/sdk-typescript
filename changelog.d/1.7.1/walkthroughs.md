### Added

- **Two walkthroughs with runnable scripts.** "A governed rotation" sets up
  a local NA with the privileged key, runs `governedAction` with the
  standard controller key and an evidence outbox (one ALLOW, one DENY), and
  verifies the export offline from the root key
  (`examples/governed-rotation.ts`). "Acting while the NA is down" issues a
  grant, uses it twice with the NA stopped, falls back to break-glass past
  its budget, and syncs when the NA is back
  (`examples/act-while-na-down.ts`). Each page has a GIF of a real run,
  with its transcript and the script that records it
  (`docs/assets/walkthroughs/`). The examples are type-checked with the
  tests, and `docs/assets/` is left out of the npm package.
