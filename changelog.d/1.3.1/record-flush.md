### Fixed

- **The record outbox drains under the NA's rate limit.** `flushRecords` sent
  observations 100 at a time and retried a `429` unchanged, so with
  `NA_RATE_LIMIT_OBSERVATIONS_PER_MINUTE` below 100 the backlog never drained
  and break-glass records waited behind it. Batches now halve after each
  `429`, nothing is sent until the NA's `Retry-After` has passed (unless
  `ignoreBackoff`), and break-glass records go first.
- **`flushPending` never answers with a partial run.** A call made while a
  governed action was draining the records its own record chains from got
  that drain's result, and every other pending record was left untried; a
  call asking for `ignoreBackoff` during a run that kept backoff got that
  run's result too. A call now joins a run only when it tries everything the
  call asks for, and otherwise starts its own once that one ends. The same
  holds for `flushRecords`.
- A record that failed with a `Retry-After` is retried no earlier than it
  asks (at most 15 minutes), in both outboxes.

### Changed

- `GenesisMeshError.retryAfterSeconds` holds the response's `Retry-After`
  (seconds; null without one). New export `nextAttemptAt`.
