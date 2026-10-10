### Fixed

- **Observations and break-glass records pass the NA's own metadata guard
  before they are signed.** The SDK sized their metadata as UTF-8, left the
  justification out of the total, skipped `actor`, `source_event_id` and
  `version_id`, and counted the justification in UTF-16 units. A record the NA
  then refused was dead-lettered after its action had run: 3000 `é` in
  metadata, a context near 16 KiB plus a justification, or a justification of
  under 1024 characters ending in emoji (of which no record was kept at all).
  `metadataProblem` is now the reference's `metadata_problem`: escaped JSON,
  the same fields and order, characters counted as the NA counts them, and a
  refused justification named as `justification` rather than
  `outcome_detail`.
- **String times are signed in the form the NA writes.** `changed_at`,
  `changed_not_before`, `changed_not_after`, `observed_at` and `executed_at`
  given as strings were signed exactly as passed, so the documented
  `changed_at: event.time` with `toISOString()` output (`.573Z`), `+00:00` or a
  seven-digit fraction was refused as `observation_malformed`, and the SDK's
  own `verifyOutOfBandRecord` refused it too. Any ISO 8601 time with a UTC
  offset is now converted to UTC microseconds (`...00.573000Z`); a string
  without an offset, or that is not a time, is refused before signing.
- **A repeated reconciliation scan is a duplicate, not a conflict.**
  `observationFromFinding` records got a random `observation_id`, so signing a
  finding again was refused as `observation_conflict` and dead-lettered. The
  recorder now derives the default ID from the source event:
  `observationId(observer, source, source_event_id)`, the SHA-256 in hex of
  the three joined by NUL characters. Give your own IDs the same way.
- `governedAction` with `breakGlass` checks the record as it will be signed
  before evaluating or running anything, with room for the action's report as
  the NA sizes it, so a record can always be kept once the action has run.
- A change window is ordered to the microsecond, as the NA orders it.

### Changed

- The default `observation_id` is derived from the source event instead of a
  random UUID. A second record of one source event with other fields (a later
  `observed_at`) is refused as `observation_conflict`, as before; take
  `observed_at` from your first record when you read an event again.
- New exports: `metadataProblem`, `observationId`.
