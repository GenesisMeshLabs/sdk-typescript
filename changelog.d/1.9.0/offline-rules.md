### Fixed

Where the .NET SDK reads as the references do (T2 of the parity plan):

- **`parseRfc3339`** refuses a time that falls outside the years 1 to 9999 once in UTC (`0001-01-01T00:00:00+00:01`), which it printed out of range; the reference cannot convert one (`OverflowError`).
- **A key's placement times** (`registered_at_time`, `retired_at_time`) with more than six fraction digits, as .NET's round-trip format writes them, are read to the microsecond, as the references read them; `verifyEvidenceEvents` threw for one.
- **`useProblem` throws for a time its caller gives that it cannot read** (`revokedAt`, `recordedAt`, `tokenHead.executed_at`, `previous`'s times), where it skipped the rule that time is for, so an unreadable revocation time let a use through. Seven fraction digits are read to the microsecond.
- **`checkEventsAgainstAnchors`** refuses an anchor that is not well formed, as `verifyStoreAnchors` does, so a hand-built one never counts as matched.
