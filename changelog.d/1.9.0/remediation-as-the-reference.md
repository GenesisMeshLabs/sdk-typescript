### Changed

- **`cancelByRotatingForward` disables the version the change made.** `deniedVersionId` is optional and defaults to the state's `change_version_id`; another one is refused before anything runs (`remediation_subject_mismatch`). Before, it was disabled, then the NA refused the record for good and quarantined it, leaving the denied version enabled.
- **`RemediationNotRecordedError.disabled`** says whether the denied version was disabled, and its docs say what to do in each case.

### Fixed

- **`cancelByRotatingForward` never disables after a rotation the NA refused for good.** With an evidence outbox, a rotation whose evidence is a dead letter can never be cited by a remediation record: it now throws `RemediationNotRecordedError` before the disable.
- **`policySectionIssues` refuses `stands_for` with a `*` anywhere, or blank,** as the reference does (`invalid_emergency`). Only a final `.*` was refused.
- **`reviewApprovalProblem` refuses a review whose recorded time cannot be read.** The 300-second bound was skipped, so such a review passed.
- **Due times refuse a date that does not exist and a time past the year 9999,** as the reference does. `remediationDueAt('2026-02-29T00:00:00Z', 0)` gave `2026-03-01T00:00:00Z`, and a due time past 9999 printed as `+010000-…`. `rfc3339` returns null for a time that falls outside the years 1 to 9999 once read in UTC.
