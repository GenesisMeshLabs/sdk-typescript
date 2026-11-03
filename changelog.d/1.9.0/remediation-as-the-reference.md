### Changed

- **`RemediationNotRecordedError.disabled`** says whether the denied version was disabled, and its docs say what to do in each case, and which failures of the rotation's own governed action throw as `governedAction` does.

### Fixed

- **`cancelByRotatingForward` disables only the version the change made.** When the state carries `change_version_id` (as the due queue's state does), another `deniedVersionId` is refused before anything runs (`remediation_subject_mismatch`). Before, it was disabled, then the NA refused the record for good and quarantined it, leaving the denied version enabled.
- **`cancelByRotatingForward` never disables after a rotation the NA refused for good.** With an evidence outbox, a rotation whose evidence is a dead letter can never be cited by a remediation record: it now throws `RemediationNotRecordedError` before the disable.
- **`policySectionIssues` refuses `stands_for` with a `*` anywhere, or blank,** as the reference does (`invalid_emergency`). Only a final `.*` was refused.
- **`reviewApprovalProblem` reads a review's recorded times (`decided_at`, `requested_at`) as its model does: UTC timestamps only.** Another time gives `the review's decided_at is not a UTC timestamp`. The 300-second bound was skipped when the time could not be read, so such a review passed, and a time without an offset or in another zone was taken.
- **Due times refuse a date that does not exist and a time outside the years 1 to 9999,** as the reference does. `remediationDueAt('2026-02-29T00:00:00Z', 0)` gave `2026-03-01T00:00:00Z`, a due time past 9999 printed as `+010000-…`, and `dueAfterDenial` gave the earlier due time when the decision's grace ran past 9999. `rfc3339` returns null for a time that falls outside the years 1 to 9999 once read in UTC.
- **Due times and `rfc3339` keep every microsecond.** A time before 1685 or after 2255 lost its last digits (`0885-08-29T21:51:35.999999Z` printed as `…:36Z`).
