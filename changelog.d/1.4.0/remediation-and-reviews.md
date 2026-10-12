### Added

- **Remediation records.** `signRemediation` and `ExecutionRecorder.signRemediation`
  build and sign a `RemediationRecord` (entry kind `remediation`) with the
  executor key, refused before signing as the NA would refuse it
  (`remediation_malformed`, `remediation_secret_material`, `StrictJsonError`).
  `evidenceStore.submitRemediation` submits one; the record outbox keeps them
  too (`kind: "remediation"`) and submits them after break-glass records and
  observations. New permanent refusals in `RECORD_PERMANENT_REFUSALS`:
  `invalid_remediation`, `remediation_malformed`,
  `remediation_invalid_signature`, `remediation_key_retired`,
  `remediation_out_of_scope`, `remediation_secret_material`,
  `remediation_subject_mismatch`, `remediation_steps_mismatch`,
  `remediation_rotation_mismatch`, `remediation_rotation_before_change`,
  `remediation_rotation_other_executor`, `remediation_rotation_reused`,
  `remediation_not_due`, `remediation_already_recorded`,
  `remediation_conflict`.
- **The cancel pair.** `cancelByRotatingForward` cancels a denied change to a
  versioned resource as the NA states it: a governed rotation to a new version
  (its evidence names `execution_parameters.version_id`), then a disable of the
  denied version, then the remediation record linking the two. It checks the
  state (`remediation_due` or `overdue`; a pending review does not stop it),
  the plan and the record before the denied version is disabled, and throws
  `RemediationNotRecordedError` (`remediation_not_recorded`) for a failure
  after the rotation. `remediationSubject` names a decision never executed
  (`fallback: not_executed`) as its own change, for the alert that closes it.
- **The due queue, notices and reviews.** `evidenceStore.listRemediations`
  (paged with `after`; `state: "review_pending"` lists every change with a
  pending review), `allRemediations`, `remediation` (its newest 100 reviews
  and records, with `reviews_truncated` and `records_truncated`),
  `markNotified`, `requestReview`, `review` and `decideReview` wrap the NA's
  1.4.0 routes. A judgement, a resource's changes and the store status carry
  the remediation state (`RemediationStatus`), where a pending review is the
  flag `review_pending` beside the state, not a state: it stops no clock.
- **Urgent changes.** `urgentAction` runs an urgent change under the ordinary
  capability, under the emergency capability (with its justification
  parameter) when the ordinary one is denied, or under break-glass naming the
  emergency capability when the NA cannot be reached or answers `5xx` or
  `429`. It is never blocked, and always judged.
- **Offline verification of the new records.** `verifyEvidenceEvents` verifies
  the `remediation` and `review` entry kinds, with the new reasons
  `duplicate_remediation`, `remediation_subject_mismatch`,
  `remediation_subject_missing`, `remediation_rotation_missing`,
  `remediation_rotation_mismatch`, `remediation_rotation_other_executor`,
  `remediation_rotation_before_change`, `remediation_rotation_reused`,
  `review_approval_invalid`,
  `review_approval_key_mismatch`, `review_same_holder`,
  `review_subject_mismatch`, `review_subject_missing` and
  `review_waiver_after_remediation`, and the counts `remediations` and
  `reviews`. The missing-subject and missing-rotation checks apply to a run
  from entry 1 or right after the `checkpoint` passed, and only registry
  records the NA signed bind an operator key. `reviewApprovalProblem` proves
  a review from the operators' signed requests embedded in it, whose
  timestamps and waiver end are strict RFC 3339 (`rfc3339`);
  `verifyRemediationRecord`, `verifyReviewRecord`, `adminApprovalValid`,
  `reviewHolderProblem` and `reviewRequestProblem` check one record each.
- **The NA's rules, as pure functions.** `remediationPlan`,
  `decisionPlan`, `remediationGuidance`, `cancelSteps`, `changeFacts`,
  `remediationDueAt`, `dueAfterDenial`, `dueAfterWaiver`, `stepsProblem`,
  `remediationRecordProblem` (the record's exact form first, then
  `checkRemediation`), `rotationProblem`, `nextState(state, event,
  reviewPending)` (with `TransitionRefusedError` and the NA's codes),
  `emergencyMap` and `policySectionIssues`. All 340 vectors of the shared
  `remediation` conformance suite pass.
- Policy types carry the 1.4.0 sections `remediation`, `review_required` and
  `emergency`.

### Changed

- `policyDigest` and `policyCanonical` leave a policy's `remediation`,
  `review_required` and `emergency` sections out when they are absent or
  `null`, as the reference does, so a policy without them keeps its 1.3
  digest and a decision that binds it still verifies.
- `resourceChanges` takes `limit` and `after_sequence` (the NA pages a
  resource's changes from 1.4.0, 1000 at a time by default), and
  `allResourceChanges` follows the pages.
- The field registry covers `RemediationRecord`, `ReviewRecord`,
  `AdminApproval` and the new policy sections, and knows the `remediation` and
  `review` entry kinds; a quarantine entry may hold a refused remediation
  record (`record_kind: "remediation"`).

### Upgrading

- Upgrade every SDK that reads policies or verifies exports before the NA
  turns on `EVIDENCE_REMEDIATION`: a 1.3 SDK refuses policies with the new
  sections as `unknown_field` and exports with the new entry kinds as
  `unknown_entry_kind`.
- A `FileRecordOutbox` written by 1.4.0 may hold remediation records. A 1.3
  SDK cannot read them and moves their files aside as `<name>.unreadable`:
  flush the record outbox before going back to 1.3.
