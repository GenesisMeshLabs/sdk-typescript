### Fixed

- **Reconciliation counts break-glass changes.** `resourceStates` read
  execution records only, so after a break-glass rotation reconciliation
  reported the new version as `drifted`, and the change was recorded and
  judged a second time. Break-glass records now count as the resource's
  changes, in the order the changes were made; `last_break_glass_id` names
  the record when the latest change was one. The chain head
  (`resource_sequence`, `record_digest`) and `last_decision_id` stay the
  newest execution record's, 0 and empty for a resource with only break-glass
  records.
