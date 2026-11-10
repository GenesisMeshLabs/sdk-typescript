### Added

- **Expected policy IDs (1.10.0).** `verifyBoundaryDecision` takes
  `expectedPolicyIds`: the policies an ALLOW must rest on, at whatever
  version the NA signed. Each must be in the decision's policy binding with
  at least one enforce-mode gate of that version evaluated, so an ALLOW left
  when a policy was deactivated or its selector stopped matching is refused
  (`policy_binding_mismatch`; `policy_binding_missing` without a binding). A
  DENY is reported as it is. `governedAction` and `urgentAction` accept the
  IDs in place of, or with, the signed policies (`PolicyExpectations`); an
  empty or malformed list is refused before anything is evaluated
  (`policy_expectations_required`). The conformance vectors `bd-011` to
  `bd-017` cover it. A 1.10.0 Network Authority can also deny such requests
  itself (`BOUNDARY_POLICY_COVERAGE=required`); the denial arrives as
  `unauthorized_policy_resolution_failed`.

### Upgrading

- **`GovernedActionParams['verify']` is `PolicyExpectations` now.** Every
  value that type-checked before still does. Code that reads
  `params.verify.expectedPolicies` back gets `readonly BoundaryPolicy[] |
  undefined`, since the IDs may stand in for it.
