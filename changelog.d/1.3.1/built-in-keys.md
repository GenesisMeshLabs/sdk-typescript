### Fixed

- **Keys named like built-ins are fields like any other.** Validation of an
  export envelope accepted an unknown field named `constructor` or
  `toString`, and `verifyEvidenceEvents` threw instead of returning a verdict
  for an unsigned field next to a signature whose `key_id` was `constructor`.
  Both now look at own properties only.
