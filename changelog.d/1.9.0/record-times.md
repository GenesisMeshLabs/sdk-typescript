### Security

- **A record without its own time is signed by no key of the NA's key history.** `verifyDecisionSignature`, `verifyPolicySignature`, `verifyJustificationSignature`, `verifyAttestationSignature`, `verifyTreatySignature`, `verifyRevocationFeedSignature`, `revocationFeedSigner` and `verifyRetentionCheckpoint` took every key of the history for a record whose time was null, so a succeeded key's signature over such a record verified forever. The reference's models require these times: a record whose own time is not a timestamp now verifies under no key of a history. A list of keys is still valid at every time.

### Fixed

- **The same verifiers no longer throw for a record whose time is absent or not a string** under a key history (`TypeError` from the key lookup): it verifies under no key.
- **Timestamps of the year 0000 are refused,** as the reference refuses them: `Date.UTC` reads the year 0000 as 1900, so a record dated `0000-…` passed the shape checks.
