### Security

- **A record without its own time is signed by no key of the NA's key history.** `verifyDecisionSignature`, `verifyPolicySignature`, `verifyJustificationSignature`, `verifyAttestationSignature`, `verifyRevocationFeedSignature`, `revocationFeedSigner` and `verifyRetentionCheckpoint` took every key of the history for a record whose time was null, so a succeeded key's signature over such a record verified forever. The reference's models require these times. A list of keys is still valid at every time.

### Fixed

- **Timestamps of the year 0000 are refused,** as the reference refuses them: `Date.UTC` reads the year 0000 as 1900, so a record dated `0000-…` passed the shape checks.
