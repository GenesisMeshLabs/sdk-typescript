### Added

- `GrantSyncResult.timeTokenRefusal`: a time token the NA refused for a reason other than the grant's end, such as `time_token_request_stale` (this clock is more than 300 seconds off the NA's).
- `GrantStateNotKeptError.actionError`: when the action itself failed, its error; `result.use` is then its failure use.

### Fixed

- **A failed action's use is persisted.** `GrantHolder.act` recorded a failed action as a `failure` use, which moves the chain, but did not persist the state after it; a process that stopped then signed that place in the chain again on resume.
- **A resumed holder takes up a kept use.** On its first change a holder takes up the latest use of its grant the record outbox holds beyond its state (kept before the process stopped, the state unpersisted), so no place in the chain is signed twice.
- **A refused time token does not stop the upload.** `sync` threw on a time token the NA refused for another reason than the grant's end (such as `time_token_request_stale`) before it uploaded the record outbox; it now reports it (`timeTokenRefusal`) and uploads. `act` threw it when the time token's uses were spent; it now falls back, and the NA decides.
- **A retired bearer key is a refusal from the first call.** `act` threw the NA's `ConflictError` (`grant_bearer_key_retired`) when it asked for a fresh time token, and `GrantRefusedError` on later calls; it is `GrantRefusedError` from the first.
- **A use without a resource is outside an empty prefix.** Under a bearer key with the empty resource prefix, `act` let a request without a resource run and `verifyEvidenceEvents` let such a use through; the reference refuses both as `grant_use_out_of_scope`.

### Documentation

- `GrantHolder`: any other error of the governed action under a fallback (a refused evaluation, a decision that fails verification) is thrown as it is; the class comment said `GrantRefusedError`.
