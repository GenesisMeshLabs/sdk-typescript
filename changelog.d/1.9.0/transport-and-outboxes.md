### Fixed

- **Failover moves past a failed endpoint once.** Requests that failed at one endpoint together each moved the client on, so two of them skipped the next endpoint, a healthy one too. A request now moves past only the endpoint it was sent to, and only while the client is still there; requests waiting on one NA-key lookup that failed move once.
- **A refused observation in a batch keeps the NA's details:** its quarantine entry (`last_error.quarantine_id`), as when it is refused alone.
- **An outbox removes a record only on an answer that admits it.** A 2xx answer without a status the SDK knows (`null`, `{}`, an unknown status, or a batch result of such a status) removed the record as admitted; it now stays pending (`response_body_unreadable`), and a resubmission is a duplicate when the NA holds it.
- **`ObservationRecorder.record` refuses in the NA's order:** JSON the NA cannot read (a lone surrogate) before a change time it cannot read.
