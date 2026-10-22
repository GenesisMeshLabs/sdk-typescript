### Fixed

- **Every verification route is retried and failed over.** The agreement,
  trust-evidence, consensus, disclosure (`prove` and `verify`) and data-usage
  verification requests were sent as non-idempotent, so `retry` and
  `baseUrls` failover skipped them on a 502, 503 or 504, although the guides
  said public verification was eligible. They now behave like the boundary,
  attestation and policy verification routes. The route table test pins
  which routes are retried. The guides now also say which admin POSTs are
  retried (judgements, `anchor`, `recordArchive`), because the NA answers a
  replay with the existing record.
