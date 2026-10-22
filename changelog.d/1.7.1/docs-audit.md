### Fixed

- **The README and the guides match the code and the NA again.** The quick
  start uses a standard-tier `controller` key, as the local NA guide does,
  and reads a key file with blank lines. The boundary example uses
  `evaluate`; `decide` is marked as the legacy route an NA that requires
  policies refuses. The README lists all 12 sub-clients, marks the beta
  routes, names the NA release and switches the later features need, the
  typed errors, and the 1.7.1 `invalid_path_segment` refusal. The
  remediation guide gives the 1.5.0 default queue (a remediated change with
  a pending review is no longer listed) and says the routes are stable from
  1.5.0. The high-availability guide lists `grant_issuance_conflict` and the
  1.5.0 `na_key` readiness check. The audit-pack guide says which routes are
  beta, and is retitled "Key succession, audit packs and offline
  verification". `SECURITY.md` takes the core's response times and covers
  the verifiers, the grant holder, the outboxes and request paths. The npm
  description no longer says "capability enforcement".
