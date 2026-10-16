### Security

- **A caller-supplied ID can no longer address another NA route.** The
  clients put IDs in request paths with `encodeURIComponent`, which keeps
  `/`, `?`, `#` and `%` inside the segment but leaves `.` and `..` as they
  are, and URL parsing resolves dot segments: `attestation.get('..')`
  requested `/`, `grants.revokeGrant('..')` requested `/admin/revoke`, and a
  resource ID such as `vaults/../../grants/x` requested `/admin/grants/x`.
  An admin request was still refused (its signature covers the path the SDK
  meant, not the one sent), but a public read reached another route. The
  transport now refuses any request path with a `.` or `..` segment (also
  percent-encoded), before it signs or sends anything, with a
  `GenesisMeshError` whose code is `invalid_path_segment`.

### Upgrading

- An ID of `.` or `..`, or a resource ID with such a segment, now fails with
  `invalid_path_segment` instead of sending a request. No NA record has such
  an ID.
