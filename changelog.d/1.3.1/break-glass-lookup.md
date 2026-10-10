### Fixed

- **A firewall's `403` or a `404` no longer breaks the glass.** When the NA's
  public key could not be read from `/sovereign.json`, any failure, an HTTP
  answer included, became a `NetworkError`, so `governedAction` with
  `breakGlass` ran the action without ever calling evaluate. Now only a lookup
  that gets no answer is a network error (or a timeout); an answer without the
  key throws `na_public_key_unavailable` with that answer's HTTP status, and
  breaks the glass only when it is a `5xx` or `429`. Another NA instance is
  still tried after a `502`, `503` or `504`.

### Changed

- New error code `na_public_key_unavailable` (status of the `/sovereign.json`
  answer) for a failed NA public key lookup; it was `network_error`.
