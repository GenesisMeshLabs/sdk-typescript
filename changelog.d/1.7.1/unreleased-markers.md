### Fixed

- **The README and the grants and audit-pack guides no longer call shipped
  features unreleased.** The npm package carried "*Unreleased.*" on the
  pre-issued grants (1.6.0) and key succession and audit packs (1.5.0)
  sections. A release now refuses the marker: `npm run check:version` fails
  on a `release/<version>` pull request and in the publish workflow when
  `README.md` or `docs/` still marks a feature "Unreleased"
  (`scripts/release-docs.mjs`).
