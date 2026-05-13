---
sidebar_position: 21
title: Contributing
---

# Contributing

## Code and documentation contributions

- Open issues and pull requests in the [noxtls-oem-rust repository](https://github.com/Argenox/noxtls-oem-rust).
- Keep documentation aligned with actual exported Rust APIs and crate feature flags.
- Include tests for TLS/crypto behavior changes where practical.

## Documentation standards

- Update relevant topic pages in the same change as implementation updates.
- Regenerate OEM-parity algorithm pages after large crypto API changes: `python docs/scripts/gen_api_algorithm_pages.py` (from repo root).
- For new feature flags or policy toggles, update:
  - [Configuration Guide](./configuration-guide)
  - API topic pages under `docs/docs/api`
  - [Release Notes](./release-notes) and `docs/changelog.json`
- Keep cross-links current between TLS, crypto, X.509, and applications pages.

## Documentation versioning

For docs versioning workflow, see:

- [`docs/VERSIONING.md`](https://github.com/Argenox/noxtls-oem-rust/blob/main/docs/VERSIONING.md)
- [`docs/changelog.json`](https://github.com/Argenox/noxtls-oem-rust/blob/main/docs/changelog.json)

## Review checklist

- Workspace build and tests pass for changed crates.
- New feature toggles and policy implications are documented.
- Security-sensitive behavior changes are called out in release notes.
- API references and usage snippets match current Rust symbols and signatures.
