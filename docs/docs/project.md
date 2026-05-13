---
sidebar_position: 19
title: Project
---

# Project

This page summarizes project-level process for NoxTLS Rust documentation and releases.

## Release model

- Source of truth for tagged releases: [GitHub Releases](https://github.com/Argenox/noxtls-oem-rust/releases)
- Active docs are maintained in `docs/docs`.
- Versioned snapshots in `docs/versioned_docs` are created after release docs are finalized.

## Documentation lifecycle

1. Update guides and API topic pages in the same change as implementation updates.
2. Run docs build and link checks.
3. Update `docs/changelog.json`.
4. Regenerate release notes and crate-reference pages.
5. Create a docs version snapshot for the release.

## Scope areas

- TLS/DTLS protocol state machine and record processing (`noxtls`)
- Core policy and configuration (`noxtls-core`)
- Cryptography primitives and key management (`noxtls-crypto`)
- PEM and X.509 parsing/validation (`noxtls-pem`, `noxtls-x509`)
- Platform and transport integration (`noxtls-platform`, `noxtls-io`, optional `noxtls-psa`)

## Cross-links

- [Release notes](./release-notes)
- [Contributing](./contributing)
- [Documentation Parity Matrix](./documentation-parity-matrix)
