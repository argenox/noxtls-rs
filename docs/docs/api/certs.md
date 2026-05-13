---
title: Certificates
---

# Certificates

## Purpose

The **`noxtls-x509`** crate (re-exported through the workspace TLS stack where enabled) provides **DER X.509** parsing, **PEM ↔ DER** helpers, **hostname matching** for TLS-style identity checks, and **path validation** with optional policy knobs. Use it when you load trust anchors and peer certificates from disk, firmware blobs, or embedded PEM strings, then need to parse, inspect, and validate them before trusting a connection.

Typical flow:

1. **Load bytes** (DER as-is, or PEM text converted to DER).
2. **`noxtls_parse_certificate`** to obtain a **`Certificate`** view (borrowed slices into your buffer where possible).
3. **`noxtls_certificate_matches_hostname`** (or SAN inspection) for the intended DNS name.
4. **`noxtls_validate_certificate_chain`** (or **`noxtls_validate_certificate_chain_with_options`**) against your **trust anchor** set and a **validation time** string.

For PEM labels, line wrapping, and file helpers, see [Utility](./utility) and the broader [X.509 topic](./x509).

## Loading: DER vs PEM

- **DER (binary)** — Pass the file or blob bytes directly to **`noxtls_parse_certificate(&der)`**. The parser expects a single **X.509 `Certificate`** structure (tag `0x30` at the top level).
- **PEM (`-----BEGIN CERTIFICATE-----`)** — PEM is **UTF-8 text**. Decode with **`noxtls_certificate_pem_to_der(pem: &str) -> Result<Vec<u8>>`**, which extracts the first `CERTIFICATE` block. For bundles (server chain files with several certificates in order), use **`noxtls_certificate_chain_pem_to_der_blocks(pem: &str) -> Result<Vec<Vec<u8>>>`** and **`noxtls_parse_certificate`** on each DER block in order (leaf first if that is how your file is written).

With **`std`** enabled on **`noxtls-x509`**, you can read a file and branch on PEM vs DER the same way as the **`noxtls_parse_certificate`** example: if bytes start with **`b"-----BEGIN CERTIFICATE-----"`**, decode as UTF-8 then **`noxtls_certificate_pem_to_der`**; otherwise treat the bytes as DER. Optional **`noxtls_pem_file_to_der`** / **`noxtls_pem_file_to_der_blocks`** (from the same crate surface) read PEM directly from a path.

## `Certificate` snapshot

**`noxtls_parse_certificate`** returns **`Certificate<'a>`** with fields used by validation and TLS wiring, including:

- **Validity** — **`not_before`**, **`not_after`** (string forms as extracted from the cert).
- **Subject / issuer** — Raw DER slices (**`subject_raw`**, **`issuer_raw`**) plus parsed **Subject Alternative Name** DNS names in **`subject_alt_dns_names`**.
- **Keys and signatures** — **`subject_public_key`**, algorithm OIDs, **`signature_value`**, and **`raw_tbs_der`** for signature verification.
- **Extensions** — Basic constraints, key usage, EKU, name constraints, AIA/CRL distribution fields, and related OIDs as parsed by this implementation.

Inspect these fields for logging, policy, or custom checks beyond the built-in chain validator.

## Rust API

- **Crate:** `noxtls-x509`
- **Module path:** types and functions are re-exported at the **`noxtls_x509`** crate root (flat API).
- **Primary symbols (certificates):**
  - **`noxtls_parse_certificate`**, **`Certificate`**
  - **`noxtls_certificate_pem_to_der`**, **`noxtls_certificate_chain_pem_to_der_blocks`**, **`noxtls_certificate_der_to_pem`**
  - **`noxtls_certificate_matches_hostname`**
  - **`noxtls_validate_certificate_chain`**, **`noxtls_validate_certificate_chain_with_options`**, **`noxtls_validate_certificate_chain_constraints_only`**, **`noxtls_validate_certificate_chain_strict`**
  - **`noxtls_verify_certificate_signature`**
  - **`ValidationOptions`**, **`ValidationReport`**, **`ValidationError`**

**Functions and types (selected):**

- **`noxtls_parse_certificate(input: &[u8]) -> Result<Certificate<'_>>`** — Parameters: full **DER** certificate bytes (size-limited internally). Behavior: parses TBSCertificate, signature, and common extensions. Returns: a **`Certificate`** view or **`noxtls_core::Error`** on parse failure.
- **`noxtls_certificate_pem_to_der(pem: &str) -> Result<Vec<u8>>`** — Parameters: PEM text containing a **`CERTIFICATE`** block. Behavior: decodes the first block to DER. Returns: DER bytes suitable for **`noxtls_parse_certificate`**, or PEM/DER decode errors from the **`noxtls_pem`** layer.
- **`noxtls_certificate_chain_pem_to_der_blocks(pem: &str) -> Result<Vec<Vec<u8>>>`** — Parameters: PEM text that may contain **multiple** `CERTIFICATE` blocks. Behavior: returns one DER blob per block in order. Returns: vector of DER chunks.
- **`noxtls_certificate_matches_hostname(cert, hostname: &str) -> bool`** — Parameters: parsed **`Certificate`** and a DNS hostname. Behavior: matches against **SAN dNSName** entries when present; otherwise falls back to **Subject CN** when no SAN DNS names exist. Returns: **`true`** if a match is allowed under the implementation’s DNS rules (including simple wildcard handling where supported).
- **`noxtls_validate_certificate_chain(leaf, intermediates, trust_anchors, now) -> Result<ValidationReport, ValidationError>`** — Parameters: parsed **`Certificate`** references for the **end-entity**, optional **intermediate** issuers, non-empty **trust anchors**, and **`now`** as an ASN.1 time string (**UTCTime** `YYMMDDhhmmssZ` or **GeneralizedTime** `YYYYMMDDhhmmssZ`). Behavior: builds a chain toward an anchor, checks time and path constraints, and **verifies signatures** at each hop. Returns: **`ValidationReport`** on success, or **`ValidationError`** on failure (expired cert, untrusted root, bad signature, etc.).
- **`noxtls_validate_certificate_chain_with_options(..., options: &ValidationOptions)`** — Same as above with optional **policy OID**, **required EKU OID**, explicit-policy, CRL/AIA presence flags, and **policy mapping** inhibition.
- **`noxtls_validate_certificate_chain_constraints_only(...)`** — Same path-building and constraint checks **without** signature verification (narrow use; prefer full validation for security).
- **`noxtls_verify_certificate_signature(certificate, issuer) -> Result<(), ValidationError>`** — Verifies that **`certificate`**’s signature over **`raw_tbs_der`** verifies under **`issuer`**’s public key (RSA/EC/Ed25519 per supported OIDs).

## Feature flags and policy

Certificate and X.509 code paths are gated by **`feature-cert`** on **`noxtls-core`** (and thus on crates that depend on **`noxtls-x509`** in the full TLS profile). Your firmware or host binary should enable the **`noxtls-core`** profile that includes **`feature-cert`** when you ship TLS with PKIX verification. See [Build configuration](./build_config) and the [Configuration guide](../../configuration-guide).

## Examples

### Parse DER from memory

```rust
use noxtls_x509::noxtls_parse_certificate;

fn inspect_leaf(der: &[u8]) -> noxtls_core::Result<()> {
    let cert = noxtls_parse_certificate(der)?;
    println!("not_before={} not_after={}", cert.not_before, cert.not_after);
    println!("san_dns={:?}", cert.subject_alt_dns_names);
    Ok(())
}
# fn main() {}
```

### Decode PEM, then parse (host / `std`)

```rust
use noxtls_core::Result;
use noxtls_x509::{noxtls_certificate_pem_to_der, noxtls_parse_certificate, noxtls_certificate_matches_hostname};

fn load_leaf_from_pem(pem_utf8: &str) -> Result<()> {
    let der = noxtls_certificate_pem_to_der(pem_utf8)?;
    let cert = noxtls_parse_certificate(&der)?;
    let _ = noxtls_certificate_matches_hostname(&cert, "server.example.com");
    Ok(())
}
# fn main() {}
```

### PEM chain: split blocks, parse each certificate

```rust
use noxtls_core::Result;
use noxtls_x509::{noxtls_certificate_chain_pem_to_der_blocks, noxtls_parse_certificate};

fn load_chain(pem: &str) -> Result<()> {
    let der_blocks = noxtls_certificate_chain_pem_to_der_blocks(pem)?;
    for der in &der_blocks {
        let _cert = noxtls_parse_certificate(der)?;
    }
    Ok(())
}
# fn main() {}
```

**Lifetime note:** each **`Certificate<'a>`** borrows from the **`der`** slice you parsed. Keep the **`Vec<u8>`** (or full PEM buffer) alive for as long as you hold the **`Certificate`** views—often you store **`der_blocks`** in a struct next to the parsed cert list.

### Validate against a trust anchor (generated demo)

This mirrors the **`cert_app`** example: same key material produces a self-signed “leaf” that is also your trust anchor, so path validation can succeed for API testing.

```rust
use noxtls_core::Result;
use noxtls_crypto::P256PrivateKey;
use noxtls_x509::{
    noxtls_certificate_matches_hostname, noxtls_parse_certificate, noxtls_validate_certificate_chain,
    noxtls_write_self_signed_certificate_p256_sha256,
};

fn demo() -> Result<()> {
    let der = {
        let key = P256PrivateKey::from_bytes([0x66u8; 32])?;
        let pub_key = key.public_key()?;
        noxtls_write_self_signed_certificate_p256_sha256(
            &[0x20],
            "server.noxtls.local",
            "240101000000Z",
            "300101000000Z",
            &pub_key,
            &key,
        )?
    };
    let cert = noxtls_parse_certificate(&der)?;
    assert!(noxtls_certificate_matches_hostname(&cert, "server.noxtls.local"));

    let anchor = cert.clone();
    let report = noxtls_validate_certificate_chain(&cert, &[], &[anchor], "20260101000000Z")
        .expect("demo: self-signed cert validates as its own trust anchor");
    assert!(report.chain_len >= 1);
    Ok(())
}
# fn main() { let _ = demo(); }
```

For more issuance and CSR flows, run the in-tree examples (for example **`cargo run -p noxtls --example cert_app`**, **`noxtls_parse_certificate`**, **`verify_chain`**) and read [X.509](./x509).

## Security and compatibility

- **Trust store** — Ship only anchors you intend to trust; prefer **pinning** or a **minimal curated store** over “every public CA” on constrained devices. Document anchor rotation and emergency update paths.
- **Time** — Pass a correct **`now`** string from your RTC or time sync; wrong clocks cause spurious **not yet valid** / **expired** results.
- **Hostname** — **`noxtls_certificate_matches_hostname`** is one layer; still run **full chain validation** and apply TLS **SNI** / application policy separately.
- **Revocation** — Built-in validation can enforce **CRL/AIA presence** via **`ValidationOptions`**; it does not by itself fetch CRLs or OCSP over the network. Plan how your product obtains revocation status if required.
- **Errors** — Parsing failures use **`noxtls_core::Error`**; chain validation uses **`ValidationError`**. Map both in application logging without leaking sensitive PEM in logs.

## Related

- [X.509 topic](./x509)
- [Utility](./utility) (PEM encoding helpers)
- [Build configuration](./build_config)
