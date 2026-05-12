# noxtls example applications

These examples are wired into the `noxtls` crate and can be run from repository root:

```powershell
cargo run -p noxtls --example <name>
```

Available examples:

- `dtls_client`: sends one UDP datagram and reads one response.
- `dtls_server`: receives one UDP datagram and sends one response.
- `tls_client`: demonstrates a simple TLS 1.3 client flow with noxtls APIs.
- `tls_server`: serves one fixed HTTP response over TCP.
- `cert_app`: validates a generated certificate chain and hostname.
- `cert_req`: generates a P-256 CSR and prints PEM output.
- `cert_write`: writes a self-signed P-256 certificate in PEM.
- `crl_app`: loads and dumps basic CRL ASN.1 envelope fields from a DER file path.
- `req_app`: loads and dumps a CSR ASN.1 envelope from a DER/PEM file path.
- `pem2der`: converts a certificate between PEM and DER (`<input> [output]`).
- `parse_certificate`: parses and prints key certificate fields from a DER/PEM file path.
- `verify_chain`: validates a generated certificate against a trust anchor.
- `embedded_no_std`: demonstrates `no_std`-friendly usage patterns.
- `noxtls-rs`: OpenSSL-style utility with `dgst`, `enc`, `dec`, `rand`, `genpkey`, `pkcs8`, `req`, `x509`, and `verify`.

X.509-oriented examples with input arguments:

```powershell
cargo run -p noxtls --example parse_certificate -- .\certs\leaf.pem
cargo run -p noxtls --example pem2der -- .\certs\leaf.pem .\certs\leaf.der
cargo run -p noxtls --example crl_app -- .\certs\crl.der
cargo run -p noxtls --example req_app -- .\certs\request.pem
```

OpenSSL-style `noxtls-rs` examples:

```powershell
cargo run -p noxtls --example noxtls-rs -- dgst --alg sha256 --in .\README.md
cargo run -p noxtls --example noxtls-rs -- enc --key 00112233445566778899aabbccddeeff --text "hello"
cargo run -p noxtls --example noxtls-rs -- rand --bytes 32 --hex
cargo run -p noxtls --example noxtls-rs -- genpkey --algorithm x25519 --out .\x25519-private.txt --pubout .\x25519-public.pem
cargo run -p noxtls --example noxtls-rs -- pkcs8 --topk8 --algorithm p256 --key-hex 1111111111111111111111111111111111111111111111111111111111111111 --out .\p256-key.pem
cargo run -p noxtls --example noxtls-rs -- pkcs8 --in .\p256-key.pem --outform hex
cargo run -p noxtls --example noxtls-rs -- req --new --key-hex 1111111111111111111111111111111111111111111111111111111111111111 --subj "client.noxtls.local" --out .\client.csr.pem
cargo run -p noxtls --example noxtls-rs -- x509 --selfsign --key-hex 1111111111111111111111111111111111111111111111111111111111111111 --subj "client.noxtls.local" --out .\client.crt.pem
cargo run -p noxtls --example noxtls-rs -- verify --cert .\client.crt.pem --ca .\client.crt.pem --hostname client.noxtls.local --time 20260101000000Z
```
