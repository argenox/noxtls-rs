import React from "react";
import Link from "@docusaurus/Link";

/**
 * Landing page: device-first doc map (parity with NoxTLS C docs IA), Rust-specific content.
 */
export default function Home() {
  return (
    <main style={{maxWidth: 1100, margin: "0 auto", padding: "0 1rem 3rem"}}>
      <header style={{padding: "2.5rem 0 1rem", textAlign: "center"}}>
        <h1 style={{fontSize: "2.25rem", marginBottom: "0.75rem"}}>
          NoxTLS Rust documentation
        </h1>
        <p
          style={{
            maxWidth: 760,
            margin: "0 auto",
            fontSize: "1.1rem",
            color: "var(--ifm-font-color-secondary)",
          }}>
          Device-oriented TLS/DTLS, cryptography, and PKIX guidance for Rust—structured like
          the NoxTLS product docs. Open <strong>Documentation</strong> in the navbar for the
          full sidebar (TLS API, Crypto API, Applications, and more).
        </p>
      </header>

      <section className="home-section">
        <h2 className="home-section-title">Core guides</h2>
        <div className="home-card-grid">
          <Link className="home-card" to="/docs/intro">
            <div className="home-card-title">Introduction</div>
            <p className="home-card-desc">Who the docs are for and how sections fit together.</p>
          </Link>
          <Link className="home-card" to="/docs/getting-started">
            <div className="home-card-title">Getting started</div>
            <p className="home-card-desc">Build, test, and run the doc site locally.</p>
          </Link>
          <Link className="home-card" to="/docs/architecture">
            <div className="home-card-title">Architecture</div>
            <p className="home-card-desc">Crate graph from device, gateway, and crypto-only views.</p>
          </Link>
          <Link className="home-card" to="/docs/security">
            <div className="home-card-title">Security</div>
            <p className="home-card-desc">Reporting, scope, fleet considerations, policy flags.</p>
          </Link>
        </div>
      </section>

      <section className="home-section">
        <h2 className="home-section-title">Porting and configuration</h2>
        <div className="home-card-grid">
          <Link className="home-card" to="/docs/porting-guide">
            <div className="home-card-title">Porting guide</div>
            <p className="home-card-desc">MCU / RTOS checklist and C-to-Rust mapping.</p>
          </Link>
          <Link className="home-card" to="/docs/embed-targets">
            <div className="home-card-title">Embedded targets and I/O</div>
            <p className="home-card-desc">Transports, profiles, adapters.</p>
          </Link>
          <Link className="home-card" to="/docs/configuration-guide">
            <div className="home-card-title">Configuration guide</div>
            <p className="home-card-desc">Cargo features and core profiles as device policy.</p>
          </Link>
          <Link className="home-card" to="/docs/memory-usage">
            <div className="home-card-title">Memory usage</div>
            <p className="home-card-desc">ROM/RAM methodology for firmware images.</p>
          </Link>
          <Link className="home-card" to="/docs/release-notes">
            <div className="home-card-title">Release notes</div>
            <p className="home-card-desc">Versioned changelog entries.</p>
          </Link>
        </div>
      </section>

      <section className="home-section">
        <h2 className="home-section-title">Cryptography and TLS</h2>
        <div className="home-card-grid">
          <Link className="home-card" to="/docs/eddsa">
            <div className="home-card-title">EdDSA</div>
            <p className="home-card-desc">Ed25519 on devices: enablement and operations.</p>
          </Link>
          <Link className="home-card" to="/docs/tls-component">
            <div className="home-card-title">TLS component</div>
            <p className="home-card-desc">Layers, roles, and integration patterns.</p>
          </Link>
          <Link className="home-card" to="/docs/tls-api/overview">
            <div className="home-card-title">TLS API</div>
            <p className="home-card-desc">API map and link into the TLS topic guide.</p>
          </Link>
          <Link className="home-card" to="/docs/crypto-api/overview">
            <div className="home-card-title">Crypto API</div>
            <p className="home-card-desc">Topic guides and generated crate reference.</p>
          </Link>
        </div>
      </section>

      <section className="home-section">
        <h2 className="home-section-title">Applications</h2>
        <div className="home-card-grid">
          <Link className="home-card" to="/docs/applications/overview">
            <div className="home-card-title">Applications overview</div>
            <p className="home-card-desc">Firmware, gateway, and examples index.</p>
          </Link>
          <Link className="home-card" to="/docs/applications/firmware-integration">
            <div className="home-card-title">Firmware integration</div>
            <p className="home-card-desc">Boot order, storage, transport binding, validation matrix.</p>
          </Link>
          <Link className="home-card" to="/docs/applications/host-gateway">
            <div className="home-card-title">Host gateway</div>
            <p className="home-card-desc">Tokio-based services and cloud front-ends.</p>
          </Link>
        </div>
      </section>

      <section className="home-section">
        <h2 className="home-section-title">Latest in-repo (Next)</h2>
        <p style={{color: "var(--ifm-font-color-secondary)", marginTop: 0}}>
          Use the version dropdown for <strong>Next</strong> to follow <code>main</code> between
          doc snapshots.
        </p>
        <div className="home-card-grid">
          <Link className="home-card" to="/docs/next/intro">
            <div className="home-card-title">Introduction (Next)</div>
            <p className="home-card-desc">In-development edits to this site.</p>
          </Link>
        </div>
      </section>

      <section className="home-section">
        <h2 className="home-section-title">Ecosystem</h2>
        <div className="home-card-grid">
          <a className="home-card" href="https://github.com/argenox/noxtls-rs">
            <div className="home-card-title">Source on GitHub</div>
            <p className="home-card-desc">noxtls-rs repository.</p>
          </a>
          <a className="home-card" href="https://crates.io/crates/noxtls">
            <div className="home-card-title">noxtls on crates.io</div>
            <p className="home-card-desc">Published crates.</p>
          </a>
          <a className="home-card" href="https://docs.rs/noxtls">
            <div className="home-card-title">docs.rs</div>
            <p className="home-card-desc">Rust API reference.</p>
          </a>
          <a className="home-card" href="https://docs.noxtls.com">
            <div className="home-card-title">NoxTLS (C) documentation</div>
            <p className="home-card-desc">Sibling C library product docs.</p>
          </a>
        </div>
      </section>
    </main>
  );
}
