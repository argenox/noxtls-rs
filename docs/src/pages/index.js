import React from "react";
import Link from "@docusaurus/Link";

/**
 * Landing page styled like NoxTLS C docs (card grid + sections), with Rust-specific links.
 * Uses stable `/docs/...` URLs (lastVersion) so behavior matches docs.noxtls.com-style paths.
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
            maxWidth: 720,
            margin: "0 auto",
            fontSize: "1.1rem",
            color: "var(--ifm-font-color-secondary)",
          }}>
          Pure Rust TLS/DTLS, cryptography, and X.509 building blocks. Use the
          Documentation link in the navbar for the full sidebar (including auto-generated
          crate pages under <strong>Crate API → Published crates</strong> on the Next
          version).
        </p>
      </header>

      <section className="home-section">
        <h2 className="home-section-title">Start here</h2>
        <div className="home-card-grid">
          <Link className="home-card" to="/docs/intro">
            <div className="home-card-title">Introduction</div>
            <p className="home-card-desc">Workspace goals, layout, and how the pieces fit together.</p>
          </Link>
          <Link className="home-card" to="/docs/getting-started">
            <div className="home-card-title">Getting started</div>
            <p className="home-card-desc">Clone, build, test, and run examples from the repo.</p>
          </Link>
          <Link className="home-card" to="/docs/architecture">
            <div className="home-card-title">Architecture</div>
            <p className="home-card-desc">Crate boundaries and dependency direction.</p>
          </Link>
          <Link className="home-card" to="/docs/api">
            <div className="home-card-title">Crate API</div>
            <p className="home-card-desc">Topic guides (hash, TLS, X.509, …) and per-crate metadata.</p>
          </Link>
        </div>
      </section>

      <section className="home-section">
        <h2 className="home-section-title">Security and releases</h2>
        <div className="home-card-grid">
          <Link className="home-card" to="/docs/security">
            <div className="home-card-title">Security</div>
            <p className="home-card-desc">Reporting scope and practices for this workspace.</p>
          </Link>
          <Link className="home-card" to="/docs/embed-targets">
            <div className="home-card-title">Embedded targets and I/O</div>
            <p className="home-card-desc">Transports, profiles, and integration notes.</p>
          </Link>
          <Link className="home-card" to="/docs/release-notes">
            <div className="home-card-title">Release notes</div>
            <p className="home-card-desc">Versioned changelog entries.</p>
          </Link>
        </div>
      </section>

      <section className="home-section">
        <h2 className="home-section-title">Latest in-repo docs (Next)</h2>
        <p style={{color: "var(--ifm-font-color-secondary)", marginTop: 0}}>
          Use the version dropdown (top right) to switch to <strong>Next</strong> for markdown
          that tracks <code>main</code> before the next snapshot.
        </p>
        <div className="home-card-grid">
          <Link className="home-card" to="/docs/next/api">
            <div className="home-card-title">Crate API (Next)</div>
            <p className="home-card-desc">Includes generated pages for each workspace crate.</p>
          </Link>
          <Link className="home-card" to="/docs/next/getting-started">
            <div className="home-card-title">Getting started (Next)</div>
            <p className="home-card-desc">Bleeding-edge edits to install and build instructions.</p>
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
            <p className="home-card-desc">Install the published stack from crates.io.</p>
          </a>
          <a className="home-card" href="https://docs.rs/noxtls">
            <div className="home-card-title">docs.rs</div>
            <p className="home-card-desc">Rust API reference for the main crate.</p>
          </a>
          <a className="home-card" href="https://docs.noxtls.com">
            <div className="home-card-title">NoxTLS (C) documentation</div>
            <p className="home-card-desc">Sibling C library docs for protocol and API parity context.</p>
          </a>
        </div>
      </section>
    </main>
  );
}
