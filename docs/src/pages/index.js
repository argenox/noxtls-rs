import React from "react";
import Link from "@docusaurus/Link";

/**
 * Static landing page (same idea as embedded C docs at noxtls-oem/noxtls/docs).
 * Avoids a client-only <Redirect>, which can leave an empty shell until JS runs.
 *
 * Primary links use versionless `/docs/...` paths — these are the `lastVersion`
 * aliases (same URL style as https://docs.noxtls.com/docs/intro ).
 */
export default function Home() {
  return (
    <main style={{maxWidth: 900, margin: "0 auto", padding: "3rem 1rem"}}>
      <h1>NoxTLS Rust documentation</h1>
      <p>
        NoxTLS Rust is a pure Rust TLS/DTLS and cryptography workspace. Start with
        the versionless documentation paths below (same pattern as docs.noxtls.com).
        Use the version dropdown for other snapshots, or open Next for the latest
        in-tree markdown under <code>docs/docs/</code>.
      </p>

      <h2>Start here</h2>
      <ul>
        <li>
          <Link to="/docs/intro">Introduction</Link>
        </li>
        <li>
          <Link to="/docs/getting-started">Getting started</Link>
        </li>
        <li>
          <Link to="/docs/architecture">Architecture</Link>
        </li>
        <li>
          <Link to="/docs/api">Crate API</Link>
        </li>
        <li>
          <Link to="/docs/security">Security</Link>
        </li>
        <li>
          <Link to="/docs/release-notes">Release notes</Link>
        </li>
        <li>
          <Link to="/docs/embed-targets">Embedded targets and I/O</Link>
        </li>
      </ul>

      <h2>Current branch (Next)</h2>
      <p>
        In-development docs (from <code>docs/docs/</code> before the next snapshot):
      </p>
      <ul>
        <li>
          <Link to="/docs/next/intro">Introduction (Next)</Link>
        </li>
        <li>
          <Link to="/docs/next/getting-started">Getting started (Next)</Link>
        </li>
        <li>
          <Link to="/docs/next/api">Crate API (Next)</Link>
        </li>
      </ul>

      <h2>Repository</h2>
      <ul>
        <li>
          <a href="https://github.com/argenox/noxtls-rs">noxtls-rs on GitHub</a>
        </li>
      </ul>
    </main>
  );
}
