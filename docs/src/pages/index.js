import React from "react";
import Link from "@docusaurus/Link";

/**
 * Static landing page (same idea as embedded C docs at noxtls-oem/noxtls/docs).
 * Avoids a client-only <Redirect>, which can leave an empty shell until JS runs.
 */
export default function Home() {
  return (
    <main style={{maxWidth: 900, margin: "0 auto", padding: "3rem 1rem"}}>
      <h1>NoxTLS Rust documentation</h1>
      <p>
        NoxTLS Rust is a pure Rust TLS/DTLS and cryptography workspace. Use the
        links below for the in-tree Next docs that match this repository, or
        open the version dropdown for a frozen snapshot (for example 0.1.0).
      </p>

      <h2>Start here</h2>
      <ul>
        <li>
          <Link to="/docs/next/intro">Introduction (Next)</Link>
        </li>
        <li>
          <Link to="/docs/next/getting-started">Getting started (Next)</Link>
        </li>
        <li>
          <Link to="/docs/next/architecture">Architecture (Next)</Link>
        </li>
        <li>
          <Link to="/docs/next/api">Crate API (Next)</Link>
        </li>
        <li>
          <Link to="/docs/next/security">Security (Next)</Link>
        </li>
        <li>
          <Link to="/docs/next/release-notes">Release notes (Next)</Link>
        </li>
      </ul>

      <h2>Released snapshot</h2>
      <ul>
        <li>
          <Link to="/docs/intro">Introduction (latest snapshotted version)</Link>
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
