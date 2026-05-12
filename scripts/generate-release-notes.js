#!/usr/bin/env node
/**
 * Generates Docusaurus release-notes pages from docs/changelog.json.
 *
 * Usage:
 *   node scripts/generate-release-notes.js [repo-root]
 */

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(process.argv[2] || path.join(__dirname, ".."));
const docsDir = path.join(repoRoot, "docs");
const versionedDocsDir = path.join(docsDir, "versioned_docs");
const changelogPath = path.join(docsDir, "changelog.json");
const versionsPath = path.join(docsDir, "versions.json");

if (!fs.existsSync(changelogPath)) {
  console.error("changelog.json not found at", changelogPath);
  process.exit(1);
}
if (!fs.existsSync(versionsPath)) {
  console.error("versions.json not found at", versionsPath);
  process.exit(1);
}

const changelog = JSON.parse(fs.readFileSync(changelogPath, "utf8"));
const versions = JSON.parse(fs.readFileSync(versionsPath, "utf8"));
const byVersion = new Map((changelog.releases || []).map((release) => [release.version, release]));

function renderList(items) {
  if (!items || items.length === 0) {
    return "- (None recorded.)";
  }
  return items.map((item) => `- ${item}`).join("\n");
}

function buildMarkdown(version, release) {
  return [
    "---",
    "sidebar_position: 5",
    "title: Release Notes",
    "---",
    "",
    "# Release Notes",
    "",
    `This page describes changes, fixes, and known issues for **NoxTLS Rust ${version}**.`,
    "",
    "For source artifacts and release tags, see [Releases on GitHub](https://github.com/argenox/noxtls-rs/releases).",
    "",
    "Use the **version dropdown** in the navbar to view docs and notes for other versions.",
    "",
    "---",
    "",
    `## ${version}`,
    "",
    `**Release date:** ${release.date || "TBD"}`,
    "",
    "### Changes",
    "",
    renderList(release.changes),
    "",
    "### Fixed / Resolved",
    "",
    renderList(release.fixed),
    "",
    "### Known issues / Open",
    "",
    renderList(release.known_issues),
    "",
  ].join("\n");
}

let written = 0;

const latestVersion = versions[0];
const latestRelease = byVersion.get(latestVersion);
if (latestRelease) {
  const mainReleasePath = path.join(docsDir, "docs", "release-notes.md");
  fs.mkdirSync(path.dirname(mainReleasePath), {recursive: true});
  fs.writeFileSync(mainReleasePath, buildMarkdown(latestVersion, latestRelease), "utf8");
  console.log("Written", mainReleasePath, `(${latestVersion})`);
  written += 1;
}

for (const version of versions) {
  const release = byVersion.get(version);
  if (!release) {
    continue;
  }

  const versionedDir = path.join(versionedDocsDir, `version-${version}`);
  if (!fs.existsSync(versionedDir)) {
    continue;
  }

  const outPath = path.join(versionedDir, "release-notes.md");
  fs.writeFileSync(outPath, buildMarkdown(version, release), "utf8");
  console.log("Written", outPath);
  written += 1;
}

console.log("Done. Generated", written, "release notes page(s).");
