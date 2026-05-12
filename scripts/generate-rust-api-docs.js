#!/usr/bin/env node
/**
 * Generates crate API pages for Docusaurus from workspace Cargo members.
 *
 * Usage:
 *   node scripts/generate-rust-api-docs.js [repo-root]
 */

const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(process.argv[2] || path.join(__dirname, ".."));
const workspaceCargoPath = path.join(repoRoot, "Cargo.toml");
const docsApiDir = path.join(repoRoot, "docs", "docs", "api");

if (!fs.existsSync(workspaceCargoPath)) {
  console.error("Workspace Cargo.toml not found at", workspaceCargoPath);
  process.exit(1);
}

const workspaceCargo = fs.readFileSync(workspaceCargoPath, "utf8");

function parseWorkspaceMembers(contents) {
  const membersMatch = contents.match(/members\s*=\s*\[(?<members>[\s\S]*?)\]/m);
  if (!membersMatch || !membersMatch.groups || !membersMatch.groups.members) {
    return [];
  }

  return membersMatch.groups.members
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith('"'))
    .map((line) => line.replace(/"|,/g, "").trim())
    .filter((value) => value.length > 0);
}

function parsePackageField(contents, fieldName) {
  const pattern = new RegExp(`^${fieldName}\\s*=\\s*"([^"]+)"$`, "m");
  const match = contents.match(pattern);
  return match ? match[1] : null;
}

function parsePublishValue(contents) {
  const match = contents.match(/^publish\s*=\s*(.+)$/m);
  return match ? match[1].trim() : null;
}

function toDocIdFromMember(member) {
  return member;
}

function buildDoc(member, pkgName, description, published) {
  const docsRsUrl = `https://docs.rs/${pkgName}`;
  const crateLabel = `\`${pkgName}\``;

  return [
    "---",
    `title: ${pkgName}`,
    "---",
    "",
    `# ${crateLabel}`,
    "",
    description || `API module documentation page for ${crateLabel}.`,
    "",
    "## Crate metadata",
    "",
    `- Workspace path: \`${member}\``,
    `- Package name: ${crateLabel}`,
    `- Publish status: ${published ? "published/public" : "internal/private"}`,
    "",
    "## API references",
    "",
    published
      ? `- docs.rs: [${docsRsUrl}](${docsRsUrl})`
      : "- docs.rs: not published (internal crate)",
    `- Source: [\`${member}\`](https://github.com/Argenox/noxtls-oem-rust/tree/main/${member})`,
    "",
    "## Notes",
    "",
    "This page is generated from workspace Cargo metadata. Re-run `npm run api:sync` after crate metadata changes.",
    "",
  ].join("\n");
}

const members = parseWorkspaceMembers(workspaceCargo);
fs.mkdirSync(docsApiDir, {recursive: true});

let written = 0;

for (const member of members) {
  const cargoPath = path.join(repoRoot, member, "Cargo.toml");
  if (!fs.existsSync(cargoPath)) {
    continue;
  }

  const cargo = fs.readFileSync(cargoPath, "utf8");
  const pkgName = parsePackageField(cargo, "name");
  if (!pkgName) {
    continue;
  }

  const description = parsePackageField(cargo, "description");
  const publishRaw = parsePublishValue(cargo);
  const published = !publishRaw || publishRaw === "true";

  const docId = toDocIdFromMember(member);
  const outPath = path.join(docsApiDir, `${docId}.md`);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, buildDoc(member, pkgName, description, published), "utf8");
  console.log("Written", outPath);
  written += 1;
}

console.log("Done. Generated", written, "crate API page(s).");
