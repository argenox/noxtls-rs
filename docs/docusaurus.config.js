// @ts-check
// NoxTLS Rust documentation

import {themes as prismThemes} from "prism-react-renderer";

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "NoxTLS Rust",
  tagline: "Pure Rust crypto and TLS workspace",
  favicon: "img/logo.svg",

  future: {
    v4: true,
  },

  url: "https://rsdocs.noxtls.com",
  baseUrl: "/",

  onBrokenLinks: "warn",

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  presets: [
    [
      "classic",
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: "./sidebars.js",
          // Match embedded C docs pattern: pin default + keep "Next" for in-tree `docs/`.
          lastVersion: "0.1.0",
          includeCurrentVersion: true,
          versions: {
            current: {
              label: "Next",
              path: "next",
            },
          },
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Without this, localStorage can pin "next" as preferred; navbar `doc` then
      // resolves to `/docs/next/...` and versionless `/docs/intro` feels missing.
      docs: {
        versionPersistence: "none",
      },
      navbar: {
        title: "NoxTLS Rust",
        logo: {
          alt: "NoxTLS",
          src: "img/logo.svg",
        },
        items: [
          // Land on versionless `/docs/intro` (lastVersion alias), not `/docs/next/...`
          {
            type: "doc",
            docId: "intro",
            label: "Documentation",
            position: "left",
          },
          {
            type: "docsVersionDropdown",
            position: "right",
            dropdownItemsAfter: [
              {to: "https://github.com/Argenox/noxtls-oem-rust/releases", label: "All releases"},
            ],
          },
          {
            href: "https://github.com/Argenox/noxtls-oem-rust",
            label: "GitHub",
            position: "right",
          },
        ],
      },
      footer: {
        style: "dark",
        links: [
          {
            title: "Documentation",
            items: [
              {label: "Introduction", to: "/docs/intro"},
              {label: "Getting Started", to: "/docs/getting-started"},
              {label: "Architecture", to: "/docs/architecture"},
              {label: "Security", to: "/docs/security"},
              {label: "Crate API", to: "/docs/api"},
              {label: "Release Notes", to: "/docs/release-notes"},
            ],
          },
          {
            title: "Get the Code",
            items: [
              {label: "Build from source", to: "/docs/getting-started"},
              {label: "GitHub", href: "https://github.com/Argenox/noxtls-oem-rust"},
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Argenox Technologies LLC.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ["rust", "toml", "bash", "powershell"],
      },
    }),
};

export default config;
