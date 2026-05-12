// @ts-check
// NoxTLS Rust documentation — layout aligned with NoxTLS C docs (docs.noxtls.com)

import {themes as prismThemes} from "prism-react-renderer";

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "NoxTLS Rust",
  tagline: "Pure Rust crypto and TLS workspace",
  favicon: "img/noxtls-rust-logo-256.webp",

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
          lastVersion: "0.1.3",
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
      colorMode: {
        defaultMode: "light",
        disableSwitch: false,
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: "NoxTLS Rust",
        logo: {
          alt: "NoxTLS Rust",
          src: "img/noxtls-rust-logo-256.webp",
        },
        items: [
          {
            type: "docSidebar",
            sidebarId: "docsSidebar",
            position: "left",
            label: "Documentation",
          },
          {
            type: "docsVersionDropdown",
            position: "right",
            dropdownItemsBefore: [],
            dropdownItemsAfter: [
              {to: "https://github.com/argenox/noxtls-rs/releases", label: "All releases"},
            ],
          },
          {
            href: "https://github.com/argenox/noxtls-rs",
            label: "GitHub",
            position: "right",
          },
          {
            to: "/docs/security",
            label: "Security",
            position: "right",
          },
          {
            href: "https://crates.io/crates/noxtls",
            label: "crates.io",
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
              {label: "Embedded targets and I/O", to: "/docs/embed-targets"},
              {label: "Crate API", to: "/docs/api"},
              {label: "Release Notes", to: "/docs/release-notes"},
            ],
          },
          {
            title: "Get the code",
            items: [
              {label: "Build from source", to: "/docs/getting-started"},
              {label: "GitHub", href: "https://github.com/argenox/noxtls-rs"},
              {label: "noxtls on crates.io", href: "https://crates.io/crates/noxtls"},
              {label: "API on docs.rs", href: "https://docs.rs/noxtls"},
            ],
          },
          {
            title: "Community",
            items: [
              {label: "NoxTLS (C library)", href: "https://docs.noxtls.com"},
              {label: "noxtls.com", href: "https://noxtls.com"},
              {label: "Contact", href: "mailto:info@argenox.com"},
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Argenox Technologies LLC.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ["rust", "toml", "bash", "powershell", "c"],
      },
    }),
};

export default config;
