import { defineConfig } from 'vitepress'

// Inline SVG icon factory for the features grid (renders inside .VPFeature .icon)
const svg = (paths: string) =>
    `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`

const icons = {
    shield: svg('<path d="M12 3 4.5 5.8v6.1c0 4.7 3.3 9.1 7.5 10.4 4.2-1.3 7.5-5.7 7.5-10.4V5.8L12 3Z"/><path d="m8.5 12 2.5 2.5L15.5 9.5"/>'),
    bot: svg('<rect x="4" y="7.5" width="16" height="11" rx="3"/><path d="M12 4v3.5"/><circle cx="12" cy="3.5" r="0.9" fill="currentColor" stroke="none"/><circle cx="9" cy="13" r="1.1" fill="currentColor" stroke="none"/><circle cx="15" cy="13" r="1.1" fill="currentColor" stroke="none"/><path d="M2 13.5v2M22 13.5v2"/>'),
    servers: svg('<rect x="3.5" y="4" width="17" height="6" rx="1.5"/><rect x="3.5" y="14" width="17" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/><path d="M11 7h6M11 17h6"/>'),
    refresh: svg('<path d="M3.5 12a8.5 8.5 0 0 1 14.5-6L20 8"/><path d="M20 3v5h-5"/><path d="M20.5 12a8.5 8.5 0 0 1-14.5 6L4 16"/><path d="M4 21v-5h5"/>'),
    package: svg('<path d="M21 8 12 3 3 8v8l9 5 9-5V8Z"/><path d="m3.3 8 8.7 5 8.7-5"/><path d="M12 13v8"/><path d="m7.5 5.5 9 5"/>'),
    puzzle: svg('<path d="M14 4.5a2 2 0 1 0-4 0V6H6a1.5 1.5 0 0 0-1.5 1.5V11h1.5a2 2 0 1 1 0 4H4.5v3.5A1.5 1.5 0 0 0 6 20h3.5v-1.5a2 2 0 1 1 4 0V20H17a1.5 1.5 0 0 0 1.5-1.5V15H20a2 2 0 1 0 0-4h-1.5V7.5A1.5 1.5 0 0 0 17 6h-3V4.5Z"/>')
}

export default defineConfig({
    title: 'Patterns',
    titleTemplate: ':title — Patterns',
    description: 'Automated OWASP CRS and bad-bot rules for Nginx, Apache, Traefik, and HAProxy.',
    base: '/patterns/',
    cleanUrls: true,
    lastUpdated: true,

    markdown: {
        languageAlias: {
            haproxy: 'apache'
        },
        theme: {
            light: 'github-light',
            dark: 'github-dark-dimmed'
        }
    },

    head: [
    // Everything this site loads is first-party. 'unsafe-inline' is required
    // because VitePress emits an inline appearance script and inline styles.
    // Applied to the built site only: `vitepress dev` serves HMR over a
    // websocket, which a strict connect-src would block as soon as the dev
    // server is not same-origin (--host, or a custom server.hmr.port).
    ...(process.env.NODE_ENV === 'production'
      ? [
          [
            'meta',
            {
              'http-equiv': 'Content-Security-Policy',
              content:
                "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'",
            },
          ] as [string, Record<string, string>],
        ]
      : []),
        ['link', { rel: 'icon', type: 'image/svg+xml', href: '/patterns/favicon.svg' }],
        ['meta', { name: 'theme-color', content: '#0071e3' }],
        ['meta', { name: 'apple-mobile-web-app-capable', content: 'yes' }],
        ['meta', { name: 'apple-mobile-web-app-status-bar-style', content: 'default' }],
        ['meta', { property: 'og:type', content: 'website' }],
        ['meta', { property: 'og:title', content: 'Patterns — OWASP CRS WAF rules' }],
        ['meta', { property: 'og:description', content: 'Automated OWASP CRS and bad-bot rules for Nginx, Apache, Traefik, and HAProxy.' }],
        ['meta', { name: 'twitter:card', content: 'summary_large_image' }]
    ],

    themeConfig: {
        logo: { src: '/logo.svg', width: 24, height: 24 },
        siteTitle: 'Patterns',

        // Expose icons to markdown via Vite config? Instead we expose them through home features below.
        // (Used by index.md frontmatter via `icon: { svg: ... }`)
        // @ts-expect-error — custom field for home page
        icons,

        nav: [
            { text: 'Documentation', link: '/getting-started', activeMatch: '^/(getting-started|nginx|apache|traefik|haproxy|badbots|api)' },
            {
                text: 'Web Servers',
                items: [
                    { text: 'Nginx', link: '/nginx' },
                    { text: 'Apache (ModSecurity)', link: '/apache' },
                    { text: 'Traefik', link: '/traefik' },
                    { text: 'HAProxy', link: '/haproxy' }
                ]
            },
            { text: 'Bad Bots', link: '/badbots' },
            { text: 'API', link: '/api' },
            { text: 'Releases', link: 'https://github.com/fabriziosalmi/patterns/releases' }
        ],

        sidebar: [
            {
                text: 'Introduction',
                items: [
                    { text: 'Overview', link: '/' },
                    { text: 'Getting Started', link: '/getting-started' }
                ]
            },
            {
                text: 'Web Server Integration',
                items: [
                    { text: 'Nginx', link: '/nginx' },
                    { text: 'Apache (ModSecurity)', link: '/apache' },
                    { text: 'Traefik', link: '/traefik' },
                    { text: 'HAProxy', link: '/haproxy' }
                ]
            },
            {
                text: 'Reference',
                items: [
                    { text: 'Bad Bot Detection', link: '/badbots' },
                    { text: 'API & Scripts', link: '/api' }
                ]
            }
        ],

        socialLinks: [
            { icon: 'github', link: 'https://github.com/fabriziosalmi/patterns' }
        ],

        footer: {
            message: 
        'Released under the MIT License. · <a href="https://fabriziosalmi.github.io/privacy">Privacy &amp; legal</a>',
            copyright: `Copyright © 2024–${new Date().getFullYear()} Fabrizio Salmi`
        },

        search: { provider: 'local' },

        editLink: {
            pattern: 'https://github.com/fabriziosalmi/patterns/edit/main/docs/:path',
            text: 'Edit this page on GitHub'
        },

        outline: { level: [2, 3], label: 'On this page' },

        docFooter: { prev: 'Previous', next: 'Next' }
    }
})

// Re-export icons so the home page (index.md) can pull them via a JS hash, if needed.
export { icons }
