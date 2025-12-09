import { defineConfig } from 'vitepress'

export default defineConfig({
    title: 'Patterns',
    description: 'OWASP CRS and Bad Bot Detection for Web Servers',
    base: '/patterns/',

    head: [
        ['link', { rel: 'icon', href: '/patterns/favicon.ico' }]
    ],

    themeConfig: {
        logo: '/logo.svg',

        nav: [
            { text: 'Home', link: '/' },
            { text: 'Getting Started', link: '/getting-started' },
            {
                text: 'Web Servers',
                items: [
                    { text: 'Nginx', link: '/nginx' },
                    { text: 'Apache', link: '/apache' },
                    { text: 'Traefik', link: '/traefik' },
                    { text: 'HAProxy', link: '/haproxy' }
                ]
            },
            { text: 'Bad Bots', link: '/badbots' },
            { text: 'API', link: '/api' }
        ],

        sidebar: [
            {
                text: 'Introduction',
                items: [
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
                text: 'Features',
                items: [
                    { text: 'Bad Bot Detection', link: '/badbots' },
                    { text: 'API Reference', link: '/api' }
                ]
            }
        ],

        socialLinks: [
            { icon: 'github', link: 'https://github.com/fabriziosalmi/patterns' }
        ],

        footer: {
            message: 'Released under the MIT License.',
            copyright: 'Copyright © 2024-present Fabrizio Salmi'
        },

        search: {
            provider: 'local'
        },

        editLink: {
            pattern: 'https://github.com/fabriziosalmi/patterns/edit/main/docs/:path',
            text: 'Edit this page on GitHub'
        }
    }
})
