<script setup lang="ts">
import { withBase } from 'vitepress'
import IconNginx from './icons/IconNginx.vue'
import IconApache from './icons/IconApache.vue'
import IconTraefik from './icons/IconTraefik.vue'
import IconHaproxy from './icons/IconHaproxy.vue'
import IconArrow from './icons/IconArrow.vue'

const platforms = [
    { name: 'Nginx',   meta: 'map directives + if rules',     href: '/nginx',   icon: IconNginx,   accent: '#009639' },
    { name: 'Apache',  meta: 'ModSecurity SecRule directives', href: '/apache',  icon: IconApache,  accent: '#d22128' },
    { name: 'Traefik', meta: 'Middleware TOML configuration',  href: '/traefik', icon: IconTraefik, accent: '#24a1c1' },
    { name: 'HAProxy', meta: 'ACL pattern files',              href: '/haproxy', icon: IconHaproxy, accent: '#7cc242' }
]

const stats = [
    { value: '600+',  label: 'OWASP CRS patterns', sub: 'Extracted from upstream daily' },
    { value: 'Daily', label: 'Refresh cadence',     sub: 'Scheduled GitHub Actions' },
    { value: '4',     label: 'Server backends',     sub: 'Native, idiomatic output' },
    { value: 'MIT',   label: 'License',             sub: 'Open-source, no vendor lock' }
]
</script>

<template>
    <section class="home-section">
        <header class="home-rail-head">
            <span class="home-eyebrow">Integrations</span>
            <h2 class="home-title">Four web servers, one source of truth</h2>
            <p class="home-lede">
                The same OWASP CRS rule set is converted into the native syntax of each platform &mdash;
                so you get equivalent protection regardless of the proxy in front of your stack.
            </p>
        </header>

        <div class="platform-grid">
            <a
                v-for="p in platforms"
                :key="p.name"
                :href="withBase(p.href)"
                class="platform-card"
                :style="{ '--accent': p.accent }"
            >
                <span class="platform-icon">
                    <component :is="p.icon" />
                </span>
                <div class="platform-name">{{ p.name }}</div>
                <div class="platform-meta">{{ p.meta }}</div>
                <span class="platform-arrow"><IconArrow /></span>
            </a>
        </div>
    </section>

    <section class="home-section home-section--stats">
        <div class="stats-rail">
            <div v-for="s in stats" :key="s.label" class="stat-cell">
                <div class="stat-value">{{ s.value }}</div>
                <div class="stat-key">{{ s.label }}</div>
                <div class="stat-sub">{{ s.sub }}</div>
            </div>
        </div>
    </section>
</template>
