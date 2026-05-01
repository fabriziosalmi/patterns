<script setup lang="ts">
const features = [
    {
        eyebrow: '01',
        title: 'OWASP CRS coverage',
        body: 'Rules for SQL injection, XSS, RCE, LFI, and RFI, derived from the same Core Rule Set behind ModSecurity.'
    },
    {
        eyebrow: '02',
        title: 'Native multi-server output',
        body: 'One source, four idiomatic backends — Nginx maps, Apache SecRule, Traefik middleware, HAProxy ACL files.'
    },
    {
        eyebrow: '03',
        title: 'Bad-bot blocking',
        body: 'Curated User-Agent lists from public sources — scrapers, AI crawlers, scanners, with allow-lists for legitimate engines.'
    },
    {
        eyebrow: '04',
        title: 'Daily automated rebuild',
        body: 'A scheduled GitHub Actions workflow re-fetches the latest CRS release and republishes every archive — no maintenance.'
    },
    {
        eyebrow: '05',
        title: 'Pre-built archives',
        body: 'Drop-in zips published on every run: nginx_waf.zip, apache_waf.zip, traefik_waf.zip, haproxy_waf.zip.'
    },
    {
        eyebrow: '06',
        title: 'Composable pipeline',
        body: 'Each backend is a small Python converter on a single JSON intermediate. Adding a platform is a few hundred lines.'
    }
]
</script>

<template>
    <section class="home-rail">
        <header class="home-rail-head">
            <span class="home-eyebrow">Capabilities</span>
            <h2 class="home-title">Engineered for production</h2>
            <p class="home-lede">
                Six guarantees that turn a daily scrape of upstream rules into something your traffic can actually
                live behind &mdash; quietly, predictably, and without operator toil.
            </p>
        </header>

        <ul class="rail-grid">
            <li v-for="f in features" :key="f.title" class="rail-item">
                <span class="rail-eyebrow">{{ f.eyebrow }}</span>
                <h3 class="rail-title">{{ f.title }}</h3>
                <p class="rail-body">{{ f.body }}</p>
            </li>
        </ul>
    </section>
</template>

<style scoped>
.home-rail {
    max-width: 1120px;
    margin: 0 auto;
    padding: 24px 24px 80px;
}

.home-rail-head {
    margin-bottom: 56px;
    max-width: 720px;
}

.rail-grid {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0;
    border-top: 1px solid var(--vp-c-divider);
}

@media (max-width: 900px) {
    .rail-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media (max-width: 600px) {
    .rail-grid {
        grid-template-columns: 1fr;
    }
}

.rail-item {
    position: relative;
    padding: 28px 24px 32px 0;
    border-bottom: 1px solid var(--vp-c-divider);
}

.rail-item:not(:nth-child(3n)) {
    border-right: 1px solid var(--vp-c-divider);
    padding-right: 24px;
}
.rail-item:not(:nth-child(3n)) {
    padding-left: 24px;
}
.rail-item:nth-child(3n+1) {
    padding-left: 0;
}

@media (max-width: 900px) {
    .rail-item:not(:nth-child(3n)) {
        border-right: none;
    }
    .rail-item:nth-child(odd) {
        border-right: 1px solid var(--vp-c-divider);
        padding-right: 24px;
        padding-left: 0;
    }
    .rail-item:nth-child(even) {
        padding-left: 24px;
        padding-right: 0;
    }
}

@media (max-width: 600px) {
    .rail-item,
    .rail-item:nth-child(odd),
    .rail-item:nth-child(even) {
        border-right: none !important;
        padding: 24px 0 24px 0;
    }
}

.rail-eyebrow {
    display: inline-block;
    font-family: var(--vp-font-family-mono);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.08em;
    color: var(--vp-c-text-3);
    margin-bottom: 14px;
}

.rail-title {
    font-size: 1.05rem;
    font-weight: 600;
    letter-spacing: -0.015em;
    color: var(--vp-c-text-1);
    margin: 0 0 8px;
    line-height: 1.3;
}

.rail-body {
    font-size: 0.92rem;
    line-height: 1.55;
    color: var(--vp-c-text-2);
    margin: 0;
}
</style>
