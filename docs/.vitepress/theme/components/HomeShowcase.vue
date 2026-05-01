<script setup>
import IconNginx from './icons/IconNginx.vue'
import IconApache from './icons/IconApache.vue'
import IconTraefik from './icons/IconTraefik.vue'
import IconHaproxy from './icons/IconHaproxy.vue'
import IconArrow from './icons/IconArrow.vue'
import { withBase } from 'vitepress'

const platforms = [
  { name: 'Nginx',   meta: 'map directives + if rules',     href: '/nginx',   icon: IconNginx   },
  { name: 'Apache',  meta: 'ModSecurity SecRule directives', href: '/apache',  icon: IconApache  },
  { name: 'Traefik', meta: 'Middleware TOML configuration',  href: '/traefik', icon: IconTraefik },
  { name: 'HAProxy', meta: 'ACL pattern files',              href: '/haproxy', icon: IconHaproxy }
]
</script>

<template>
  <section class="home-section">
    <div class="home-eyebrow">Integrations</div>
    <h2 class="home-title">Four web servers, one source of truth</h2>
    <p class="home-lede">
      The same OWASP CRS rule set is converted into the native syntax of each platform &mdash;
      so you get equivalent protection whether you run Nginx, Apache, Traefik, or HAProxy.
    </p>

    <div class="platform-grid">
      <a
        v-for="p in platforms"
        :key="p.name"
        :href="withBase(p.href)"
        class="platform-card"
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

  <section class="home-section">
    <div class="stats-strip">
      <div class="stat-item">
        <div class="stat-value">600+</div>
        <div class="stat-label">OWASP CRS patterns extracted</div>
      </div>
      <div class="stat-item">
        <div class="stat-value">Daily</div>
        <div class="stat-label">Automated rule refresh</div>
      </div>
      <div class="stat-item">
        <div class="stat-value">4</div>
        <div class="stat-label">Web server backends</div>
      </div>
      <div class="stat-item">
        <div class="stat-value">MIT</div>
        <div class="stat-label">Open-source license</div>
      </div>
    </div>
  </section>
</template>
