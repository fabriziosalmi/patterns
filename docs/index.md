---
layout: home

hero:
  name: Patterns
  text: Production-grade WAF rules, on autopilot.
  tagline: Automated OWASP Core Rule Set and bad-bot patterns, converted into native configurations for Nginx, Apache, Traefik, and HAProxy &mdash; refreshed every day.
  image:
    src: /hero-shield.svg
    alt: Patterns
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/fabriziosalmi/patterns

features:
  - icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4.5 5.8v6.1c0 4.7 3.3 9.1 7.5 10.4 4.2-1.3 7.5-5.7 7.5-10.4V5.8L12 3Z"/><path d="m8.5 12 2.5 2.5L15.5 9.5"/></svg>'
    title: OWASP CRS Protection
    details: Defends against SQL injection, XSS, RCE, LFI, and RFI by deriving rules from the OWASP Core Rule Set &mdash; the same engine that powers ModSecurity worldwide.
  - icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="7.5" width="16" height="11" rx="3"/><path d="M12 4v3.5"/><circle cx="12" cy="3.5" r="0.9" fill="currentColor" stroke="none"/><circle cx="9" cy="13" r="1.1" fill="currentColor" stroke="none"/><circle cx="15" cy="13" r="1.1" fill="currentColor" stroke="none"/><path d="M2 13.5v2M22 13.5v2"/></svg>'
    title: Bad Bot Blocking
    details: Curated User-Agent lists from public sources block scrapers, AI crawlers, vulnerability scanners, and SEO spam &mdash; with configurable allow-lists for legitimate bots.
  - icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="3.5" y="4" width="17" height="6" rx="1.5"/><rect x="3.5" y="14" width="17" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/><path d="M11 7h6M11 17h6"/></svg>'
    title: Native Multi-Server Output
    details: One source rule set, four idiomatic outputs &mdash; Nginx <code>map</code>+<code>if</code>, Apache <code>SecRule</code>, Traefik middleware TOML, and HAProxy ACL files.
  - icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M3.5 12a8.5 8.5 0 0 1 14.5-6L20 8"/><path d="M20 3v5h-5"/><path d="M20.5 12a8.5 8.5 0 0 1-14.5 6L4 16"/><path d="M4 21v-5h5"/></svg>'
    title: Daily Automated Updates
    details: A GitHub Actions workflow re-fetches the latest CRS release, rebuilds every backend, and publishes a fresh release archive &mdash; without manual intervention.
  - icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8 12 3 3 8v8l9 5 9-5V8Z"/><path d="m3.3 8 8.7 5 8.7-5"/><path d="M12 13v8"/><path d="m7.5 5.5 9 5"/></svg>'
    title: Pre-Built Releases
    details: Drop-in archives are published on every run. Skip the toolchain &mdash; download <code>nginx_waf.zip</code>, <code>apache_waf.zip</code>, <code>traefik_waf.zip</code>, or <code>haproxy_waf.zip</code>.
  - icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4.5a2 2 0 1 0-4 0V6H6a1.5 1.5 0 0 0-1.5 1.5V11h1.5a2 2 0 1 1 0 4H4.5v3.5A1.5 1.5 0 0 0 6 20h3.5v-1.5a2 2 0 1 1 4 0V20H17a1.5 1.5 0 0 0 1.5-1.5V15H20a2 2 0 1 0 0-4h-1.5V7.5A1.5 1.5 0 0 0 17 6h-3V4.5Z"/></svg>'
    title: Composable & Extensible
    details: Each backend is a small Python converter that consumes a single JSON intermediate. Adding a new platform is a few hundred lines &mdash; not a fork.
---

<div class="home-section">

## Quick start

Pull the latest release archive and include it in your existing server configuration &mdash; no toolchain required.

```bash
# Pick the archive that matches your stack
curl -LO https://github.com/fabriziosalmi/patterns/releases/latest/download/nginx_waf.zip
unzip nginx_waf.zip -d /etc/nginx/waf_patterns
```

Or build from source to customize before deploying:

```bash
git clone https://github.com/fabriziosalmi/patterns.git
cd patterns
pip install -r requirements.txt
python owasp2json.py            # Fetch the latest OWASP CRS
python json2nginx.py            # Or json2apache.py / json2traefik.py / json2haproxy.py
python badbots.py               # Generate bad-bot blocklists
```

::: tip Using Caddy?
See the dedicated [caddy-waf](https://github.com/fabriziosalmi/caddy-waf) project for Caddy-specific WAF support.
:::

</div>
