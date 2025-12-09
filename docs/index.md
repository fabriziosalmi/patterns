---
layout: home

hero:
  name: Patterns
  text: OWASP WAF Rules for Web Servers
  tagline: Automated OWASP CRS patterns and Bad Bot detection for Nginx, Apache, Traefik, and HAProxy
  image:
    src: /shield.svg
    alt: Patterns
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/fabriziosalmi/patterns

features:
  - icon: 🛡️
    title: OWASP CRS Protection
    details: Leverages OWASP Core Rule Set for web application firewall defense against SQLi, XSS, RCE, and LFI attacks.
  - icon: 🤖
    title: Bad Bot Blocking
    details: Blocks known malicious bots and scrapers using regularly updated public bot lists.
  - icon: ⚙️
    title: Multi-Server Support
    details: Generates WAF configs for Nginx, Apache, Traefik, and HAProxy with consistent protection across platforms.
  - icon: 🔄
    title: Daily Updates
    details: GitHub Actions automatically fetch new OWASP rules daily and push updated configurations.
  - icon: 📦
    title: Pre-Generated Configs
    details: Download ready-to-use WAF configurations from GitHub Releases without building from source.
  - icon: 🧩
    title: Extensible Design
    details: Modular architecture makes it easy to extend support to other web servers or load balancers.
---

## Quick Start

Download the latest configurations from [GitHub Releases](https://github.com/fabriziosalmi/patterns/releases) or build from source:

```bash
git clone https://github.com/fabriziosalmi/patterns.git
cd patterns
pip install -r requirements.txt
python owasp2json.py
python json2nginx.py  # or json2apache.py, json2traefik.py, json2haproxy.py
```

## Supported Platforms

| Platform | Config Format | Documentation |
|----------|---------------|---------------|
| **Nginx** | `.conf` files | [Read more →](/nginx) |
| **Apache** | ModSecurity rules | [Read more →](/apache) |
| **Traefik** | Middleware TOML | [Read more →](/traefik) |
| **HAProxy** | ACL files | [Read more →](/haproxy) |

::: tip Using Caddy?
Check out the [caddy-waf](https://github.com/fabriziosalmi/caddy-waf) project for Caddy-specific WAF support.
:::
