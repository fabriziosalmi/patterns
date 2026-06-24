<div align="center">
  <img src="docs/public/logo.svg" alt="Patterns" width="64" height="64" />
  <h1>Patterns</h1>
  <p><strong>Production-grade WAF rules, on autopilot.</strong></p>
  <p>
    Automated <a href="https://github.com/coreruleset/coreruleset">OWASP Core Rule Set</a> and
    bad-bot patterns, converted into native configurations for
    <strong>Nginx</strong>, <strong>Apache</strong>, <strong>Traefik</strong>, and <strong>HAProxy</strong>
    &mdash; refreshed every day.
  </p>
  <p>
    <a href="https://github.com/fabriziosalmi/patterns/releases/latest"><img alt="Latest Release" src="https://img.shields.io/github/v/release/fabriziosalmi/patterns?label=release&color=0071e3"></a>
    <a href="https://github.com/fabriziosalmi/patterns/actions/workflows/update_patterns.yml"><img alt="Update workflow" src="https://github.com/fabriziosalmi/patterns/actions/workflows/update_patterns.yml/badge.svg"></a>
    <a href="https://github.com/fabriziosalmi/patterns/actions/workflows/test_nginx.yml"><img alt="Nginx tests" src="https://github.com/fabriziosalmi/patterns/actions/workflows/test_nginx.yml/badge.svg"></a>
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-1d1d1f"></a>
    <a href="https://fabriziosalmi.github.io/patterns/"><img alt="Documentation" src="https://img.shields.io/badge/docs-online-0071e3"></a>
  </p>
  <p>
    <a href="https://fabriziosalmi.github.io/patterns/">Documentation</a>
    &middot;
    <a href="https://fabriziosalmi.github.io/patterns/getting-started">Get started</a>
    &middot;
    <a href="https://github.com/fabriziosalmi/patterns/releases/latest">Latest release</a>
  </p>
</div>

---

## Why Patterns

The OWASP Core Rule Set (CRS) is the de-facto open-source rule base behind ModSecurity, but plugging it into anything other than Apache is non-trivial. Patterns automates the whole pipeline:

1. Pull the latest CRS rules straight from upstream.
2. Convert them into the **native** syntax of each web server &mdash; not a generic shim.
3. Package the output as ready-to-deploy archives, refreshed every day by GitHub Actions.

You get equivalent protection across SQL injection, XSS, RCE, LFI, and bad-bot traffic, regardless of which proxy you run.

## Highlights

| | |
|---|---|
| **OWASP CRS coverage** | SQLi, XSS, RCE, LFI, RFI, plus generic anomaly and protocol-violation rules. |
| **Native output** | Nginx `map`/`if`, Apache `SecRule`, Traefik middleware TOML, HAProxy ACL files. |
| **Bad-bot blocking** | Curated User-Agent lists from public sources, with safe defaults that do **not** block major search engines. |
| **Daily refresh** | A scheduled GitHub Actions workflow rebuilds every backend and publishes a fresh release. |
| **Pre-built archives** | Skip the toolchain &mdash; download `nginx_waf.zip`, `apache_waf.zip`, `traefik_waf.zip`, or `haproxy_waf.zip`. |
| **Composable** | Each backend is a small Python converter on top of one JSON intermediate. Adding a new platform is a few hundred lines. |

> Using **Caddy**? See the dedicated [`caddy-waf`](https://github.com/fabriziosalmi/caddy-waf) project.

## Quick start

### Option 1 &mdash; download a pre-built release

```bash
# Pick the archive that matches your stack
curl -LO https://github.com/fabriziosalmi/patterns/releases/latest/download/nginx_waf.zip
unzip nginx_waf.zip -d /etc/nginx/waf_patterns
```

Then follow the [Nginx](https://fabriziosalmi.github.io/patterns/nginx),
[Apache](https://fabriziosalmi.github.io/patterns/apache),
[Traefik](https://fabriziosalmi.github.io/patterns/traefik), or
[HAProxy](https://fabriziosalmi.github.io/patterns/haproxy) integration guide.

### Option 2 &mdash; build from source

Requires **Python 3.9+**, `pip`, and `git`.

```bash
git clone https://github.com/fabriziosalmi/patterns.git
cd patterns
pip install -r requirements.txt

python owasp2json.py            # 1. Fetch the latest OWASP CRS into owasp_rules.json
python json2nginx.py            # 2. Convert into Nginx WAF config
python json2apache.py           #    …or Apache (ModSecurity)
python json2traefik.py          #    …or Traefik middleware
python json2haproxy.py          #    …or HAProxy ACL files
python badbots.py               # 3. Generate bad-bot blocklists
```

Generated files land in `waf_patterns/<platform>/`.

## Architecture

```text
   ┌─────────────────────┐    daily cron     ┌──────────────────────┐
   │ coreruleset/        │ ───────────────▶  │ owasp2json.py        │
   │ coreruleset (GH)    │                   │   → owasp_rules.json │
   └─────────────────────┘                   └──────────┬───────────┘
                                                        │
            ┌─────────────────┬──────────────────┬──────┴──────────┐
            ▼                 ▼                  ▼                 ▼
      json2nginx.py    json2apache.py    json2traefik.py    json2haproxy.py
            │                 │                  │                 │
            ▼                 ▼                  ▼                 ▼
       nginx_waf.zip    apache_waf.zip    traefik_waf.zip    haproxy_waf.zip
                          (published as a GitHub Release)
```

Each converter is independent, idempotent, and configured exclusively through environment variables (`INPUT_FILE`, `OUTPUT_DIR`). Full reference at [docs/api](https://fabriziosalmi.github.io/patterns/api).

## Repository layout

```text
patterns/
├── owasp2json.py            # Pull and parse OWASP CRS into a JSON intermediate
├── json2nginx.py            # JSON → Nginx (map + if directives)
├── json2apache.py           # JSON → Apache (ModSecurity SecRule)
├── json2traefik.py          # JSON → Traefik (middleware TOML)
├── json2haproxy.py          # JSON → HAProxy (ACL files)
├── badbots.py               # Public bot lists → per-platform blocklists
├── import_*_waf.py          # Optional installers for each platform
├── waf_patterns/            # Generated outputs
│   ├── nginx/
│   ├── apache/
│   ├── traefik/
│   └── haproxy/
├── docs/                    # VitePress documentation site
├── tests/                   # Validation tests for each backend
└── .github/workflows/       # Daily build + release automation
```

## Integration in 60 seconds

### Nginx

```nginx
http {
    include /etc/nginx/waf_patterns/nginx/waf_maps.conf;
    include /etc/nginx/waf_patterns/nginx/bots.conf;
}
server {
    include /etc/nginx/waf_patterns/nginx/waf_rules.conf;
    if ($bad_bot) { return 403; }
}
```

### Apache (ModSecurity)

```apache
<IfModule security2_module>
    SecRuleEngine On
    Include /etc/apache2/waf_patterns/apache/*.conf
</IfModule>
```

### Traefik

```yaml
http:
  routers:
    app:
      rule: "Host(`example.com`)"
      service: app
      middlewares: [waf-protection@file, bot-blocker@file]
```

### HAProxy

```haproxy
frontend http-in
    bind *:80
    acl waf_match path,url_dec -m reg -i -f /etc/haproxy/waf.acl
    acl bad_bot   hdr(User-Agent) -m reg -i -f /etc/haproxy/bots.acl
    http-request deny deny_status 403 if waf_match || bad_bot
```

Full guides &mdash; with logging, whitelists, and tuning &mdash; live in the [docs](https://fabriziosalmi.github.io/patterns/).

## Bad-bot example output (Nginx)

```nginx
map $http_user_agent $bad_bot {
    default 0;
    "~*AhrefsBot"  1;
    "~*SemrushBot" 1;
    "~*MJ12bot"    1;
    "~*GPTBot"     1;
}

if ($bad_bot) { return 403; }
```

The default list blocks SEO crawlers, AI training bots, and known scanners while explicitly **allowing** major search engines (Google, Bing, DuckDuckGo, Yandex, Baidu).

## Automation

| Workflow | Schedule | Purpose |
|----------|----------|---------|
| [`update_patterns.yml`](.github/workflows/update_patterns.yml) | Daily + manual | Re-fetch CRS, regenerate every backend, publish a release |
| [`test_nginx.yml`](.github/workflows/test_nginx.yml) | On PR | Validate generated Nginx rules against a live container |
| [`test_apache_docker.yml`](.github/workflows/test_apache_docker.yml) | On PR | Validate generated Apache rules against ModSecurity in Docker |
| [`docs.yml`](.github/workflows/docs.yml) | On `docs/` change | Build and deploy the VitePress docs to GitHub Pages |

All workflows run on **GitHub-hosted runners** (`ubuntu-latest`).

## Documentation

The full documentation lives at **[fabriziosalmi.github.io/patterns](https://fabriziosalmi.github.io/patterns/)** &mdash; built with [VitePress](https://vitepress.dev/) and deployed automatically.

- [Getting Started](https://fabriziosalmi.github.io/patterns/getting-started)
- [Nginx](https://fabriziosalmi.github.io/patterns/nginx) &middot; [Apache](https://fabriziosalmi.github.io/patterns/apache) &middot; [Traefik](https://fabriziosalmi.github.io/patterns/traefik) &middot; [HAProxy](https://fabriziosalmi.github.io/patterns/haproxy)
- [Bad Bot Detection](https://fabriziosalmi.github.io/patterns/badbots)
- [API & Scripts Reference](https://fabriziosalmi.github.io/patterns/api)

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-change`.
3. Commit and push.
4. Open a pull request &mdash; the test workflows will run automatically.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details and [SECURITY.md](SECURITY.md) for the disclosure policy.

## License

Released under the [MIT License](LICENSE).

## Resources

- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)
- [ModSecurity](https://modsecurity.org/)
- [Nginx](https://nginx.org/) &middot; [Apache HTTPD](https://httpd.apache.org/) &middot; [Traefik](https://traefik.io/) &middot; [HAProxy](https://www.haproxy.org/)
- [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) &mdash; upstream AI-bot list

---

<div align="center">
  <sub>Built and maintained by <a href="https://github.com/fabriziosalmi">Fabrizio Salmi</a>.</sub>
</div>
