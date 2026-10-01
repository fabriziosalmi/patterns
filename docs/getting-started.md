# Getting Started

This guide walks you through installing **Patterns** and integrating the generated WAF rules into your web server.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Python 3.11+** | Only required when building from source. The CI workflow targets 3.11. |
| **pip** | To install the packages listed in `requirements.txt`. |
| **git** | Optional &mdash; only needed if cloning the repository. |

## Two installation paths

### Option 1 &mdash; Download a pre-built release

The fastest path. A scheduled GitHub Actions workflow builds every archive each night, runs the tests on the result, and publishes a dated, signed release (`2026-10-01-crs-v4.29.0`) when something changed, on the [Releases page](https://github.com/fabriziosalmi/patterns/releases/latest).

| Archive | Contains | Target |
|---------|----------|--------|
| `nginx_waf.zip` | `waf_maps.conf`, `waf_rules.conf`, `bots.conf` | Nginx |
| `apache_waf.zip` | Per-category ModSecurity `.conf` files, `bots.conf`, the phrase lists `*.data` (keep them next to the `.conf`) | Apache + mod_security2 |
| `traefik_waf.zip` | `middleware.toml`, `bots.toml` | Traefik (file provider) |
| `haproxy_waf.zip` | `waf.cfg`, pattern files `waf-*.acl`, phrase lists `*.data`, `bots.acl` | HAProxy |
| `envoy_waf.zip` | `waf-rbac.yaml`, `runtime.yaml`, `bots-rbac.yaml` | Envoy (RBAC filter) |

Pick one, extract, then jump to the matching integration guide.

Each integration guide says what its target can and cannot do at the top, and [Coverage](/coverage) says what every target does with every rule.

Releases are dated and never replaced, and every file is signed: [verify a release](/verify) before you deploy it.

### Option 2 &mdash; Build from source

Choose this path if you want to pin a specific OWASP CRS tag, customize the converter, or run the toolchain in your own CI:

```bash
git clone https://github.com/fabriziosalmi/patterns.git
cd patterns
pip install -r requirements.txt

# 1. Fetch the latest OWASP Core Rule Set into a JSON intermediate
python owasp2json.py

# 2. Compile the JSON into native rules for your platform
python3 -m patterns build --all              # every target…
python3 -m patterns build --target nginx     # …or one: nginx, apache, traefik, haproxy, envoy

# 3. Generate bad-bot blocklists alongside
python badbots.py
```

::: tip GitHub API rate limits
`owasp2json.py` reads from the GitHub API. Set `GITHUB_TOKEN` in your environment to raise the rate limit when iterating locally.
:::

## Output layout

After running the converters, generated files live under `waf_patterns/`:

```text
waf_patterns/
├── nginx/      # waf_maps.conf, waf_rules.conf, bots.conf
├── apache/     # sqli.conf, xss.conf, rce.conf, lfi.conf, … bots.conf, *.data
├── traefik/    # middleware.toml, bots.toml
├── haproxy/    # waf.cfg, waf-*.acl, *.data, bots.acl
└── envoy/      # waf-rbac.yaml, runtime.yaml, bots-rbac.yaml
```

## Next steps

Choose your platform to wire the rules into a running server:

- [Nginx integration](/nginx)
- [Apache (ModSecurity) integration](/apache)
- [Traefik integration](/traefik)
- [HAProxy integration](/haproxy)
- [Envoy integration](/envoy)

For details on the bot blocklist itself, see [Bad Bot Detection](/badbots). For a reference of every script and the JSON schema that ties them together, see the [API reference](/api).

## How updates flow

```text
   ┌─────────────────────┐    daily cron     ┌──────────────────────┐
   │ coreruleset/        │ ───────────────▶  │ owasp2json.py        │
   │ coreruleset (GH)    │                   │   → owasp_rules.json │
   └─────────────────────┘                   └──────────┬───────────┘
                                                        │
            ┌────────────┬────────────┬─────────┴──┬────────────┬────────────┐
            ▼            ▼            ▼            ▼            ▼
         nginx        apache       traefik      haproxy       envoy
                  (patterns/backends/, run by `python3 -m patterns build`)
            │            │            │            │            │
            ▼            ▼            ▼            ▼            ▼
       nginx_waf.zip apache_waf.zip traefik_waf.zip haproxy_waf.zip envoy_waf.zip
                          (published as a GitHub Release)
```

To stay current, either download the latest archive or `git pull` and re-run the converters.
