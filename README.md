<div align="center">
  <img src="docs/public/logo.svg" alt="Patterns" width="64" height="64" />
  <h1>Patterns</h1>
  <p><strong>Production-grade WAF rules, on autopilot.</strong></p>
  <p>
    Automated <a href="https://github.com/coreruleset/coreruleset">OWASP Core Rule Set</a> and
    bad-bot patterns, converted into native configurations for
    <strong>Nginx</strong>, <strong>Apache</strong>, <strong>Traefik</strong>, <strong>HAProxy</strong>, and <strong>Envoy</strong>
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

The output covers SQL injection, XSS, RCE, LFI, RFI and protocol violations. What it stops is measured, not claimed: see [What this catches](#what-this-catches).

## What this catches

A ModSecurity rule is not only a regular expression. It also carries a
transformation chain (`t:urlDecodeUni`, `t:htmlEntityDecode`, ...) that the
pattern is written to run *after*, and an anomaly score that lets several weak
signals accumulate before anything is refused. An `nginx` `map` has neither. It
matches one regex against one raw request component, and that is all it can do.

So the converted rule set is measured against ordinary traffic and against
attacks, with `nginx` itself, by [`tests/test_nginx_blocking.py`](tests/test_nginx_blocking.py).
Against the rules in this repository (the nginx row of the table below), 164
ordinary requests in twelve categories of what a false positive looks like, and 21
attacks ([`patterns/corpus.py`](patterns/corpus.py)):

| | |
|---|---|
| Ordinary requests refused | **0 of 164** |
| Attacks refused, sent in clear | **17 of 21** |
| Attacks refused, percent-encoded | **6 of 21** |

The gap between the last two rows is the transformation chain. `nginx` cannot
url-decode inside a `map`, so a pattern written to run after `t:urlDecodeUni`
sees `%3Cscript%3E` where CRS would have seen `<script>`. Everything that
depends on decoding is caught in clear and missed encoded, with one exception that
is the point of `$uri`: the request path. nginx has already decoded and normalised
it by the time a map reads it, which is the `t:urlDecodeUni`, `t:normalizePath` chain
the rules on the path declare, so `/%2egit/config` is `/.git/config` to them.

Three further limits, all visible in the header of the generated
`waf_maps.conf`:

- **Rules that would refuse ordinary traffic are not emitted.** Converted
  without its transformations, CRS 920230 (`%[0-9a-fA-F]{2}`, `t:urlDecodeUni`)
  means "still percent-encoded after one decode", that is, double encoding.
  Against a raw URI it means "contains a percent-encoded character", which is
  most URLs. Such rules are excluded, each named in the generated file with the
  request that matched it, and again in the test output. Adding a request to the
  corpus can exclude more: that is what it is for, and what a reported false
  positive should do first (see CONTRIBUTING).
- **Rules that are part of a chain are not emitted.** A chain matches when every
  record does, and a record on its own is another rule. The head of CRS 920480 is
  any `charset=` in a Content-Type, and the link that makes it a rule (the charset is
  not one that is allowed) reads a transaction variable that no target here has. It
  was written alone, and refused `application/json; charset=utf-8` in **all four
  targets**: nothing in the corpus had a charset, so nothing noticed, and every
  release carried it until the corpus did. 128 records are in a chain; none is
  written, and the corpus has the Content-Types that clients send.
- **Rules that record rather than refuse are not emitted.** CRS 921170 is
  `@rx .`, matches any character, declares `pass`, and exists to count repeated
  parameter names.
- **`@rx`, `@pm` and `@pmFromFile` convert.** The two phrase operators are a
  case-insensitive match against a list, which is an alternation of the phrases,
  written in as few `map` keys as nginx's parameter limit allows (14 rules, 28 keys,
  from the 6,125 phrases the IR carries). That is what catches a scanner
  User-Agent and a request for `/.env` or `/.git/config`, which CRS refuses with
  `@pmFromFile`. `@detectSQLi` and `@detectXSS` are libinjection and `@lt`/`@ge` are
  anomaly-score comparisons: none of them is a regular expression or a list, so none
  can become a `map` key.

This is a useful first filter in front of an application, and it is not a
replacement for a WAF that can apply transformations and keep score. If you need
that on `nginx`, use ModSecurity; on Caddy, see
[`caddy-waf`](https://github.com/fabriziosalmi/caddy-waf).

### What each target does with each rule

Whether a rule is written is not the same as whether it means what CRS wrote, so
every rule gets a verdict per target: written in full, written with a named loss,
written as something it is not (*unsound*), or dropped with a reason. This is
generated from the same record the files are built from, for all four targets
([how to read it](https://fabriziosalmi.github.io/patterns/coverage)):

<!-- coverage:start -->
Of the 749 records in the CRS v4.29.0 intermediate representation, what each target does:

| Target | Full | Approximate | Unsound | Dropped |
|---|---:|---:|---:|---:|
| Nginx | 11 | 159 | 0 | 579 |
| Apache (ModSecurity) | 8 | 172 | 0 | 569 |
| Traefik | 1 | 4 | 0 | 744 |
| HAProxy | 7 | 173 | 0 | 569 |
| Envoy | 7 | 177 | 0 | 565 |

**Why a record is dropped**, by the first reason the backend found:

| Reason | Nginx | Apache (ModSecurity) | Traefik | HAProxy | Envoy |
|---|---:|---:|---:|---:|---:|
| an operator the backend cannot express | 292 | 292 |  | 292 | 292 |
| matched on a request component the target does not have | 78 | 78 | 561 | 78 | 78 |
| part of a chain, and the target cannot require all of it | 128 | 128 | 128 | 128 | 128 |
| not a rule: it changes another rule | 54 | 54 | 54 | 54 | 54 |
| it refuses ordinary traffic once converted | 10 | 16 |  | 8 | 4 |
| its severity is below what refuses, and the target cannot only record |  |  | 1 | 8 | 8 |
| longer than the target accepts | 16 |  |  |  |  |
| it records and does not refuse | 1 | 1 |  | 1 | 1 |

**What a written rule loses**, in how many of them:

| Loss | Nginx | Apache (ModSecurity) | Traefik | HAProxy | Envoy |
|---|---:|---:|---:|---:|---:|
| matched on other variables than the rule names | 153 | 167 | 4 | 173 | 177 |
| transformations the rule was written to run after are not applied | 122 | 122 | 3 | 121 | 125 |
<!-- coverage:end -->

The nginx figures above are measured on the rules in its row here. The table is
rebuilt with the rules every night; the figures in prose are not, and are kept
honest by the floors in the tests rather than by being regenerated.

### Does it load?

Every target has been run through its real server with the same corpus, by
[`tests/test_nginx_blocking.py`](tests/test_nginx_blocking.py),
[`tests/test_traefik_blocking.py`](tests/test_traefik_blocking.py),
[`tests/test_apache_blocking.py`](tests/test_apache_blocking.py) and
[`tests/test_haproxy_blocking.py`](tests/test_haproxy_blocking.py) and
[`tests/test_envoy_blocking.py`](tests/test_envoy_blocking.py). **All five load what
is generated, and none of them refuses an ordinary request of the corpus.** Two of them
did not until recently:

HAProxy did not load however its file was used ([#67](https://github.com/fabriziosalmi/patterns/issues/67),
[#68](https://github.com/fabriziosalmi/patterns/issues/68)): the rules were `acl` lines with
expressions HAProxy's parser takes for unmatched quotes, a fetch it does not have and one line of
hundreds of names, documented as a pattern file that it was not. It is now what was
documented: pattern files, which HAProxy reads a regular expression to a line, and a
`waf.cfg` to paste into a `frontend`. The test runs it in a real HAProxy: of the 21
attacks, 17 are refused in clear and 14 percent-encoded (`url_dec`), and 0 of the 164
ordinary requests. Its phrase lists (`@pmFromFile`: `/.env`, `/.git/config`, scanners) are the
`*.data` files, loaded with `-m sub -i -f`.

Apache was not loading until [#55](https://github.com/fabriziosalmi/patterns/issues/55):
it wrote the operators CRS names as if they were patterns, after `re.escape` had turned
them into other patterns (`Failed to resolve operator: lt\`), and its bad-bot list gave
every rule the same id ([#80](https://github.com/fabriziosalmi/patterns/issues/80)). It
now writes `@rx` as CRS wrote it, and the test runs it in a real Apache with ModSecurity:
none of the 164 ordinary requests is refused, and 17 of the 21 attacks are, in clear
and percent-encoded, because ModSecurity decodes `ARGS` before a rule reads it, which
`nginx` cannot do. Its phrase lists (`@pmFromFile`, which CRS uses for `/.env`, `/.git/config` and
scanners) are written as the `*.data` files ModSecurity reads from next to the rules.

Traefik needs a plugin, which Traefik's output was not written for until
[#69](https://github.com/fabriziosalmi/patterns/issues/69): it is now written for
[`traefik-plugin-blockuseragent`](https://github.com/agence-gaya/traefik-plugin-blockuseragent),
and the test runs that plugin, unmodified. The plugin sees only the User-Agent, so
the CRS rules that can be written for Traefik are five (three that share one expression, and the two
phrase lists, as one alternation each); its bad-bot list does the
rest, and it is checked not to refuse search engines, link previews or monitors
([#78](https://github.com/fabriziosalmi/patterns/issues/78)).

Each test records what the target does as the known state and fails the day it
changes, so this section and the tests are kept together. Each also runs first
against a small configuration that is known to load, so that the traffic phase is
tested before it has anything real to measure.

## Highlights

| | |
|---|---|
| **OWASP CRS coverage** | SQLi, XSS, RCE, LFI, RFI, plus generic anomaly and protocol-violation rules. |
| **Native output** | Nginx `map`/`if`, Apache `SecRule`, Traefik middleware TOML, HAProxy pattern files, an Envoy RBAC filter. |
| **Bad-bot blocking** | User-Agent lists from public sources. Search engines, link previews and uptime monitors are left out of them, and the nginx, Apache, Traefik, HAProxy and Envoy tests check it in the real server. HTTP libraries and tools (`curl`, `python-requests`, OkHttp, ...) are refused on purpose. |
| **Nightly, tested** | A scheduled GitHub Actions workflow rebuilds every backend, runs the tests on the result, and publishes only if they pass and something changed. |
| **Pre-built, signed archives** | Skip the toolchain &mdash; download `nginx_waf.zip`, `apache_waf.zip`, `traefik_waf.zip`, or `haproxy_waf.zip` from a dated release that is never replaced, and [verify it](https://fabriziosalmi.github.io/patterns/verify). |
| **Measured** | What each target does with each rule is generated and published: [coverage](https://fabriziosalmi.github.io/patterns/coverage). |
| **Composable** | Each backend is a small Python converter on top of one JSON intermediate. Adding a new platform is a few hundred lines. |

> Using **Caddy**? See the dedicated [`caddy-waf`](https://github.com/fabriziosalmi/caddy-waf) project.

## Quick start

### Option 1 &mdash; download a pre-built release

```bash
# Pick the archive that matches your stack
curl -LO https://github.com/fabriziosalmi/patterns/releases/latest/download/nginx_waf.zip
unzip nginx_waf.zip -d /etc/nginx/waf_patterns
```

> Every target loads in its real server: see [Does it load?](#does-it-load). Releases are
> dated (`2026-10-01-crs-v4.29.0`), never replaced and signed; [verify one](https://fabriziosalmi.github.io/patterns/verify)
> before you deploy it, or pin to it with `releases/download/<tag>/`.

Then follow the [Nginx](https://fabriziosalmi.github.io/patterns/nginx),
[Apache](https://fabriziosalmi.github.io/patterns/apache),
[Traefik](https://fabriziosalmi.github.io/patterns/traefik),
[HAProxy](https://fabriziosalmi.github.io/patterns/haproxy), or
[Envoy](https://fabriziosalmi.github.io/patterns/envoy) integration guide.

### Option 2 &mdash; build from source

Requires **Python 3.11+**, `pip`, and `git`.

```bash
git clone https://github.com/fabriziosalmi/patterns.git
cd patterns
pip install -r requirements.txt

python owasp2json.py                         # 1. Fetch the latest OWASP CRS into owasp_rules.json
python3 -m patterns build --all              # 2. Compile it for every target…
python3 -m patterns build --target nginx     #    …or for one: nginx, apache, traefik, haproxy, envoy
python badbots.py                            # 3. Generate bad-bot blocklists
```

`python3 -m patterns list` shows the targets, and `python3 -m patterns validate` checks `owasp_rules.json` against [its schema](https://fabriziosalmi.github.io/patterns/ir). The `json2*.py` scripts still work, and print that they are deprecated.

Generated files land in `waf_patterns/<platform>/`.

## Architecture

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

Each target is a backend registered in `patterns/backends/`, and building is deterministic: the same `owasp_rules.json` gives the same files, byte for byte, which CI checks with `python3 -m patterns build --all --check`. Full reference at [docs/api](https://fabriziosalmi.github.io/patterns/api).

## Repository layout

```text
patterns/
├── owasp2json.py            # Pull and parse OWASP CRS into a JSON intermediate
├── patterns/                # The compiler: python3 -m patterns
│   ├── ir.py                #   load and validate the intermediate representation
│   ├── backends/            #   one module per target: nginx, apache, traefik, haproxy, envoy
│   ├── cli.py               #   list, validate, build
│   └── corpus.py            #   the traffic every backend is measured against
├── schema/                  # The JSON Schema of owasp_rules.json
├── json2*.py                # Deprecated entry points, one per target
├── badbots.py               # Public bot lists → per-platform blocklists
├── import_*_waf.py          # Optional installers for each platform
├── waf_patterns/            # Generated outputs
│   ├── nginx/
│   ├── apache/
│   ├── traefik/
│   ├── haproxy/
│   └── envoy/
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
      middlewares: [waf_rce_user_agent@file, bad_bot_block@file]
```

### HAProxy

```haproxy
frontend http-in
    bind *:80
    # the lines of waf.cfg: an acl for each pattern file and phrase list, and one deny
    acl waf_query_string_urldecode query,url_dec(1) -m reg -f /etc/haproxy/waf/waf-query-string-urldecode.acl
    acl waf_user_agent_scanners_user_agents hdr(user-agent) -m sub -i -f /etc/haproxy/waf/scanners-user-agents.data
    http-request deny deny_status 403 if waf_query_string_urldecode or waf_user_agent_scanners_user_agents
    # the bad-bot list, a pattern file
    acl bad_bot hdr(user-agent) -m reg -i -f /etc/haproxy/waf/bots.acl
    http-request deny deny_status 403 if bad_bot
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

The default list blocks SEO crawlers, AI training bots, and known scanners, and does not refuse major search engines (Google, Bing, DuckDuckGo, Yandex, Baidu), link previews or uptime monitors: [Bad Bot Detection](https://fabriziosalmi.github.io/patterns/badbots) says how that is kept true.

## Automation

| Workflow | Schedule | Purpose |
|----------|----------|---------|
| [`update_patterns.yml`](.github/workflows/update_patterns.yml) | Daily + manual | Re-fetch CRS, regenerate every backend, publish a release |
| [`test_nginx.yml`](.github/workflows/test_nginx.yml) | On PR | Validate generated Nginx rules against a live container |
| [`test_conformance.yml`](.github/workflows/test_conformance.yml) | On PR | Run the generated Apache, HAProxy, Traefik and Envoy files in the real servers, and send them the corpus |
| [`test_ir.yml`](.github/workflows/test_ir.yml) | On PR | The IR, the backends, the coverage matrix, the corpus, the releases and the diff |
| [`docs.yml`](.github/workflows/docs.yml) | On `docs/` change | Build and deploy the VitePress docs to GitHub Pages |

All workflows run on **GitHub-hosted runners** (`ubuntu-latest`).

## Documentation

The full documentation lives at **[fabriziosalmi.github.io/patterns](https://fabriziosalmi.github.io/patterns/)** &mdash; built with [VitePress](https://vitepress.dev/) and deployed automatically.

- [Getting Started](https://fabriziosalmi.github.io/patterns/getting-started)
- [Nginx](https://fabriziosalmi.github.io/patterns/nginx) &middot; [Apache](https://fabriziosalmi.github.io/patterns/apache) &middot; [Traefik](https://fabriziosalmi.github.io/patterns/traefik) &middot; [HAProxy](https://fabriziosalmi.github.io/patterns/haproxy) &middot; [Envoy](https://fabriziosalmi.github.io/patterns/envoy)
- [Bad Bot Detection](https://fabriziosalmi.github.io/patterns/badbots)
- [API & Scripts Reference](https://fabriziosalmi.github.io/patterns/api)

## Commercial support & consulting

Running these WAF rules in production? I offer paid support, custom rule development, and security consulting - WAF tuning, hardening, TLS automation, and cloud detection & alerting. Reach out: **fabrizio.salmi@gmail.com**.

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-change`.
3. Commit and push.
4. Open a pull request &mdash; the test workflows will run automatically.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details and [SECURITY.md](SECURITY.md) for the disclosure policy.

## License

The **original code** of this project &mdash; the Python converters, the
documentation, and the tests &mdash; is released under the [MIT License](LICENSE)
(Copyright &copy; Fabrizio Salmi).

The **generated data** is not covered by that MIT grant. `owasp_rules.json` and
everything under `waf_patterns/**` are derived/converted from third-party
sources &mdash; chiefly the [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)
(Apache-2.0), plus public bad-bot and referrer-spam lists &mdash; and are
redistributed under those upstream licenses, not under MIT. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the source-by-source
breakdown and [`LICENSES/`](LICENSES/) for the required license texts.

## Resources

- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)
- [ModSecurity](https://modsecurity.org/)
- [Nginx](https://nginx.org/) &middot; [Apache HTTPD](https://httpd.apache.org/) &middot; [Traefik](https://traefik.io/) &middot; [HAProxy](https://www.haproxy.org/) &middot; [Envoy](https://www.envoyproxy.io/)
- Bad-bot &amp; referrer-spam sources &mdash; [Crawler-Detect](https://github.com/JayBizzle/Crawler-Detect), [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker), [referrer-spam-blacklist](https://github.com/matomo-org/referrer-spam-blacklist)

---

<div align="center">
  <sub>Built and maintained by <a href="https://github.com/fabriziosalmi">Fabrizio Salmi</a>.</sub>
</div>
