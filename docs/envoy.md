# Envoy Integration

Envoy has no WAF in it, and no rule language. What it has that can refuse a request on what it says is the **RBAC HTTP filter**: a list of policies, each a set of permissions (a header, the path) that match a request, and with `action: DENY` a request that matches one gets a `403` from Envoy itself. A header or a path can be matched against a regular expression, in RE2, or against a string. That is what the generated files are. Every example below was run against Envoy 1.32 (`envoyproxy/envoy:v1.32.13`).

## What it can and cannot do

Each rule is written as CRS wrote it, a regular expression or a list of phrases, matched on what its location is:

- **Only `@rx`, `@pm` and `@pmFromFile` are written**, not negated, not part of a chain, and only a rule of severity `high`: a `DENY` cannot only record. `@detectSQLi`, `@detectXSS`, the numeric comparisons and the byte-range checks are dropped.
- **A phrase list is a permission for each phrase**, not a regular expression: `string_match: {contains: <phrase>, ignore_case: true}`, which is what `@pm` does (a substring, case ignored; ASCII is folded and other bytes are matched as they are). This is how `/.env`, `/.git/config` and a scanner's User-Agent are refused. It needs nothing from `runtime.yaml`. The price is size and time: `waf-rbac.yaml` has about 4,900 of them, and a request took about 0.3 ms more with 5,656 permissions on two headers (Envoy 1.32, measured).
- **RE2, so no lookahead, lookbehind or backreference.** A rule that uses one is not written.
- **Nothing is decoded.** `:path` is the path and the query string as they arrived, and `url_path` is the path alone: neither is percent-decoded, so an attack written `%3Cscript%3E` passes where the same attack in clear is refused. [What this catches](https://github.com/fabriziosalmi/patterns#what-this-catches) says how much, for nginx, which is in the same position.
- **`(?i)` is kept** and a rule CRS gives `t:lowercase` is matched with case ignored. The other transformations are not applied, and the [coverage matrix](/coverage) says which, rule by rule.
- **The query string is matched together with the path**, on `:path`: a pattern written for one value sees the path and the other values too. The request body is not matched.
- **No anomaly score.** Every rule decides alone.
- **A rule that refuses ordinary traffic is not written.** Each is checked against [a corpus of ordinary requests](https://github.com/fabriziosalmi/patterns/blob/main/patterns/corpus.py) and left out if one matches. [`tests/test_envoy_blocking.py`](https://github.com/fabriziosalmi/patterns/blob/main/tests/test_envoy_blocking.py) runs the files in a real Envoy on every change: 162 ordinary requests, none refused; of 21 attacks, 17 refused in clear and 6 percent-encoded.

At CRS v4.29.0 that is 184 rules written (7 in full, 177 with a named loss). It is a useful first filter in front of an application, not the Core Rule Set.

## Quick start

1. Download `envoy_waf.zip` from the [latest release](https://github.com/fabriziosalmi/patterns/releases/latest) (or from a [pinned one](/verify)).
2. Merge `runtime.yaml` into your bootstrap.
3. Put the item of `waf-rbac.yaml` (and of `bots-rbac.yaml`) in `http_filters`, before the router.
4. Validate and restart.

## Files in the archive

| File | Purpose |
|------|---------|
| `waf-rbac.yaml` | The RBAC filter, as an item of `http_filters`: a policy for each of `:path` (the path and the query string), `url_path` (the path alone), the User-Agent, the host (`:authority`), the referer and the content type, each a list of expressions and phrases after a comment that names the CRS rule (and the phrase list) |
| `runtime.yaml` | `layered_runtime`, to merge into the bootstrap. **Envoy does not start without it** |
| `bots-rbac.yaml` | A second filter, `waf_bots`, with the bad-bot list ([Bad Bot Detection](/badbots)) |

## Step 1 &mdash; The runtime

Envoy refuses a regular expression whose compiled RE2 program is bigger than 100, and a CRS expression is bigger:

```text
RE2 program size of 112 > max program size of 100 set for the error level threshold.
Increase configured max program size if necessary.
```

`runtime.yaml` raises the limit. Merge its `layered_runtime` into your bootstrap (the largest expression needs 19,405 at CRS v4.29.0, and the file sets a million):

```yaml
layered_runtime:
  layers:
  - name: waf
    static_layer:
      re2:
        max_program_size:
          error_level: 1000000
          warn_level: 1000000
```

## Step 2 &mdash; The filters

Put the items of the two files in `http_filters`, before `envoy.filters.http.router`. This is a bootstrap that loads (`envoy --mode validate` says `configuration ... OK`), with one expression in each filter where the files have hundreds:

```yaml
layered_runtime:
  layers:
  - name: waf
    static_layer:
      re2:
        max_program_size:
          error_level: 1000000
          warn_level: 1000000

static_resources:
  listeners:
  - name: ingress
    address:
      socket_address: { address: 0.0.0.0, port_value: 8080 }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: app }
          http_filters:
          # the item of bots-rbac.yaml, then the item of waf-rbac.yaml
          - name: waf_bots
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
              rules:
                action: DENY
                policies:
                  waf_bots_user_agent:
                    permissions:
                    - or_rules:
                        rules:
                        - header:
                            name: 'user-agent'
                            string_match:
                              safe_regex:
                                regex: '(?s:.*)(?i:AhrefsBot)(?s:.*)'
                    principals:
                    - any: true
          - name: waf
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
              rules:
                action: DENY
                policies:
                  waf_path:
                    permissions:
                    - or_rules:
                        rules:
                        - header:
                            name: ':path'
                            string_match:
                              safe_regex:
                                regex: '(?s:.*)(?:<script)(?s:.*)'
                    principals:
                    - any: true
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: app
    type: STRICT_DNS
    load_assignment:
      cluster_name: app
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: app.internal, port_value: 8000 }
```

::: warning bots-rbac.yaml refuses curl
`bots-rbac.yaml` refuses HTTP libraries and tools on purpose: a request from `curl`, `python-requests`, OkHttp, Wget and the like gets a 403 whatever it asks for. A probe without `-A` tells you nothing once it is in place. [Bad Bot Detection](/badbots) says why, and how to allow one.
:::

## Step 3 &mdash; Validate and restart

```bash
envoy -c /etc/envoy/envoy.yaml --mode validate && sudo systemctl restart envoy
```

## How it works

Envoy matches a regular expression against the **whole value**, not against a part of it: measured, `union` does not match `/a?q=union+select`. So every expression is written between two `.*`, and the dot-all flag is given to those and not to the rule's own expression, which would change what its `.` means:

```yaml
regex: '(?s:.*)(?:union)(?s:.*)'
```

A phrase is not an expression, so it is not put between `.*`: `contains` looks for it anywhere in the value, and `ignore_case` folds ASCII:

```yaml
- header:
    name: ':path'
    string_match: {contains: '/.env', ignore_case: true}
```

A deny is answered by Envoy itself, with a `403` and the body `RBAC: access denied`. The filter is evaluated for every request, and a request that matches any permission of any policy is refused, so the order of the expressions does not matter.

## Testing

Probe with a browser's User-Agent. The attack is refused in clear, and not percent-encoded, because nothing is decoded:

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
curl -I -A "$UA" "http://localhost:8080/?q=hello"                                  # 200
curl -I -A "$UA" "http://localhost:8080/?id=1'+OR+'1'='1"                          # 403
curl -I -A "$UA" "http://localhost:8080/?q=<script>alert(1)</script>"              # 403
curl -I -A "$UA" "http://localhost:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E"      # 200: not decoded
curl -I -A "$UA" "http://localhost:8080/.env"                                      # 403: restricted-files.data
curl -I -A "$UA" "http://localhost:8080/%2eenv"                                    # 200: not decoded, so a phrase in clear does not see it
curl -I -A "sqlmap/1.8" "http://localhost:8080/"                                   # 403: scanners-user-agents.data, and bots-rbac.yaml
```

## Troubleshooting

- **`RE2 program size of N > max program size of 100`** &mdash; `runtime.yaml` is not merged into the bootstrap, or it is under a `layered_runtime` that something else replaces.
- **`regex ... error`, or Envoy refuses an expression** &mdash; a CRS refresh brought one RE2 does not have. The nightly build runs the files in a real Envoy before it publishes, so a release does not carry one; if you edited a file, the message names the expression.
- **A request that should be refused is not** &mdash; check whether it is percent-encoded: nothing is decoded. Check the filter is before the router.
- **A request that should pass is refused** &mdash; the response body says `RBAC: access denied`. Find the expression: the comment above each one names the CRS rule. [Report it](https://github.com/fabriziosalmi/patterns/blob/main/CONTRIBUTING.md#reporting-or-fixing-a-false-positive): it becomes an entry in the corpus every target is checked against.
