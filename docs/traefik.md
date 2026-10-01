# Traefik Integration

This guide explains how to consume the generated middleware in **Traefik v2 / v3**.

Traefik has no built-in middleware that matches a header against a regular expression, so the output needs a plugin. It is written for [`agence-gaya/traefik-plugin-blockuseragent`](https://github.com/agence-gaya/traefik-plugin-blockuseragent) (Apache-2.0, in Traefik's plugin catalog): a list of regular expressions, matched against the `User-Agent` header, and a `403` when one matches.

::: warning What this can and cannot do
The plugin sees the `User-Agent` header and nothing else: not the path, the query string, the cookies or the body. Of the CRS rules, only the few that are aimed at that header and that refuse (three at the time of writing) can be written for it, so `middleware.toml` is short. The part that does most of the work is the bad-bot list, `bots.toml`. For the rest of what CRS covers, see [Coverage](/coverage), and use a WAF that reads requests (Coraza, ModSecurity) in front of or behind Traefik.
:::

::: warning The bad-bot list refuses search engines today
`bots.toml` contains a catch-all entry that matches any User-Agent with `bot`, `crawl` or `spider` in it, which includes Googlebot and Bingbot ([#78](https://github.com/fabriziosalmi/patterns/issues/78)). Until that is fixed, do not put it in front of a site that wants to be indexed.
:::

## Quick start

1. Download `traefik_waf.zip` from the [latest release](https://github.com/fabriziosalmi/patterns/releases/latest) (or from a [pinned one](/verify)).
2. Register the plugin in the **static** configuration.
3. Drop the TOML files into your dynamic configuration directory.
4. Reference the middlewares from each router that should be protected.

## Files in the archive

| File | Purpose |
|------|---------|
| `middleware.toml` | The CRS rules that can be written for a User-Agent plugin: one middleware per category, e.g. `waf_rce_user_agent` |
| `bots.toml` | The bad-bot list: one middleware, `bad_bot_block` |

## Step 1 &mdash; Register the plugin

Plugins are declared in the static configuration, under the name the generated files use, `blockuseragent`:

::: code-group

```toml [traefik.toml]
[experimental.plugins.blockuseragent]
  moduleName = "github.com/agence-gaya/traefik-plugin-blockuseragent"
  version = "v0.1.8"
```

```yaml [traefik.yml]
experimental:
  plugins:
    blockuseragent:
      moduleName: github.com/agence-gaya/traefik-plugin-blockuseragent
      version: v0.1.8
```

:::

Traefik downloads the plugin when it starts, so it needs to reach the plugin catalog. `v0.1.8` is the version the generated output is tested with.

## Step 2 &mdash; Enable the file provider

::: code-group

```toml [traefik.toml]
[providers.file]
  directory = "/etc/traefik/dynamic"
  watch = true
```

```yaml [traefik.yml]
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
```

:::

## Step 3 &mdash; Drop the TOML files in

```bash
sudo cp waf_patterns/traefik/*.toml /etc/traefik/dynamic/
```

## Step 4 &mdash; Reference the middlewares

The names are the keys defined inside the files. List them:

```bash
grep -ho '^\[http\.middlewares\.[A-Za-z0-9_]*\]' /etc/traefik/dynamic/*.toml
```

The names of the rules' middlewares follow the categories CRS has rules for, so they can change when the rules are refreshed. Bundle them in a `chain` of your own and reference that:

::: code-group

```toml [dynamic/routes.toml]
[http.middlewares.waf.chain]
  middlewares = ["waf_rce_user_agent", "bad_bot_block"]

[http.routers.app]
  rule = "Host(`example.com`)"
  service = "app"
  middlewares = ["waf"]
```

```yaml [dynamic/routes.yml]
http:
  middlewares:
    waf:
      chain:
        middlewares:
          - waf_rce_user_agent
          - bad_bot_block
  routers:
    app:
      rule: "Host(`example.com`)"
      service: app
      middlewares:
        - waf
```

:::

## Docker labels

For Docker / Compose deployments, attach the middlewares through the file provider's names, with the `@file` suffix:

```yaml
services:
  app:
    image: my-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`example.com`)"
      - "traefik.http.routers.app.middlewares=waf_rce_user_agent@file,bad_bot_block@file"
```

## Customization

### Add your own patterns

Add an expression to the `regex` list of a middleware. They are Go regular expressions ([RE2](https://github.com/google/re2/wiki/Syntax): no lookahead, lookbehind or backreferences), matched anywhere in the header, case-sensitive unless they start with `(?i)`. Write them as TOML *literal* strings (`'...'`), so that backslashes mean what they say:

```toml
[http.middlewares.my_blocklist.plugin.blockuseragent]
  regex = [
    '(?i)MyCustomBot',
  ]
```

### Allow a client

The plugin has a second list, `regexAllow`, checked first: a User-Agent that matches it is let through whatever `regex` says.

```toml
[http.middlewares.bad_bot_block.plugin.blockuseragent]
  regexAllow = ['(?i)Googlebot']
```

### Logging

The plugin logs each refusal (the expression's index, the User-Agent, the address, the host and the URI) to Traefik's log. To see what the middlewares do per request, enable the access log:

```toml
[accessLog]
  filePath = "/var/log/traefik/access.log"
  format = "json"
```

## Testing

```bash
curl -s -o /dev/null -w "%{http_code}\n" -A "Mozilla/5.0" http://localhost/            # 200
curl -s -o /dev/null -w "%{http_code}\n" -A "sqlmap/1.8"  http://localhost/            # 403, if bad_bot_block is on the route
```

## Troubleshooting

- **Everything returns `404`, or the routers are missing** &mdash; the file provider rejected a file. Traefik logs the reason at start (`ERR Error while building configuration`).
- **`error compiling regex ...`** &mdash; an expression uses something RE2 does not have, and the whole middleware does not start. The generated files only contain expressions RE2 compiles; this is for the ones you added.
- **The plugin is not found** &mdash; it is declared under `experimental.plugins` in the *static* configuration, with the name `blockuseragent`, and Traefik can reach the plugin catalog.
- **A legitimate client is refused** &mdash; check which expression matched in Traefik's log, then add the client to `regexAllow`. If an ordinary request is refused by a rule from `middleware.toml`, [report it](https://github.com/fabriziosalmi/patterns/blob/main/CONTRIBUTING.md#reporting-or-fixing-a-false-positive).
