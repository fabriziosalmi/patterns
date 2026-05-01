# Traefik Integration

This guide explains how to consume the generated WAF middleware in **Traefik v2 / v3**.

## Quick start

1. Download `traefik_waf.zip` from the [latest release](https://github.com/fabriziosalmi/patterns/releases/latest).
2. Drop the TOML files into your dynamic configuration directory.
3. Reference the middleware from each router that should be protected.

## Files in the archive

| File | Purpose |
|------|---------|
| `middleware.toml` | WAF middleware definition (regex patterns per category) |
| `bots.toml` | Bad-bot User-Agent middleware |

## Step 1 &mdash; Enable the file provider

::: code-group

```toml [traefik.toml]
[providers]
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

## Step 2 &mdash; Drop the TOML files in

```bash
sudo cp waf_patterns/traefik/*.toml /etc/traefik/dynamic/
```

Traefik picks them up automatically because `watch = true`.

## Step 3 &mdash; Reference the middleware

::: code-group

```toml [dynamic/routes.toml]
[http.routers.app]
  rule = "Host(`example.com`)"
  service = "app"
  middlewares = ["waf-protection", "bot-blocker"]
```

```yaml [dynamic/routes.yml]
http:
  routers:
    app:
      rule: "Host(`example.com`)"
      service: app
      middlewares:
        - waf-protection
        - bot-blocker
```

:::

The middleware names (`waf-protection`, `bot-blocker`) are the keys defined inside `middleware.toml` and `bots.toml`.

## Docker labels

For Docker / Compose deployments, attach the middleware via labels:

```yaml
services:
  app:
    image: my-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`example.com`)"
      - "traefik.http.routers.app.middlewares=waf-protection@file,bot-blocker@file"
```

The `@file` suffix tells Traefik to resolve the middleware from the file provider.

## Plugin compatibility

`middleware.toml` is generated against Traefik's built-in middleware primitives. If you prefer a dedicated WAF plugin (e.g. one of the community plugins on [Traefik Plugins](https://plugins.traefik.io/)), you can declare it side-by-side and chain both:

```yaml
experimental:
  plugins:
    waf:
      moduleName: "github.com/example/traefik-waf-plugin"
      version: "v1.0.0"
```

## Customization

### Add custom patterns

Edit `middleware.toml` to extend the regex set:

```toml
[[http.middlewares.waf-protection.plugin.rewriteHeaders.replacements]]
  regex = "your-custom-pattern"
  replacement = "BLOCKED"
```

### Logging

Enable structured access logs to track middleware decisions:

```toml
[accessLog]
  filePath = "/var/log/traefik/access.log"
  format = "json"
  [accessLog.fields]
    [accessLog.fields.headers]
      defaultMode = "keep"
```

## Testing

```bash
curl -H "Host: example.com" "http://localhost/?id=1' OR '1'='1"
docker logs traefik 2>&1 | grep -i blocked
```

## Troubleshooting

- **Middleware never loads** &mdash; check that the file provider directory matches and that `watch = true`. `traefik logs -f` shows hot-reload events.
- **Router does not apply the middleware** &mdash; the middleware name must match exactly (case-sensitive) between router declaration and middleware definition.
- **Latency** &mdash; regex middleware adds per-request overhead. Profile with `traefik` access logs and consider scoping the middleware to specific routers rather than applying globally.
