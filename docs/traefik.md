# Traefik Integration

This guide explains how to integrate the WAF patterns with Traefik using middleware plugins.

## Quick Start

1. Download `traefik_waf.zip` from [Releases](https://github.com/fabriziosalmi/patterns/releases)
2. Extract the files
3. Configure the middleware in your Traefik configuration

## Configuration Files

The Traefik WAF package includes:

| File | Purpose |
|------|---------|
| `middleware.toml` | WAF middleware configuration |
| `bots.toml` | Bad bot detection rules |

## Integration with File Provider

### Step 1: Enable File Provider

In your `traefik.toml` or `traefik.yml`:

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

### Step 2: Copy Middleware Files

Copy the WAF configuration files to your dynamic configuration directory:

```bash
cp waf_patterns/traefik/*.toml /etc/traefik/dynamic/
```

### Step 3: Apply Middleware to Routes

Reference the middleware in your router configuration:

::: code-group

```toml [dynamic/routes.toml]
[http.routers.my-router]
  rule = "Host(`example.com`)"
  service = "my-service"
  middlewares = ["waf-protection", "bot-blocker"]

[http.middlewares.waf-protection.plugin.waf]
  # WAF configuration loaded from middleware.toml

[http.middlewares.bot-blocker.plugin.botblocker]
  # Bot blocking loaded from bots.toml
```

```yaml [dynamic/routes.yml]
http:
  routers:
    my-router:
      rule: "Host(`example.com`)"
      service: my-service
      middlewares:
        - waf-protection
        - bot-blocker
```

:::

## Integration with Docker Labels

For Docker-based deployments:

```yaml
services:
  my-app:
    image: my-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.my-app.rule=Host(`example.com`)"
      - "traefik.http.routers.my-app.middlewares=waf@file"
```

## Middleware Configuration

The `middleware.toml` contains regex-based blocking rules:

```toml
[http.middlewares.waf.plugin.rewriteHeaders]
  # SQL Injection patterns
  [[http.middlewares.waf.plugin.rewriteHeaders.replacements]]
    regex = "(?i)union.*select"
    replacement = "BLOCKED"
```

## Using with Traefik Plugins

For enhanced WAF capabilities, consider using community plugins:

```yaml
experimental:
  plugins:
    waf:
      moduleName: "github.com/example/traefik-waf-plugin"
      version: "v1.0.0"
```

## Customization

### Add Custom Patterns

Edit `middleware.toml` to add your own patterns:

```toml
[[http.middlewares.waf.plugin.rewriteHeaders.replacements]]
  regex = "your-custom-pattern"
  replacement = "BLOCKED"
```

### Logging

Enable access logs to monitor blocked requests:

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
# Test WAF detection
curl -H "Host: example.com" \
  "http://localhost/?id=1' OR '1'='1"

# Check Traefik logs
docker logs traefik 2>&1 | grep -i blocked
```

## Troubleshooting

### Middleware not loading
Check that the file provider is correctly configured and watching the right directory.

### Routes not applying middleware
Ensure the middleware name matches exactly between router and middleware definition.

### Performance considerations
Traefik's regex-based middleware can impact performance at high traffic. Monitor latency after enabling WAF rules.
