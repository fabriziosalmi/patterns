# Nginx Integration

This guide explains how to wire the generated rules into an Nginx configuration.

## Quick start

1. Download `nginx_waf.zip` from the [latest release](https://github.com/fabriziosalmi/patterns/releases/latest) and extract it (e.g. into `/etc/nginx/waf_patterns/nginx/`).
2. Include `waf_maps.conf` from the `http` block.
3. Include `waf_rules.conf` from each `server` (or `location`) you want to protect.
4. Reload Nginx.

## Files in the archive

| File | Purpose | Where to include |
|------|---------|------------------|
| `waf_maps.conf` | Defines `map` variables for every attack category | `http` block |
| `waf_rules.conf` | `if (...) { return 403; }` rules that consume those maps | `server` or `location` block |
| `bots.conf` | `map $http_user_agent $bad_bot` for User-Agent filtering | `http` block |
| `sqli.conf`, `xss.conf`, `rce.conf`, `lfi.conf`, … | Per-category files for inspection only | **Do not include directly** |

::: warning Use only the two main files
The per-category `.conf` files (`attack.conf`, `xss.conf`, `sqli.conf`, …) are emitted for inspection. They contain both `map` and `if` directives, which Nginx does not allow in the same context. Always include `waf_maps.conf` + `waf_rules.conf` instead.
:::

## Step 1 &mdash; Include the maps

The `map` directives must live in the `http` context:

```nginx
http {
    include /etc/nginx/waf_patterns/nginx/waf_maps.conf;
    include /etc/nginx/waf_patterns/nginx/bots.conf;

    # …rest of your http config
}
```

## Step 2 &mdash; Include the rules

Place the blocking rules inside any `server` block you want to protect:

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    include /etc/nginx/waf_patterns/nginx/waf_rules.conf;

    if ($bad_bot) { return 403; }

    # …your locations
}
```

## Step 3 &mdash; Validate and reload

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## How it works

The converter rewrites every OWASP regex into a `map` lookup, which Nginx evaluates with O(1) overhead per request:

```nginx
map $request_uri $waf_block_sqli {
    default 0;
    "~*union[\s\S]+select"  1;
    "~*insert[\s\S]+into"   1;
}

# …elsewhere, in a server block:
if ($waf_block_sqli) { return 403; }
```

The full set of map variables is `$waf_block_<category>` &mdash; one per attack family the OWASP CRS defines.

## Customization

### Log blocked requests

Add a dedicated access log next to the deny:

```nginx
log_format waf_block '$remote_addr - [$time_local] "$request" '
                     'blocked=$waf_block_sqli ua="$http_user_agent"';

server {
    access_log /var/log/nginx/waf_blocked.log waf_block if=$waf_block_sqli;
    include /etc/nginx/waf_patterns/nginx/waf_rules.conf;
}
```

### Whitelist a path

Skip the WAF inside specific routes by branching before the include:

```nginx
location = /api/webhook {
    proxy_pass http://upstream;
    # waf_rules.conf intentionally not included here
}

location / {
    include /etc/nginx/waf_patterns/nginx/waf_rules.conf;
    proxy_pass http://upstream;
}
```

## Testing

Probe the deployment with known-bad payloads &mdash; both should return `403`:

```bash
curl -I "https://example.com/?id=1' OR '1'='1"
curl -I "https://example.com/?q=<script>alert(1)</script>"
```

## Troubleshooting

- **`nginx: configuration file test failed`** &mdash; you likely included a per-category file. Switch to `waf_maps.conf` + `waf_rules.conf`.
- **False positives** &mdash; check `/var/log/nginx/error.log`, identify the matching `$waf_block_*` variable, then add a `location`-scoped exemption.
- **High traffic** &mdash; the `map`-based design is already the fastest option Nginx offers; no further tuning is normally needed.
