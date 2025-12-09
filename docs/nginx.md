# Nginx Integration

This guide explains how to integrate the WAF patterns into your Nginx configuration.

## Quick Start

1. Download `nginx_waf.zip` from [Releases](https://github.com/fabriziosalmi/patterns/releases)
2. Extract to your Nginx configuration directory
3. Include the configuration files as shown below

## Configuration Files

The Nginx WAF package includes:

| File | Purpose | Include Location |
|------|---------|------------------|
| `waf_maps.conf` | Map directives for pattern matching | `http` block |
| `waf_rules.conf` | If statements for blocking | `server` block |
| `bots.conf` | Bad bot detection maps | `http` block |

## Integration

### Step 1: Include Maps in HTTP Block

The map directives **must** be included in the `http` context:

```nginx
http {
    # Include WAF maps (pattern definitions)
    include /path/to/waf_patterns/nginx/waf_maps.conf;
    
    # Include bot detection maps
    include /path/to/waf_patterns/nginx/bots.conf;
    
    # ... other http configurations ...
}
```

### Step 2: Include Rules in Server Block

The blocking rules go inside your `server` or `location` block:

```nginx
server {
    listen 80;
    server_name example.com;
    
    # Include WAF rules
    include /path/to/waf_patterns/nginx/waf_rules.conf;
    
    # ... other server configurations ...
}
```

### Step 3: Reload Nginx

Test and reload the configuration:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## How It Works

The WAF uses Nginx's `map` directive for efficient pattern matching:

```nginx
map $request_uri $waf_block_sqli {
    default 0;
    "~*union.*select" 1;
    "~*insert.*into" 1;
}

if ($waf_block_sqli) {
    return 403;
}
```

## Customization

### Enable Logging

To log blocked requests, edit `waf_rules.conf` and uncomment the logging lines:

```nginx
if ($waf_block_sqli) {
    return 403;
    access_log /var/log/nginx/waf_blocked.log;
}
```

### Whitelist Specific Paths

Add exceptions before the WAF rules:

```nginx
location /api/webhook {
    # Skip WAF for this path
    # ... your configuration ...
}

# WAF rules for other paths
include /path/to/waf_patterns/nginx/waf_rules.conf;
```

::: warning Important
Individual category files like `attack.conf` or `xss.conf` should **not** be included directly. They contain both `map` and `if` directives which cannot be used in the same context. Always use `waf_maps.conf` + `waf_rules.conf`.
:::

## Testing

Test your WAF configuration with common attack patterns:

```bash
# Should be blocked (SQL injection)
curl -I "http://example.com/?id=1' OR '1'='1"

# Should be blocked (XSS)
curl -I "http://example.com/?q=<script>alert(1)</script>"
```

## Troubleshooting

### Configuration errors
Always run `nginx -t` before reloading to catch syntax errors.

### False positives
If legitimate requests are being blocked, check `/var/log/nginx/error.log` and consider adding path-specific exceptions.

### Performance
The map-based approach is highly efficient. For high-traffic sites, consider enabling caching for the map variables.
