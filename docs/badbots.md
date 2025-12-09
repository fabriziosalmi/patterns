# Bad Bot Detection

This guide explains how to use the bad bot detection feature to block malicious crawlers and scrapers.

## Overview

The `badbots.py` script generates configuration files to block known malicious bots based on their User-Agent strings. It fetches bot lists from multiple public sources and generates blocking rules for each supported web server.

## How It Works

1. Fetches bot lists from public sources:
   - [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)
   - Various community-maintained bot lists
2. Generates blocking configurations for each platform
3. Updates configurations daily via GitHub Actions

## Generated Files

| Platform | File | Format |
|----------|------|--------|
| Nginx | `bots.conf` | Map directive |
| Apache | `bots.conf` | ModSecurity rules |
| Traefik | `bots.toml` | Middleware config |
| HAProxy | `bots.acl` | ACL patterns |

## Nginx Bot Blocker

The Nginx configuration uses a map directive:

```nginx
# In http block
map $http_user_agent $bad_bot {
    default 0;
    "~*AhrefsBot" 1;
    "~*SemrushBot" 1;
    "~*MJ12bot" 1;
    "~*DotBot" 1;
    # ... more bots
}

# In server block
if ($bad_bot) {
    return 403;
}
```

### Integration

```nginx
http {
    include /path/to/waf_patterns/nginx/bots.conf;
    
    server {
        if ($bad_bot) {
            return 403;
        }
    }
}
```

## Apache Bot Blocker

Uses ModSecurity rules:

```apache
SecRule REQUEST_HEADERS:User-Agent "@rx AhrefsBot" \
    "id:200001,phase:1,deny,status:403,msg:'Bad Bot Blocked'"
```

## HAProxy Bot Blocker

Uses ACL rules:

```haproxy
acl bad_bot hdr_reg(User-Agent) -i -f /etc/haproxy/bots.acl
http-request deny if bad_bot
```

## Blocked Bot Categories

The following categories of bots are blocked by default:

### SEO/Marketing Crawlers
- AhrefsBot
- SemrushBot
- MJ12bot
- DotBot
- BLEXBot

### AI/ML Crawlers
- GPTBot
- ChatGPT-User
- CCBot
- Google-Extended
- Anthropic-AI

### Scrapers
- DataForSeoBot
- PetalBot
- Bytespider
- ClaudeBot

### Malicious Bots
- Known vulnerability scanners
- Spam bots
- Content scrapers

## Customization

### Add Custom Bots

Edit the generated file or add your own patterns:

```nginx
# Nginx: Add to bots.conf
"~*MyCustomBot" 1;
```

```apache
# Apache: Add rule
SecRule REQUEST_HEADERS:User-Agent "@rx MyCustomBot" \
    "id:200999,deny"
```

### Whitelist Bots

For Nginx, allow specific bots:

```nginx
map $http_user_agent $bad_bot {
    default 0;
    "~*Googlebot" 0;     # Allow Google
    "~*AhrefsBot" 1;     # Block Ahrefs
}
```

### Allow All Bots for Specific Paths

```nginx
location /public-api {
    # Override bot blocking
    if ($bad_bot) {
        # Don't block here
    }
}
```

## Generate Manually

Run the script to regenerate bot lists:

```bash
python badbots.py
```

The script supports fallback lists if primary sources are unavailable.

## Monitoring

### Log Blocked Bots

Enable logging to track blocked requests:

```nginx
if ($bad_bot) {
    access_log /var/log/nginx/blocked_bots.log;
    return 403;
}
```

### Analyze Bot Traffic

```bash
# Count blocked bot requests
grep "403" /var/log/nginx/access.log | \
  awk '{print $12}' | sort | uniq -c | sort -rn | head -20
```

## Best Practices

1. **Regular Updates**: The bot lists are updated daily. Pull the latest changes or download from releases.

2. **Monitor False Positives**: Some legitimate services may use blocked User-Agents. Monitor your logs.

3. **Combine with Rate Limiting**: Use bot blocking with rate limiting for comprehensive protection.

4. **Test Before Deploying**: Verify that legitimate traffic (search engines, monitoring) is not blocked.

::: warning
Blocking search engine bots (Googlebot, Bingbot) can negatively impact SEO. The default lists do **not** block major search engines.
:::
