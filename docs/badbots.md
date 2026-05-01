# Bad Bot Detection

`badbots.py` generates per-platform User-Agent blocklists alongside the OWASP rules, so you can drop noisy crawlers, AI scrapers, and known abusive scanners in a single include.

## How it works

1. The script fetches public bot lists &mdash; including [`ai.robots.txt`](https://github.com/ai-robots-txt/ai.robots.txt) and other community-curated sources.
2. It deduplicates and normalizes the User-Agent patterns.
3. It emits one file per platform under `waf_patterns/<platform>/`.
4. The daily GitHub Actions workflow regenerates and republishes these files alongside the OWASP-derived rules.

If a primary source is unreachable, the script falls back to a bundled list so the build still succeeds.

## Generated files

| Platform | File | Format |
|----------|------|--------|
| Nginx | `bots.conf` | `map $http_user_agent $bad_bot` |
| Apache | `bots.conf` | ModSecurity `SecRule` directives |
| Traefik | `bots.toml` | Middleware regex replacements |
| HAProxy | `bots.acl` | One regex per line, loadable with `-f` |

## Nginx

```nginx
# In the http block:
include /etc/nginx/waf_patterns/nginx/bots.conf;

# In any server block you want to protect:
server {
    if ($bad_bot) { return 403; }
}
```

The map looks like:

```nginx
map $http_user_agent $bad_bot {
    default 0;
    "~*AhrefsBot"   1;
    "~*SemrushBot"  1;
    "~*MJ12bot"     1;
    "~*GPTBot"      1;
    # …
}
```

## Apache

```apache
SecRule REQUEST_HEADERS:User-Agent "@rx AhrefsBot" \
    "id:200001,phase:1,deny,status:403,msg:'Bad Bot Blocked'"
```

Include the file globally or per VirtualHost:

```apache
Include /etc/apache2/waf_patterns/apache/bots.conf
```

## HAProxy

```haproxy
acl bad_bot hdr(User-Agent) -m reg -i -f /etc/haproxy/bots.acl
http-request deny deny_status 403 if bad_bot
```

## Traefik

```toml
[http.middlewares.bot-blocker]
  # populated automatically by bots.toml
```

Reference `bot-blocker@file` from the routers you want to protect.

## What gets blocked

The default list groups User-Agent patterns into four broad categories.

### SEO and marketing crawlers

Aggressive site indexers that are usually unwelcome on production traffic:

- AhrefsBot
- SemrushBot
- MJ12bot
- DotBot
- BLEXBot

### AI training crawlers

Most are documented at [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt):

- GPTBot, ChatGPT-User
- ClaudeBot, Anthropic-AI
- Google-Extended
- CCBot, Bytespider, PerplexityBot

### General scrapers

- DataForSeoBot
- PetalBot
- Bytespider

### Malicious scanners

Public vulnerability scanners and spam bots that have no legitimate reason to crawl your origin.

::: tip Search engines are not blocked
Major search engines (Googlebot, Bingbot, DuckDuckBot, Baiduspider, YandexBot) are **not** included in the default block list &mdash; blocking them harms SEO.
:::

## Customization

### Add your own pattern

```nginx
# Append in bots.conf
"~*MyCustomBot" 1;
```

```apache
SecRule REQUEST_HEADERS:User-Agent "@rx MyCustomBot" \
    "id:200999,phase:1,deny,status:403"
```

### Whitelist a bot

For Nginx, override the match before the catch-all:

```nginx
map $http_user_agent $bad_bot {
    default 0;
    "~*Googlebot"   0;   # explicit allow
    "~*AhrefsBot"   1;
}
```

### Allow bots inside a path

```nginx
location /public-api/ {
    # bypass the bot rule for this path
    proxy_pass http://upstream;
}

location / {
    if ($bad_bot) { return 403; }
    proxy_pass http://upstream;
}
```

## Regenerating manually

```bash
python badbots.py
```

The generated files end up in `waf_patterns/<platform>/`.

## Monitoring

Track which patterns actually fire in your traffic:

```bash
# Top 20 user agents that hit a 403
awk '$9 == 403 {print $12}' /var/log/nginx/access.log \
  | sort | uniq -c | sort -rn | head -20
```

If you see legitimate traffic in the list, add it to a whitelist and re-include `bots.conf` after your override.
