# Bad Bot Detection

`badbots.py` generates per-platform User-Agent blocklists alongside the OWASP rules, so you can drop noisy crawlers, AI scrapers, and known abusive scanners in a single include.

## How it works

1. The script fetches three public lists: [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker), [Crawler-Detect](https://github.com/JayBizzle/Crawler-Detect) and the Matomo [referrer-spam-blacklist](https://github.com/matomo-org/referrer-spam-blacklist).
2. It deduplicates them, and leaves out every entry that would refuse an ordinary client (below).
3. It emits one file per platform under `waf_patterns/<platform>/`.
4. The daily GitHub Actions workflow regenerates and republishes these files alongside the OWASP-derived rules.

A source that cannot be fetched is skipped. If none can, the script stops with an error and writes nothing, so the previous files stay.

## Generated files

| Platform | File | Format |
|----------|------|--------|
| Nginx | `bots.conf` | `map $http_user_agent $bad_bot` |
| Apache | `bots.conf` | One ModSecurity `SecRule` (`@rx`) per entry, each with an id of its own |
| Traefik | `bots.toml` | Middleware regex replacements |
| HAProxy | `bots.acl` | A pattern file: one regular expression to a line, for `-m reg -i -f` |

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
acl bad_bot hdr(user-agent) -m reg -i -f /etc/haproxy/waf/bots.acl
http-request deny deny_status 403 if bad_bot
```

## Traefik

`bots.toml` is a middleware named `bad_bot_block` for the [`blockuseragent`](https://github.com/agence-gaya/traefik-plugin-blockuseragent) plugin: a list of Go regular expressions, each matched against the `User-Agent` header, case ignored.

```toml
[http.middlewares.bad_bot_block.plugin.blockuseragent]
  regex = [ '(?i)008\/', '(?i)AhrefsBot', ... ]
```

Register the plugin in Traefik's static configuration and reference `bad_bot_block@file` from the routers you want to protect: [Traefik](/traefik) has both steps. An entry Go's regular expressions cannot compile (a lookahead, a backreference) is left out of the file, with a comment that says which, because one such entry stops the whole middleware from starting.

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

The ones that name themselves in the User-Agent:

- GPTBot, ChatGPT-User
- ClaudeBot, Anthropic-AI
- CCBot, Bytespider

### General scrapers

- DataForSeoBot
- PetalBot
- Bytespider

### Malicious scanners

Public vulnerability scanners and spam bots that have no legitimate reason to crawl your origin.

## What it leaves out, and what it refuses on purpose

Run through a real server, the list built straight from those sources refused Googlebot, Bingbot and every other search engine, every link preview (Slack, WhatsApp, Facebook, Discord...) and every uptime monitor (#78): one of its entries matches any User-Agent with `bot` in it, and others name Pingdom, StatusCake or WhatsApp outright. A bad-bot list that does that is an outage.

So `badbots.py` leaves out any entry that an ordinary client matches. *Ordinary* is what [the corpus](https://github.com/fabriziosalmi/patterns/blob/main/patterns/corpus.py) says it is, the same one every CRS rule is checked against: the browsers, the search engines (Google, Bing, DuckDuckGo, Baidu, Yandex, Apple), the link previews, the monitors, and an internal service. Each file starts with a comment line for every entry left out and the client it would have refused. Today that is the `bot|crawl|spider|...` catch-all, `Pingdom`, `StatusCake`, `WhatsApp`, `facebookexternalhit`, `Disco`, `baidu.com`, `Yandex(?!Search)`, `Apache-HttpClient` and `oBot`, which is a piece of the word `robots` in Slack's agent.

::: tip What the tests send
The nginx, Apache, Traefik and HAProxy tests start the real server with the written list, and send it the bots the list is made of (a scanner, AhrefsBot, SemrushBot, MJ12bot), every client of the corpus a site wants, and the HTTP libraries. The list has to refuse the first, none of the second, and the third.
:::

**HTTP libraries and tools are refused on purpose.** `curl`, `python-requests`, `Go-http-client`, OkHttp, Dart, node-fetch, axios, `Java/`, Wget, HTTPie and Postman are in the list, and a request that carries one of them as its User-Agent gets a 403, an ordinary one too, and that includes a mobile app that has not set a User-Agent of its own. The first thing a scraper does is run one of them with its default agent, and that is what the list is for. If you serve an API to scripts or to your own apps, or monitor the site with `curl`, remove the entry, or whitelist the agent as below, and give your apps a User-Agent of their own.

Because the list now has fewer entries, a bot that only the catch-all caught is let through. The specific names the sources list are still refused.

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
