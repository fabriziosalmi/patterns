# Nginx Integration

This guide explains how to wire the generated rules into an Nginx configuration. Nginx is the one target whose output loads today: see [Does it load?](https://github.com/fabriziosalmi/patterns#does-it-load) for the other three.

## Quick start

1. Download `nginx_waf.zip` from the [latest release](https://github.com/fabriziosalmi/patterns/releases/latest) (or from a [pinned one](/verify)) and extract it (e.g. into `/etc/nginx/waf_patterns/nginx/`).
2. Include `waf_maps.conf` from the `http` block.
3. Include `waf_rules.conf` from each `server` (or `location`) you want to protect.
4. Reload Nginx.

## Files in the archive

| File | Purpose | Where to include |
|------|---------|------------------|
| `waf_maps.conf` | One `map` for each request variable the rules can see: `$args`, `$request_uri`, `$http_user_agent`, `$http_host`, `$http_referer` and `$http_content_type`. Each sets a `$waf_*` variable to `"<severity>:<category>"` on a match, and to `""` otherwise | `http` block |
| `waf_rules.conf` | For each of those variables, `if ($waf_… ~ "^high") { return 403; }` | `server` or `location` block |
| `bots.conf` | `map $http_user_agent $bad_bot` for User-Agent filtering | `http` block |
| `README.md` | Usage notes, in the archive | |

The header of `waf_maps.conf` lists the rules that were **left out** and why: the ones that record rather than refuse, the ones too long for Nginx to accept, and the ones that match ordinary traffic once converted, each with the request that matched it.

## What it can and cannot do

A `map` matches one regular expression against one raw request variable, and that is all. It does not apply the transformations CRS writes its patterns for (URL-decoding, case folding, ...), it cannot read the request body, and it does not add up an anomaly score. So it catches an attack written in clear far more often than the same attack percent-encoded. [What this catches](https://github.com/fabriziosalmi/patterns#what-this-catches) says how much, measured, and [Coverage](/coverage) says what the matrix does with each rule. Treat it as a useful first filter in front of an application, not as a WAF.

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
    listen 443 ssl;
    server_name example.com;

    include /etc/nginx/waf_patterns/nginx/waf_rules.conf;

    if ($bad_bot) { return 403; }

    # …your locations
}
```

Only a `high` severity match refuses the request. Lower severities are recorded in the variables and do not block; they are there for logging.

## Step 3 &mdash; Validate and reload

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## How it works

Every OWASP regular expression that Nginx can express becomes a key of a `map`:

```nginx
map $args $waf_args {
    default "";
    "~*union[\s\S]+select"  "high:sqli";
    # …
}

# …in waf_rules.conf, in a server block:
if ($waf_args ~ "^high") {
    return 403;
}
```

Nginx checks the keys of a regular-expression `map` in the order they appear and takes the first that matches. The cost of a lookup therefore grows with the number of keys, which is a few dozen per variable, not a constant. Measure it on your own traffic before you rely on it staying out of your latency.

## Customization

### Run it in detection mode first

Include the maps and not the rules, and log what would have been refused:

```nginx
http {
    include /etc/nginx/waf_patterns/nginx/waf_maps.conf;

    # 1 when any variable matched, 0 when none did
    map "$waf_args$waf_request_uri$waf_http_user_agent$waf_http_referer" $waf_seen {
        ""      0;
        default 1;
    }

    log_format waf '$remote_addr "$request" args=$waf_args uri=$waf_request_uri ua="$http_user_agent"';
}

server {
    access_log /var/log/nginx/waf.log waf if=$waf_seen;
    # waf_rules.conf is not included: nothing is refused
}
```

Each line carries `"<severity>:<category>"` for the variables that matched. Read it against your own traffic, then include `waf_rules.conf`.

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

Probe the deployment with a known-bad payload sent in clear, and a browser's User-Agent:

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
curl -I -A "$UA" "https://example.com/?q=hello"                       # 200
curl -I -A "$UA" "https://example.com/?id=1'+OR+'1'='1"               # 403
curl -I -A "$UA" "https://example.com/?q=<script>alert(1)</script>"   # 403
```

Without `-A` the probe tells you nothing: `bots.conf` lists `curl`, so with `if ($bad_bot)` in place every request from `curl` is refused, the ordinary one too. The same payloads percent-encoded (`%3Cscript%3E`) are mostly **not** caught: that is the transformation chain Nginx cannot apply, and the reason the table in the README has two rows.

## Troubleshooting

- **`nginx: [emerg] unknown "waf_args" variable`** &mdash; `waf_rules.conf` is included and `waf_maps.conf` is not, or the maps are not in the `http` block.
- **`"map" directive is not allowed here`** &mdash; `waf_maps.conf` or `bots.conf` was included in a `server` block. They belong in `http`.
- **False positives** &mdash; log the `$waf_*` variables as above to see which variable and category matched, then add a `location`-scoped exemption. If an ordinary request is being refused, [report it](https://github.com/fabriziosalmi/patterns/blob/main/CONTRIBUTING.md#reporting-or-fixing-a-false-positive): it becomes an entry in the corpus the generator checks every rule against, so it stays fixed.
