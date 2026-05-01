# HAProxy Integration

This guide explains how to plug the generated rules into HAProxy using **ACL** files.

## Quick start

1. Download `haproxy_waf.zip` from the [latest release](https://github.com/fabriziosalmi/patterns/releases/latest).
2. Drop the ACL files into `/etc/haproxy/` (or any path you prefer).
3. Reference them from a `frontend` block.
4. Reload HAProxy.

## Files in the archive

| File | Purpose |
|------|---------|
| `waf.acl` | Pre-compiled regex patterns covering every OWASP CRS category |
| `bots.acl` | Bad-bot User-Agent patterns |

## Step 1 &mdash; Reference the ACL files

The cleanest approach is to load the patterns from disk with `-f`:

```haproxy
frontend http-in
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/

    acl waf_match    path,url_dec -m reg -i -f /etc/haproxy/waf.acl
    acl waf_match_q  query        -m reg -i -f /etc/haproxy/waf.acl
    acl bad_bot      hdr(User-Agent) -m reg -i -f /etc/haproxy/bots.acl

    http-request deny deny_status 403 if waf_match || waf_match_q || bad_bot

    default_backend servers
```

## Step 2 &mdash; Validate and reload

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
```

## ACL primer

HAProxy ACLs match against fetch samples (path, query, headers, …) using converters and matchers:

```haproxy
# Match path against a regex
acl sqli_path  path -m reg -i union.*select

# Match a specific query parameter
acl sqli_qid   url_param(id) -m reg -i union.*select

# Match a request header
acl bad_ref    hdr(Referer) -m reg -i malicious-site\.com

# Combine with boolean operators
http-request deny if sqli_path || sqli_qid
```

## A complete example

```haproxy
global
    log /dev/log local0
    maxconn 4096

defaults
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client  50s
    timeout server  50s

frontend http-in
    bind *:80

    # WAF
    acl waf_match    path,url_dec -m reg -i -f /etc/haproxy/waf.acl
    acl waf_match_q  query        -m reg -i -f /etc/haproxy/waf.acl
    acl bad_bot      hdr(User-Agent) -m reg -i -f /etc/haproxy/bots.acl

    # Block matching requests
    http-request deny deny_status 403 if waf_match || waf_match_q || bad_bot

    default_backend servers

backend servers
    balance roundrobin
    server srv1 127.0.0.1:8080 check
```

## Customization

### Custom error response

Return a styled error body instead of the default empty 403:

```haproxy
http-request deny deny_status 403 \
    content-type "text/html; charset=utf-8" \
    string "<h1>Blocked by WAF</h1>" if waf_match
```

### Logging blocked requests

```haproxy
http-request set-var(txn.blocked) str(1) if waf_match
http-request capture var(txn.blocked) len 1

log-format "%ci:%cp [%t] %ft %b/%s %ST %B blocked=%[var(txn.blocked)] ua=%[capture.req.hdr(0)]"
```

### Per-path whitelist

```haproxy
acl is_webhook path_beg /api/webhook
http-request deny deny_status 403 if waf_match !is_webhook
```

### Combine with rate limiting

```haproxy
stick-table type ip size 100k expire 30s store http_req_rate(10s)
http-request track-sc0 src
acl too_many sc_http_req_rate(0) gt 100
http-request deny deny_status 429 if too_many
```

## Testing

```bash
curl -I "http://example.com/?id=1' UNION SELECT * FROM users--"
curl -A "AhrefsBot" -I "http://example.com/"

echo "show stat" | sudo socat stdio /var/run/haproxy.sock
```

## Troubleshooting

- **ACL never matches** &mdash; run `haproxy -c -f haproxy.cfg` to validate the syntax. Use `-d` for debug output to watch ACL evaluation in real time.
- **Performance impact** &mdash; complex regex over `path,url_dec` adds per-request cost. Benchmark with realistic traffic before enabling globally.
- **Configuration too large** &mdash; the converter keeps `waf.acl` flat and grep-friendly. Split it across multiple files if you need to apply different rule subsets to different frontends.
