# HAProxy Integration

This guide explains how to integrate the WAF patterns with HAProxy using ACL rules.

## Quick Start

1. Download `haproxy_waf.zip` from [Releases](https://github.com/fabriziosalmi/patterns/releases)
2. Extract the files
3. Include the ACL files in your HAProxy configuration

## Configuration Files

The HAProxy WAF package includes:

| File | Purpose |
|------|---------|
| `waf.acl` | Main WAF ACL rules |
| `bots.acl` | Bad bot detection ACLs |

## Integration

### Step 1: Include ACL Files

In your `haproxy.cfg`, include the WAF ACL files:

```haproxy
frontend http-in
    bind *:80
    
    # Include WAF ACL rules
    acl waf_block_sqli path_reg -i union.*select
    acl waf_block_sqli path_reg -i insert.*into
    acl waf_block_xss path_reg -i <script>
    
    # Or include from external file
    # acl waf_patterns path_reg -i -f /etc/haproxy/waf.acl
    
    # Block matching requests
    http-request deny if waf_block_sqli
    http-request deny if waf_block_xss
    
    default_backend servers
```

### Step 2: Include Bot Blockers

```haproxy
frontend http-in
    bind *:80
    
    # Bad bot detection
    acl bad_bot hdr_reg(User-Agent) -i -f /etc/haproxy/bots.acl
    http-request deny if bad_bot
    
    default_backend servers
```

### Step 3: Reload HAProxy

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
```

## ACL Rule Format

HAProxy ACLs use pattern matching on various request attributes:

```haproxy
# Match path
acl sqli_path path_reg -i union.*select

# Match query string
acl sqli_query url_param(id) -m reg -i union.*select

# Match headers
acl bad_referer hdr_reg(Referer) -i malicious-site\.com

# Combined conditions
http-request deny if sqli_path OR sqli_query
```

## Complete Example

```haproxy
global
    log /dev/log local0
    maxconn 4096

defaults
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client 50s
    timeout server 50s

frontend http-in
    bind *:80
    
    # WAF Rules
    acl waf_sqli path_reg -i (union.*select|insert.*into|delete.*from)
    acl waf_xss path_reg -i (<script|javascript:|on\w+\s*=)
    acl waf_lfi path_reg -i (\.\.\/|\.\.\\)
    acl waf_rce path_reg -i (;|\||`|\$\()
    
    # Bot blocking
    acl bad_bot hdr_reg(User-Agent) -i (AhrefsBot|SemrushBot|MJ12bot)
    
    # Deny malicious requests
    http-request deny deny_status 403 if waf_sqli
    http-request deny deny_status 403 if waf_xss
    http-request deny deny_status 403 if waf_lfi
    http-request deny deny_status 403 if waf_rce
    http-request deny deny_status 403 if bad_bot
    
    default_backend servers

backend servers
    balance roundrobin
    server server1 127.0.0.1:8080 check
```

## Customization

### Custom Error Pages

Return a custom error page for blocked requests:

```haproxy
http-request deny deny_status 403 content-type text/html \
    string "Access Denied" if waf_sqli
```

### Logging Blocked Requests

Create a dedicated log for WAF blocks:

```haproxy
frontend http-in
    # Log blocked requests
    http-request set-var(txn.blocked) str(1) if waf_sqli
    http-request capture var(txn.blocked) len 1
    
    # Custom log format
    log-format "%ci:%cp [%t] %ft %b/%s %Tq/%Tw/%Tc/%Tr/%Tt %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq blocked=%[var(txn.blocked)]"
```

### Whitelist Paths

Skip WAF for specific paths:

```haproxy
acl is_api path_beg /api/webhook
http-request deny if waf_sqli !is_api
```

## Rate Limiting

Combine WAF with rate limiting:

```haproxy
# Stick table for rate limiting
stick-table type ip size 100k expire 30s store http_req_rate(10s)
http-request track-sc0 src
acl too_many_requests sc_http_req_rate(0) gt 100

http-request deny if too_many_requests
```

## Testing

```bash
# Test SQL injection detection
curl -I "http://example.com/?id=1' UNION SELECT * FROM users--"

# Test bot blocking
curl -A "AhrefsBot" -I "http://example.com/"

# Check HAProxy stats
echo "show stat" | socat stdio /var/run/haproxy.sock
```

## Troubleshooting

### ACLs not matching
Use `haproxy -c -f haproxy.cfg` to validate syntax. Enable debug logging to see ACL evaluation.

### Performance impact
ACL evaluation is fast, but complex regex patterns can add latency. Test with realistic traffic.

### Configuration too large
HAProxy has limits on configuration size. Consider splitting large ACL lists into multiple files.
