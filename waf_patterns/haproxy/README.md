# HAProxy WAF Configuration

This directory contains HAProxy WAF configuration files generated from OWASP CRS rules.
You can include these ACL (Access Control List) files in your HAProxy configuration to enhance security.

## Prerequisites

- HAProxy 2.0 or higher
- Basic understanding of HAProxy ACLs and rules

## Configuration Files

The generated files include:
- ACL files with pattern matching rules
- Request filtering configurations
- Bad bot/User-Agent blocking lists

## Usage

1. Copy the generated ACL files to your HAProxy configuration directory:
   ```bash
   sudo cp waf_patterns/haproxy/*.acl /etc/haproxy/
   ```

2. Include the ACL files in your HAProxy configuration.
   
   Edit `/etc/haproxy/haproxy.cfg`:
   ```haproxy
   frontend http-in
       bind *:80
       
       # Load WAF ACL files
       acl is_sql_injection path_reg -i -f /etc/haproxy/sqli_patterns.acl
       acl is_xss_attack path_reg -i -f /etc/haproxy/xss_patterns.acl
       acl is_bad_bot hdr_reg(User-Agent) -i -f /etc/haproxy/bad_bots.acl
       
       # Block malicious requests
       http-request deny if is_sql_injection
       http-request deny if is_xss_attack
       http-request deny if is_bad_bot
       
       # Default backend
       default_backend web_servers
   
   backend web_servers
       balance roundrobin
       server web1 10.0.0.1:80 check
       server web2 10.0.0.2:80 check
   ```

3. Test the configuration:
   ```bash
   sudo haproxy -c -f /etc/haproxy/haproxy.cfg
   ```

4. Reload HAProxy to apply the changes:
   ```bash
   sudo systemctl reload haproxy
   # or
   sudo service haproxy reload
   ```

## Advanced Configuration

### Logging Blocked Requests

Add logging for better visibility:

```haproxy
frontend http-in
    bind *:80
    
    # ... ACL definitions ...
    
    # Log blocked requests
    http-request capture req.hdr(User-Agent) len 200
    http-request deny deny_status 403 if is_sql_injection
    log-format "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"
```

### Custom Error Pages

Return custom error pages for blocked requests:

```haproxy
frontend http-in
    bind *:80
    
    # ... ACL definitions ...
    
    # Return custom error page
    http-request deny deny_status 403 if is_sql_injection
    errorfile 403 /etc/haproxy/errors/403.http
```

### Rate Limiting

Combine with rate limiting for additional protection:

```haproxy
frontend http-in
    bind *:80
    
    # Track request rate
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    
    # Deny if rate limit exceeded
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }
    
    # ... WAF ACLs ...
```

## Testing

### Test SQL Injection Protection
```bash
curl "http://yourserver.com/?id=1' OR '1'='1"
# Should return 403 Forbidden
```

### Test XSS Protection
```bash
curl "http://yourserver.com/?q=<script>alert('xss')</script>"
# Should return 403 Forbidden
```

### Test Bad Bot Blocking
```bash
curl -H "User-Agent: AhrefsBot" http://yourserver.com
# Should return 403 Forbidden
```

## Monitoring

### Check HAProxy Stats
```bash
# Enable stats in haproxy.cfg
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 10s
```

Visit `http://yourserver:8404/stats` to view statistics.

### View Logs
```bash
sudo tail -f /var/log/haproxy.log
```

## Performance Considerations

- ACL pattern matching is highly efficient in HAProxy
- Use regular expressions sparingly for better performance
- Consider using stick tables for rate limiting
- Monitor CPU and memory usage under load
- Test thoroughly before deploying to production

## Configuration Details

The ACL files protect against:
- **SQL Injection (SQLi)** - Common SQL injection patterns
- **Cross-Site Scripting (XSS)** - JavaScript injection attempts
- **Remote Code Execution (RCE)** - Command injection patterns
- **Local File Inclusion (LFI)** - Path traversal attempts
- **Bad Bots** - Known malicious crawlers and scrapers

## Notes

- Rules are updated daily via GitHub Actions
- Blocked requests return `403 Forbidden` by default
- ACLs are case-insensitive (`-i` flag)
- Regular expressions are used for pattern matching (`-f` for file-based ACLs)
- Compatible with HAProxy 2.0 and higher

## Resources

- [HAProxy Documentation](https://www.haproxy.org/#docs)
- [HAProxy ACL Guide](https://www.haproxy.com/documentation/hapee/latest/onepage/#7)
- [OWASP CRS](https://coreruleset.org/)
- [HAProxy Configuration Manual](http://cbonte.github.io/haproxy-dconv/)
