# HAProxy WAF Configuration

This directory contains HAProxy WAF files generated from OWASP CRS rules. HAProxy takes a regular expression from a *pattern file*, one to a line, so the rules are written as pattern files and a short `waf.cfg` that loads them.

## Prerequisites

- HAProxy 2.0 or higher (the examples were run on 3.4)

## Files

| File | What it is |
|------|-----------|
| `waf.cfg` | The `acl` lines that load the pattern files, and one `http-request deny`. Paste them into a `frontend` |
| `waf-*.acl` | Pattern files: the expressions matched on one fetch with the same converters, each after a comment that names the CRS rule |
| `bots.acl` | The bad-bot list, a pattern file of regular expressions for the User-Agent |

## Usage

1. Put the files where `waf.cfg` says they are, `/etc/haproxy/waf/` (or change the paths in it):
   ```bash
   sudo mkdir -p /etc/haproxy/waf
   sudo cp *.acl /etc/haproxy/waf/
   ```

2. Paste the lines of `waf.cfg` into a `frontend`. HAProxy has no include, and a second `-f` does not continue a section. Add the bad-bot list if you want it:
   ```haproxy
   frontend http-in
       bind *:80

       # the lines of waf.cfg
       acl waf_query_string_urldecode query,url_dec(1) -m reg -f /etc/haproxy/waf/waf-query-string-urldecode.acl
       http-request deny deny_status 403 if waf_query_string_urldecode

       # the bad-bot list
       acl bad_bot hdr(user-agent) -m reg -i -f /etc/haproxy/waf/bots.acl
       http-request deny deny_status 403 if bad_bot

       default_backend web_servers
   ```

3. Test the configuration, and reload:
   ```bash
   sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
   ```

`bots.acl` refuses HTTP libraries (`curl`, `python-requests`) on purpose.

See https://fabriziosalmi.github.io/patterns/haproxy for what the rules can and cannot do.
