# HAProxy Integration

This guide explains how to plug the generated rules into HAProxy. HAProxy takes a regular expression from a **pattern file**, one to a line, so the rules are written as pattern files and a short `waf.cfg` that loads them. Every example below was run against HAProxy 3.4 (`haproxy:latest`).

## What it can and cannot do

Each rule is written as CRS wrote it, a regular expression or a list of phrases, matched on what its location is, with the converters it declares that HAProxy has:

- **Only `@rx`, `@pm` and `@pmFromFile` are written**, not negated, and only a rule of severity `high`: a pattern file cannot only record, so a rule below `high` is not written. `@detectSQLi`, `@detectXSS`, the numeric comparisons and the byte-range checks are dropped.
- **A phrase list is a file of its own**, the one CRS ships (`restricted-files.data` is how `/.env` and `/.git/config` are refused, `scanners-user-agents.data` how a scanner's User-Agent is), loaded with `-m sub -i -f`: each line is looked for in the value as a substring, with case ignored, which is what `@pm` does. An `@pm` that CRS writes inline gets a file of its own, `pm-<id>.data`. HAProxy scans the list for each request: with the five largest lists on three fetches each, a request took about a millisecond more than with none (HAProxy 3.4, measured). A phrase that starts with `#`, or with blank space, which HAProxy drops from a line, cannot be written as it is, and keeps its whole rule out; CRS has none today.
- **Two transformations are applied.** `t:lowercase` is HAProxy's `lower`, and `t:urlDecodeUni` is `url_dec(1)`, which decodes `%XX` and turns `+` into a space. A phrase list is matched with `-i`, so `lower` has nothing to add to it. It does not decode `%uXXXX` as ModSecurity's does, so the [coverage matrix](/coverage) still calls such a rule approximate. The others (`htmlEntityDecode`, `jsDecode`, ...) HAProxy has no converter for, and the pattern is matched on the value before them.
- **The query string is matched whole**, not parameter by parameter: a pattern written for one value sees the others too. The request body and the cookies are not matched.
- **`(?i)` is kept as CRS wrote it, in an expression.** HAProxy compiles the patterns with PCRE2, so there is no `-i` to approximate it with.
- **No anomaly score.** Every rule decides alone.
- **A rule that refuses ordinary traffic is not written.** Each is checked against [a corpus of ordinary requests](https://github.com/fabriziosalmi/patterns/blob/main/patterns/corpus.py), with its converters applied, and left out if one matches. [`tests/test_haproxy_blocking.py`](https://github.com/fabriziosalmi/patterns/blob/main/tests/test_haproxy_blocking.py) runs it through a real HAProxy on every change: 164 ordinary requests, none refused; of 21 attacks, 17 refused in clear and 14 percent-encoded.

At CRS v4.29.0 that is 180 rules written (7 in full, 173 with a named loss). It is a useful first filter in front of an application, not the Core Rule Set.

## Quick start

1. Download `haproxy_waf.zip` from the [latest release](https://github.com/fabriziosalmi/patterns/releases/latest) (or from a [pinned one](/verify)).
2. Put the files in `/etc/haproxy/waf/`.
3. Paste the lines of `waf.cfg` into a `frontend`.
4. Validate and reload.

## Files in the archive

| File | Purpose |
|------|---------|
| `waf.cfg` | The `acl` lines that load the pattern files, and one `http-request deny`. Paste them into a `frontend` |
| `waf-<where>[-<converters>].acl` | A pattern file: the expressions that are matched on the same fetch with the same converters, each after a comment that names the CRS rule. `waf-query-string-urldecode.acl` is matched on `query,url_dec(1)` |
| `<list>.data` | A phrase list CRS ships (`restricted-files.data`, `scanners-user-agents.data`, `lfi-os-files.data`, ...), one phrase to a line after a comment, loaded with `-m sub -i -f`. **They go in the same directory as the pattern files** |
| `bots.acl` | The bad-bot list, a pattern file of regular expressions for the User-Agent ([Bad Bot Detection](/badbots)) |

The header of each pattern file says which fetch it is matched on, and which `acl` of `waf.cfg` loads it.

## Step 1 &mdash; Put the files in place

```bash
sudo mkdir -p /etc/haproxy/waf
sudo unzip haproxy_waf.zip -d /etc/haproxy/waf
```

`waf.cfg` refers to `/etc/haproxy/waf/`. HAProxy resolves a relative path from where it is started, which a generated file cannot know: if you keep the files elsewhere, change the paths in `waf.cfg`.

## Step 2 &mdash; Paste `waf.cfg` into a frontend

HAProxy has no include, and a second `-f` does not continue a section, so the lines go in the configuration itself:

```haproxy
frontend http-in
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/

    # --- the lines of waf.cfg ---
    acl waf_query_string_urldecode query,url_dec(1) -m reg -f /etc/haproxy/waf/waf-query-string-urldecode.acl
    acl waf_user_agent hdr(user-agent) -m reg -f /etc/haproxy/waf/waf-user-agent.acl
    acl waf_request_filename_urldecode_restricted_files path,url_dec(1) -m sub -i -f /etc/haproxy/waf/restricted-files.data
    # …one acl for each pattern file and each phrase list
    http-request deny deny_status 403 if waf_query_string_urldecode or waf_user_agent or waf_request_filename_urldecode_restricted_files or …

    # --- the bad-bot list ---
    acl bad_bot hdr(user-agent) -m reg -i -f /etc/haproxy/waf/bots.acl
    http-request deny deny_status 403 if bad_bot

    default_backend servers
```

::: warning bots.acl refuses curl
`bots.acl` refuses HTTP libraries on purpose: a request from `curl`, `python-requests` or `Go-http-client` gets a 403 whatever it asks for. A probe without `-A` tells you nothing once it is in place. [Bad Bot Detection](/badbots) says why, and how to allow one.
:::

## Step 3 &mdash; Validate and reload

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
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

    # waf.cfg
    acl waf_query_string_urldecode query,url_dec(1) -m reg -f /etc/haproxy/waf/waf-query-string-urldecode.acl
    http-request deny deny_status 403 if waf_query_string_urldecode

    # bots.acl
    acl bad_bot hdr(user-agent) -m reg -i -f /etc/haproxy/waf/bots.acl
    http-request deny deny_status 403 if bad_bot

    default_backend servers

backend servers
    balance roundrobin
    server srv1 127.0.0.1:8080 check
```

## How it works

An `acl` matches a *fetch* (a sample of the request) through *converters*, with a *matcher*:

```haproxy
#   fetch        converters        matcher  pattern file
acl waf_query    query,url_dec(1)  -m reg   -f /etc/haproxy/waf/waf-query-string-urldecode.acl
```

A phrase list is the same with another matcher: `-m sub -i -f` takes each line for a string to look for anywhere in the value, with case ignored (ASCII is folded, other bytes are matched as they are):

```haproxy
acl waf_path path,url_dec(1) -m sub -i -f /etc/haproxy/waf/restricted-files.data
```

`-m reg` with `-f` reads the file a line at a time and takes each line for a regular expression, as it stands: nothing to quote, `#` in the middle of a line is part of the pattern, and a line can be as long as it needs to (one of 70,000 characters loads). A line that starts with `#` is a comment, and that is where each pattern says which CRS rule it is. The request matches if any expression of the file does.

## Customization

### Custom error response

Return a styled error body instead of the default empty 403:

```haproxy
http-request deny deny_status 403 content-type "text/html; charset=utf-8" string "<h1>Blocked by WAF</h1>" if waf_query_string_urldecode
```

It is one line: HAProxy does not take a backslash at the end of a line as a continuation.

### Logging blocked requests

```haproxy
http-request set-var(txn.blocked) str(1) if waf_query_string_urldecode
http-request capture var(txn.blocked) len 1

log-format "%ci:%cp [%t] %ft %b/%s %ST %B blocked=%[var(txn.blocked)] ua=%[capture.req.hdr(0)]"
```

### Per-path whitelist

Put the exemption before the `deny`: `allow` ends the `http-request` rules for that request.

```haproxy
acl is_webhook path_beg /api/webhook
http-request allow if is_webhook
```

### Combine with rate limiting

```haproxy
stick-table type ip size 100k expire 30s store http_req_rate(10s)
http-request track-sc0 src
acl too_many sc_http_req_rate(0) gt 100
http-request deny deny_status 429 if too_many
```

## Testing

Probe with a browser's User-Agent. The attack is refused in clear and percent-encoded, because the query string is decoded before the rules that decode read it:

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
curl -I -A "$UA" "http://example.com/?q=hello"                                  # 200
curl -I -A "$UA" "http://example.com/?id=1'+OR+'1'='1"                          # 403
curl -I -A "$UA" "http://example.com/?q=<script>alert(1)</script>"              # 403
curl -I -A "$UA" "http://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E"      # 403
curl -I -A "$UA" "http://example.com/?file=..%2f..%2fetc%2fpasswd"              # 403
curl -I -A "$UA" "http://example.com/.env"                                       # 403: restricted-files.data
curl -I -A "$UA" "http://example.com/%2egit/config"                               # 403: the path is decoded first
curl -I -A "sqlmap/1.8" "http://example.com/"                                     # 403: scanners-user-agents.data
curl -I -A "AhrefsBot/7.0" "http://example.com/"                                 # 403, with bots.acl

echo "show stat" | sudo socat stdio /var/run/haproxy.sock
```

## Troubleshooting

- **ACL never matches** &mdash; run `haproxy -c -f haproxy.cfg` to validate the syntax. Use `-d` for debug output to watch ACL evaluation in real time.
- **`failed to open pattern file`** &mdash; the pattern files or the `*.data` phrase lists are not where `waf.cfg` says. HAProxy reads them at start-up, as the user it runs as: check the path and the permissions.
- **`unknown keyword 'include'`** &mdash; HAProxy has no include. Paste the lines of `waf.cfg`.
- **Performance impact** &mdash; every pattern file is read as a list of regular expressions tried one after the other, a phrase list as a list of strings looked for one after the other, and the bad-bot list has about 1,900. Benchmark with realistic traffic before enabling globally.
- **Fewer files** &mdash; if you do not want a rule set for a fetch, leave its `acl` out of the `deny` line.
