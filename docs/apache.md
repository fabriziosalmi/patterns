# Apache Integration

This guide explains how to deploy the generated rules in Apache HTTPD with the **ModSecurity** engine. Apache is the target that can keep the most of what CRS wrote, because CRS is written in ModSecurity's own language: [Coverage](/coverage) says what it does with each rule. Every example below was run against Apache 2.4 with ModSecurity 2 (`owasp/modsecurity:apache`).

## What it can and cannot do

Each rule is written as CRS wrote it, with the operator it named (`@rx`, `@pm` or `@pmFromFile`), on the variable it matches, and a rule that CRS gives `t:lowercase` is written with it. That is a part of what a CRS rule is, and the rest is not written:

- **Only `@rx`, `@pm` and `@pmFromFile` are written**, not negated. `@detectSQLi`, `@detectXSS`, the numeric comparisons and the byte-range checks are dropped. ModSecurity could run them; this backend does not write them yet.
- **A phrase list is a file, and ModSecurity reads it from next to the rule that names it.** `@pmFromFile restricted-files.data` is how CRS refuses `/.env`, `/.git/config` and a scanner's User-Agent; the `*.data` files are in the archive and **have to stay in the same directory as the `.conf` files**. A phrase list is checked against the corpus as a whole: if one phrase of it is in an ordinary request, the rule is not written.
- **Only one transformation is applied, `lowercase`.** The others (`urlDecodeUni`, `htmlEntityDecode`, ...) are written as `t:none`, so a pattern that was written to run after one runs on the raw value. The one thing ModSecurity does for you is `ARGS`: its values are already URL-decoded, so an attack percent-encoded in the query string is caught as the same attack in clear. `REQUEST_FILENAME` is not: it holds the path as it arrived (measured: a rule on `%2e` matches `/%2egit/config`), so a path percent-encoded passes a phrase written in clear.
- **No chain.** A chain matches when every record does. ModSecurity can say so with `chain`; this backend does not write it yet, and a record of a chain on its own is another rule, so no record of one is written (128 of the 749).
- **No anomaly score.** CRS adds points and refuses over a threshold. Here a rule decides alone: a rule of severity `high` refuses with a 403, and one below it records the match in the log and lets the request through (`pass,log`).
- **A rule that refuses ordinary traffic is not written.** Without its transformations, some CRS rules mean something else; each is checked against [a corpus of ordinary requests](https://github.com/fabriziosalmi/patterns/blob/main/patterns/corpus.py), as nginx's are, and left out if one matches. The corpus is held to this by [`tests/test_apache_blocking.py`](https://github.com/fabriziosalmi/patterns/blob/main/tests/test_apache_blocking.py), which runs it through a real Apache on every change: 162 ordinary requests, none refused; of 21 attacks, 17 refused in clear and 17 percent-encoded.

At CRS v4.29.0 that is 180 rules written (8 in full, 172 with a named loss), and the rest dropped with a reason. It is a useful first filter in front of an application. It is not the Core Rule Set: if you can install that, do.

## Prerequisites

- Apache HTTPD **2.4+**
- The **ModSecurity** module installed and enabled

::: code-group

```bash [Debian / Ubuntu]
sudo apt install libapache2-mod-security2
sudo a2enmod security2
```

```bash [RHEL / CentOS / Rocky]
sudo dnf install mod_security
```

```bash [Alpine]
sudo apk add mod_security
```

:::

## Quick start

1. Download `apache_waf.zip` from the [latest release](https://github.com/fabriziosalmi/patterns/releases/latest) (or from a [pinned one](/verify)).
2. Extract under your Apache config tree (e.g. `/etc/apache2/waf_patterns/apache/`).
3. Include the `.conf` files from the relevant virtual host or globally.

## Files in the archive

The Apache output is split by the part of CRS each rule comes from. A category with nothing in it has no file.

| File | CRS category |
|------|--------------|
| `sqli.conf` | SQL injection |
| `xss.conf` | Cross-site scripting |
| `rce.conf` | Remote code execution |
| `lfi.conf`, `rfi.conf` | Local and remote file inclusion |
| `php.conf`, `java.conf` | Stack-specific attacks |
| `generic.conf` | Generic application attacks |
| `enforcement.conf` | HTTP protocol enforcement |
| `attack.conf` | HTTP protocol attacks |
| `fixation.conf` | Session fixation |
| `detection.conf` | Scanner and bot detection (the User-Agent phrase list) |
| `bots.conf` | Bad-bot User-Agent rules ([Bad Bot Detection](/badbots)) |
| `*.data` | The phrase lists the rules name with `@pmFromFile`, one phrase to a line. **Keep them next to the `.conf` files** |

## Step 1 &mdash; Enable the engine

In `/etc/apache2/mods-enabled/security2.conf` (or equivalent):

```apache
<IfModule security2_module>
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess Off
    SecAuditEngine RelevantOnly
    SecAuditLog /var/log/apache2/modsec_audit.log
    SecAuditLogParts ABCDEFHZ
</IfModule>
```

The generated files **do not set the engine**. That is yours to set, and it is how you run in detection mode first: a file that said `SecRuleEngine On` would take that choice away.

::: tip Run in detection mode first
Set `SecRuleEngine DetectionOnly` for the first deployment. Every rule is evaluated and logged, and none refuses. Watch the log, tune false positives, then flip to `On`.
:::

`SecRequestBodyAccess On` is what puts the arguments of a form body in `ARGS`: without it the rules see the query string only.

## Step 2 &mdash; Include the rules

Either include all files in one go:

```apache
<VirtualHost *:443>
    ServerName example.com

    Include /etc/apache2/waf_patterns/apache/*.conf
    # …other directives
</VirtualHost>
```

…or pick the categories you want:

```apache
Include /etc/apache2/waf_patterns/apache/sqli.conf
Include /etc/apache2/waf_patterns/apache/xss.conf
Include /etc/apache2/waf_patterns/apache/rce.conf
Include /etc/apache2/waf_patterns/apache/bots.conf
```

::: warning bots.conf refuses curl
`bots.conf` refuses HTTP libraries on purpose: a request from `curl`, `python-requests` or `Go-http-client` gets a 403 whatever it asks for. A probe without `-A` tells you nothing once it is included. [Bad Bot Detection](/badbots) says why, and how to allow one.
:::

## Step 3 &mdash; Validate and restart

```bash
sudo apachectl configtest && sudo systemctl restart apache2
```

## Rule format

A rule is written as CRS wrote it, with the id and the message changed:

```apache
SecRule REQUEST_HEADERS:Host "@rx ^$" "id:9920290,phase:1,t:none,deny,status:403,log,msg:'ENFORCEMENT, CRS 920290',severity:'CRITICAL'"
```

- **The id is 9000000 plus the CRS id.** CRS rule 920290 is rule 9920290. It cannot be the id of a CRS you have installed (900000 to 999999), and the log says which rule it was.
- **`bots.conf` uses ids from 8000001.** They follow the order of the list, which changes every night: do not rely on one staying the same between releases.
- The `phase` is the one CRS gave the rule, and `severity` is CRS's.
- The expression is exactly what CRS wrote between the quotes, with `(?i)` where it had one.

A rule that **records** instead of refusing, which is every rule below `high`, is the same with `pass,log`:

```apache
SecRule REQUEST_HEADERS:Host "@rx (?:^([\d.]+|\[[\da-f:]+\]|[\da-f:]+)(:[\d]+)?$)" "id:9920350,phase:1,t:none,pass,log,msg:'ENFORCEMENT, CRS 920350',severity:'WARNING'"
```

A match is in the log with the id and the message:

```text
Warning. Pattern match "(?:^([\\d.]+|\\[[\\da-f:]+\\]|[\\da-f:]+)(:[\\d]+)?$)" at REQUEST_HEADERS:Host.
[file "/waf/enforcement.conf"] [line "11"] [id "9920350"] [msg "ENFORCEMENT, CRS 920350"] [severity "WARNING"]
```

## Customization

### Detection-only mode

Set `SecRuleEngine DetectionOnly` in your configuration, as above. To make a single rule record and not refuse:

```apache
SecRuleUpdateActionById 9941110 "pass,log"
```

Put it after the `Include`: it changes a rule that is already defined. An attack often matches more than one rule (`<script>alert(1)</script>` matches 9941110 and then 9941160), and a rule that refused stops the others, so look at every id in the log before you conclude that a request would pass.

### Whitelist a path

```apache
SecRule REQUEST_URI "@beginsWith /api/webhook" \
    "id:1,phase:1,nolog,allow"
```

Give the rule an id of your own: ids below 100000 are for local rules, so `1` does not clash with the generated ones.

### Disable a single rule

```apache
SecRuleRemoveById 9941110
```

Also after the `Include`, and with the same caution: the next rule that matches refuses.

## Testing

Probe the deployment with a browser's User-Agent. The attack is refused the same way in clear and percent-encoded, because ModSecurity decodes `ARGS` before the rule reads it:

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
curl -I -A "$UA" "https://example.com/?q=hello"                                   # 200
curl -I -A "$UA" "https://example.com/?id=1'+OR+'1'='1"                           # 403
curl -I -A "$UA" "https://example.com/?q=<script>alert(1)</script>"               # 403
curl -I -A "$UA" "https://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E"       # 403
curl -I -A "$UA" "https://example.com/?file=..%2f..%2fetc%2fpasswd"               # 403
curl -I -A "sqlmap/1.8" "https://example.com/"                                    # 403, with bots.conf
sudo tail -f /var/log/apache2/error.log
```

## Troubleshooting

- **Module not loading** &mdash; confirm with `apachectl -M | grep security2`. Re-enable with `sudo a2enmod security2`.
- **No rules triggering** &mdash; the generated files do not set `SecRuleEngine`. Check yours is `On`, not `Off` or `DetectionOnly`, and that the include path resolves; `apachectl -S` lists the parsed config.
- **A form body is not inspected** &mdash; `SecRequestBodyAccess On`. Whether a JSON body ends up in `ARGS` is up to your ModSecurity configuration (its JSON body processor, which the recommended `modsecurity.conf` enables for `application/json`); the rules are checked against ordinary traffic as if it did.
- **`Found another rule with the same id`** &mdash; the CRS itself is installed and one of its ids is in this range, or two copies of these files are included. The ids here are 9000000 plus a CRS id and 8000001 and up.
- **Performance regressions** &mdash; identify hot rules in the audit log and disable or scope them with `SecRuleRemoveById`.
