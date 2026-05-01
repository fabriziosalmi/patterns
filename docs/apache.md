# Apache Integration

This guide explains how to deploy the generated rules in Apache HTTPD using the **ModSecurity** engine.

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

1. Download `apache_waf.zip` from the [latest release](https://github.com/fabriziosalmi/patterns/releases/latest).
2. Extract under your Apache config tree (e.g. `/etc/apache2/waf_patterns/apache/`).
3. Include the `.conf` files from the relevant virtual host or globally.

## Files in the archive

The Apache output is split by attack family, each containing standard ModSecurity `SecRule` directives.

| File | Protection |
|------|------------|
| `sqli.conf` | SQL injection |
| `xss.conf` | Cross-site scripting |
| `rce.conf` | Remote code execution |
| `lfi.conf` | Local file inclusion |
| `rfi.conf` | Remote file inclusion |
| `php.conf`, `java.conf`, `iis.conf`, `shells.conf` | Stack-specific exploits |
| `attack.conf`, `generic.conf`, `correlation.conf`, `evaluation.conf` | Generic anomaly detection |
| `bots.conf` | Bad-bot User-Agent rules |

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

::: tip Run in detection mode first
Set `SecRuleEngine DetectionOnly` for the first deployment. Watch the audit log, tune false positives, then flip to `On`.
:::

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

## Step 3 &mdash; Validate and restart

```bash
sudo apachectl configtest && sudo systemctl restart apache2
```

## Rule format

Generated rules follow the standard ModSecurity DSL:

```apache
SecRule REQUEST_URI "@rx union.*select" \
    "id:100001,\
    phase:2,\
    deny,\
    status:403,\
    log,\
    msg:'SQL Injection Attempt',\
    severity:CRITICAL"
```

## Customization

### Detection-only mode

Switch a noisy rule from blocking to logging without removing it:

```apache
SecRuleUpdateActionById 100001 "pass,log,msg:'SQLi candidate (audit only)'"
```

### Whitelist a path

```apache
SecRule REQUEST_URI "@beginsWith /api/webhook" \
    "id:1,phase:1,nolog,allow"
```

### Disable a single rule

```apache
SecRuleRemoveById 100001
```

## Logs

ModSecurity logs land in:

- `/var/log/apache2/modsec_audit.log` &mdash; full audit trail
- `/var/log/apache2/error.log` &mdash; rule matches and engine messages

## Testing

```bash
curl -I "https://example.com/?id=1' UNION SELECT * FROM users--"
sudo tail -f /var/log/apache2/error.log
```

## Troubleshooting

- **Module not loading** &mdash; confirm with `apachectl -M | grep security2`. Re-enable with `sudo a2enmod security2`.
- **No rules triggering** &mdash; double-check `SecRuleEngine On` and that the include path resolves; `apachectl -S` lists the parsed config.
- **Performance regressions** &mdash; identify hot rules in the audit log and disable or scope them with `SecRuleRemoveById` / `SecRule … chain`.
