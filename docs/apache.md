# Apache Integration

This guide explains how to integrate the WAF patterns with Apache using ModSecurity.

## Prerequisites

- Apache 2.4+
- ModSecurity module installed

### Install ModSecurity

::: code-group

```bash [Debian/Ubuntu]
sudo apt install libapache2-mod-security2
sudo a2enmod security2
```

```bash [RHEL/CentOS]
sudo yum install mod_security
```

:::

## Quick Start

1. Download `apache_waf.zip` from [Releases](https://github.com/fabriziosalmi/patterns/releases)
2. Extract to your Apache configuration directory
3. Include the files in your Apache configuration

## Configuration Files

The Apache WAF package includes ModSecurity rules organized by attack type:

| File | Protection Type |
|------|-----------------|
| `sqli.conf` | SQL Injection |
| `xss.conf` | Cross-Site Scripting |
| `rce.conf` | Remote Code Execution |
| `lfi.conf` | Local File Inclusion |
| `rfi.conf` | Remote File Inclusion |
| `bots.conf` | Bad Bot Detection |

## Integration

### Step 1: Enable ModSecurity

Create or edit `/etc/apache2/mods-enabled/security2.conf`:

```apache
<IfModule security2_module>
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess Off
    SecDebugLogLevel 0
</IfModule>
```

### Step 2: Include WAF Rules

Add to your Apache configuration or virtual host:

```apache
<VirtualHost *:80>
    ServerName example.com
    
    # Include all WAF patterns
    Include /path/to/waf_patterns/apache/*.conf
    
    # ... other configurations ...
</VirtualHost>
```

Or include specific rule sets:

```apache
Include /path/to/waf_patterns/apache/sqli.conf
Include /path/to/waf_patterns/apache/xss.conf
Include /path/to/waf_patterns/apache/bots.conf
```

### Step 3: Restart Apache

```bash
sudo apachectl configtest && sudo systemctl restart apache2
```

## Rule Format

The rules follow ModSecurity syntax:

```apache
SecRule REQUEST_URI "@rx union.*select" \
    "id:100001,\
    phase:2,\
    deny,\
    status:403,\
    msg:'SQL Injection Attempt',\
    severity:CRITICAL"
```

## Customization

### Adjust Severity Levels

Modify the action from `deny` to `log` for monitoring mode:

```apache
SecRule REQUEST_URI "@rx pattern" \
    "id:100001,\
    phase:2,\
    log,\
    pass,\
    msg:'Potential attack detected'"
```

### Whitelist Paths

Add exceptions for specific paths:

```apache
SecRule REQUEST_URI "@beginsWith /api/webhook" \
    "id:1,\
    phase:1,\
    allow,\
    nolog"
```

## Logging

ModSecurity logs are typically found at:
- `/var/log/apache2/modsec_audit.log`
- `/var/log/httpd/modsec_audit.log`

Enable detailed logging:

```apache
SecAuditEngine RelevantOnly
SecAuditLog /var/log/apache2/modsec_audit.log
SecAuditLogParts ABCDEFHZ
```

## Testing

```bash
# Test SQL injection detection
curl -I "http://example.com/?id=1' UNION SELECT * FROM users--"

# Check Apache error log
sudo tail -f /var/log/apache2/error.log
```

## Troubleshooting

### ModSecurity not loading
Ensure the module is enabled: `sudo a2enmod security2`

### Rules not triggering
Check that `SecRuleEngine` is set to `On` and rules are being included.

### Performance issues
Consider using `SecRuleRemoveById` to disable noisy rules that cause false positives.
