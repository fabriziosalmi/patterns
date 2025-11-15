# Apache ModSecurity WAF Configuration

This directory contains Apache ModSecurity WAF configuration files generated from OWASP CRS rules.
You can include these files in your existing Apache configuration to enhance security.

## Prerequisites

- Apache HTTP Server (2.4 or higher)
- ModSecurity module installed and enabled
- Core Rule Set (CRS) base configuration

## Installation

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install libapache2-mod-security2
sudo a2enmod security2
sudo systemctl restart apache2
```

### CentOS/RHEL
```bash
sudo yum install mod_security
sudo systemctl restart httpd
```

## Usage

1. Copy the generated configuration files to your Apache configuration directory:
   ```bash
   sudo cp waf_patterns/apache/*.conf /etc/apache2/modsecurity.d/
   # or for CentOS/RHEL:
   # sudo cp waf_patterns/apache/*.conf /etc/httpd/modsecurity.d/
   ```

2. Include the configuration files in your Apache configuration.
   
   Edit `/etc/apache2/mods-enabled/security2.conf` (Ubuntu/Debian) or `/etc/httpd/conf.d/mod_security.conf` (CentOS/RHEL):
   ```apache
   <IfModule security2_module>
       Include /etc/apache2/modsecurity.d/*.conf
   </IfModule>
   ```

3. Test the configuration:
   ```bash
   # Ubuntu/Debian
   sudo apache2ctl configtest
   
   # CentOS/RHEL
   sudo httpd -t
   ```

4. Reload Apache to apply the changes:
   ```bash
   # Ubuntu/Debian
   sudo systemctl reload apache2
   
   # CentOS/RHEL
   sudo systemctl reload httpd
   ```

## Configuration Details

The generated rules include:
- **SQL Injection (SQLi)** detection patterns
- **Cross-Site Scripting (XSS)** prevention rules
- **Remote Code Execution (RCE)** blocking
- **Local File Inclusion (LFI)** protection
- **Bad Bot/User-Agent** blocking

## Customization

You can adjust the severity and actions for each rule by modifying the configuration files.
Common actions include:
- `deny` - Block the request
- `log` - Log the event
- `status:403` - Return HTTP 403 Forbidden

## Troubleshooting

### Check ModSecurity is loaded
```bash
# Ubuntu/Debian
apache2ctl -M | grep security

# CentOS/RHEL
httpd -M | grep security
```

### View ModSecurity logs
```bash
# Ubuntu/Debian
sudo tail -f /var/log/apache2/modsec_audit.log

# CentOS/RHEL
sudo tail -f /var/log/httpd/modsec_audit.log
```

### Test with a sample attack
```bash
curl "http://yourserver.com/?id=1' OR '1'='1"
# Should return 403 Forbidden if WAF is working
```

## Notes

- Rules are updated daily via GitHub Actions
- Blocked requests return a `403 Forbidden` response by default
- Review the ModSecurity documentation for advanced configuration options

## Resources

- [ModSecurity Documentation](https://github.com/SpiderLabs/ModSecurity)
- [OWASP CRS](https://coreruleset.org/)
- [Apache ModSecurity Module](https://modsecurity.org/)
