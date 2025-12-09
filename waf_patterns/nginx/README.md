# Nginx WAF Configuration

This directory contains Nginx WAF configuration files generated from OWASP rules.
You can include these files in your existing Nginx configuration to enhance security.

## Usage

**Important:** You should only include the two main configuration files (`waf_maps.conf` and `waf_rules.conf`). The individual category files (e.g., `attack.conf`, `xss.conf`) are provided for reference only and should **not** be included directly, as they contain both `map` and `if` directives that cannot be used in the same Nginx context.

1. Include the `waf_maps.conf` file in your `nginx.conf` *inside the `http` block*:
   ```nginx
   http {
       include /path/to/waf_patterns/nginx/waf_maps.conf;
       # ... other http configurations ...
   }
   ```
2. Include the `waf_rules.conf` file in your `server` block:
   ```nginx
   server {
       # ... other server configurations ...
       include /path/to/waf_patterns/nginx/waf_rules.conf;
   }
   ```
3. Reload Nginx to apply the changes:
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```

## Notes
- The `map` directives (defined in `waf_maps.conf`) must be placed in the `http` context.
- The `if` rules (defined in `waf_rules.conf`) must be placed in a `server` or `location` context.
- **Do not** try to include individual category files like `attack.conf` directly - they are auto-generated for reference and viewing purposes only.
- Blocked requests return a `403 Forbidden` response by default.
- You can enable logging for blocked requests by uncommenting the `access_log` line.

