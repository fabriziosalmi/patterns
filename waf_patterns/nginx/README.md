# Nginx WAF Configuration

This directory contains Nginx WAF configuration files generated from OWASP rules.

## Usage

1. **Include `waf_maps.conf` in your `http` block:**
   ```nginx
   http {
       include /path/to/waf_patterns/nginx/waf_maps.conf;
       # ... other http configurations ...
   }
   ```

2. **Include `waf_rules.conf` in your `server` or `location` block:**
   ```nginx
   server {
       # ... other server configurations ...
       include /path/to/waf_patterns/nginx/waf_rules.conf;
   }
   ```

3. **Reload Nginx:**
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```

## What this blocks

Only a rule of severity `high` refuses a request, with a 403. The lower severities are
recorded in the `$waf_*` variables, which hold `"<severity>:<category>"` on a match and
`""` otherwise, and are there for `log_format`. The header of `waf_maps.conf` lists the
rules that were left out and why.

A `map` matches one regular expression against one raw request variable, and nothing
else: it does not decode, it does not read the request body and it does not add up a
score. `@pm` and `@pmFromFile` are written as case-insensitive alternations of their
phrases, and the request path is matched on `$uri`, which nginx has decoded and
normalised. See https://fabriziosalmi.github.io/patterns/nginx for what it catches and
what it does not.

Log the variables against your own traffic before enforcing anything.

## Important Notes:

* **Testing is Crucial:**  Thoroughly test your WAF configuration with a variety of requests (both legitimate and malicious) to ensure it's working correctly and not causing false positives.
* **False Positives:**  WAF rules, especially those based on regex, can sometimes block legitimate traffic.  Monitor your Nginx logs and adjust the rules as needed.
* **Performance:** Complex regexes can impact performance.  Use the simplest regex that accurately matches the threat.
* **Updates:**  Regularly update the OWASP rules (by re-running `owasp2json.py` and `python3 -m patterns build --target nginx`) to stay protected against new threats.
* **This is not a complete WAF:** This script provides a basic WAF based on pattern matching.  For more comprehensive protection, consider using a dedicated WAF solution like Nginx App Protect or ModSecurity.
