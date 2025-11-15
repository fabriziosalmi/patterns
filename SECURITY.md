# Security Policy

## Supported Versions

We actively support the current version of this project. The WAF patterns are updated daily via automated GitHub Actions.

| Version | Supported          |
| ------- | ------------------ |
| current (main branch) | :white_check_mark: |
| latest release | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### For Non-Critical Issues
For general security concerns or minor issues:
1. Open an issue in the [Issues](https://github.com/fabriziosalmi/patterns/issues) section
2. Use the label "security" if available
3. Provide a clear description of the issue

### For Critical Vulnerabilities
For critical security vulnerabilities (e.g., in the WAF patterns themselves):
1. **DO NOT** open a public issue
2. Email the maintainer directly at: fabrizio.salmi@gmail.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### What to Include
When reporting a vulnerability, please include:
- Type of vulnerability (e.g., regex bypass, pattern detection issue)
- Affected web server(s) (Nginx, Apache, Traefik, HAProxy)
- Attack pattern that bypasses detection
- Suggested regex or pattern improvement
- Any proof-of-concept code (if applicable)

### Response Time
- We aim to acknowledge vulnerability reports within **48 hours**
- Critical vulnerabilities will be addressed in the next daily update
- Less critical issues will be prioritized based on severity

### After Reporting
Once you report a vulnerability:
1. We will acknowledge receipt
2. We will investigate and validate the issue
3. We will work on a fix and test it
4. We will deploy the fix in the next update
5. We will credit you in the release notes (unless you prefer to remain anonymous)

## Security Best Practices

When using the WAF patterns from this project:
- Always test new rules in a staging environment first
- Monitor your logs for false positives
- Keep your web server and WAF software up to date
- Review the OWASP CRS documentation for additional hardening
- Consider layering multiple security controls (WAF + rate limiting + IPS, etc.)

## Scope

This security policy covers:
- WAF pattern generation logic
- Regex patterns for attack detection
- GitHub Actions workflow security
- Dependencies listed in requirements.txt

Thank you for helping keep this project secure!


