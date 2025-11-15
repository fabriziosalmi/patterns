# Traefik WAF Configuration

This directory contains Traefik WAF configuration files generated from OWASP CRS rules.
You can use these middleware configurations to enhance security in your Traefik setup.

## Prerequisites

- Traefik v2.x or higher
- Basic understanding of Traefik middleware

## Configuration Files

The generated configuration includes:
- Middleware definitions for request filtering
- Regular expression patterns for attack detection
- Bad bot/User-Agent blocking rules

## Usage

### Option 1: File Provider (Recommended)

1. Copy the generated configuration files to your Traefik configuration directory:
   ```bash
   cp waf_patterns/traefik/*.toml /etc/traefik/dynamic/
   # or to your custom config directory
   ```

2. Configure Traefik to load dynamic configuration from files.
   
   In your `traefik.yml` or `traefik.toml`:
   ```yaml
   providers:
     file:
       directory: "/etc/traefik/dynamic"
       watch: true
   ```

3. Apply the middleware to your routes by referencing it in your service configuration:
   ```yaml
   http:
     routers:
       my-router:
         rule: "Host(`example.com`)"
         service: my-service
         middlewares:
           - waf-middleware
   ```

### Option 2: Docker Labels

If you're using Docker, you can apply the middleware via labels:

```yaml
services:
  my-service:
    image: my-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.my-router.rule=Host(`example.com`)"
      - "traefik.http.routers.my-router.middlewares=waf-middleware@file"
```

### Option 3: Kubernetes IngressRoute

For Kubernetes deployments:

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: waf-middleware
spec:
  plugin:
    # Reference your WAF plugin configuration here
```

## Configuration Details

The middleware includes protection against:
- **SQL Injection (SQLi)** attacks
- **Cross-Site Scripting (XSS)** attempts
- **Remote Code Execution (RCE)** patterns
- **Local File Inclusion (LFI)** attempts
- **Malicious bots and crawlers**

## Testing

Test the WAF is working by sending a malicious request:

```bash
curl -H "User-Agent: AhrefsBot" http://yourserver.com
# Should be blocked if bot protection is working

curl "http://yourserver.com/?id=1' OR '1'='1"
# Should be blocked if SQLi protection is working
```

## Monitoring

Monitor blocked requests in Traefik logs:

```bash
# Docker
docker logs traefik 2>&1 | grep -i "blocked\|forbidden"

# Standard installation
tail -f /var/log/traefik/access.log | grep -i "403"
```

## Customization

You can customize the middleware behavior by:
1. Editing the generated `.toml` files
2. Adjusting regex patterns for your specific needs
3. Modifying response codes and error pages
4. Adding custom headers for blocked requests

## Performance Considerations

- Regular expression matching can impact performance under high load
- Consider using caching middleware in combination with WAF
- Monitor CPU usage and adjust rules if needed
- Use Traefik's built-in rate limiting for additional protection

## Notes

- Rules are updated daily via GitHub Actions
- Blocked requests typically return `403 Forbidden` or `400 Bad Request`
- Middleware is applied at the router level
- Compatible with other Traefik middlewares (chain them as needed)

## Resources

- [Traefik Documentation](https://doc.traefik.io/traefik/)
- [Traefik Middleware](https://doc.traefik.io/traefik/middlewares/overview/)
- [OWASP CRS](https://coreruleset.org/)
