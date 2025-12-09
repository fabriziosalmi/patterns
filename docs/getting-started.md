# Getting Started

This guide will help you get up and running with Patterns WAF configurations for your web server.

## Prerequisites

- **Python 3.11+** (if building from source)
- **pip** (Python package installer)
- **git** (for cloning the repository)

## Installation Options

### Option 1: Download Pre-Generated Configurations

The easiest way to get started is to download pre-built configurations:

1. Go to the [Releases](https://github.com/fabriziosalmi/patterns/releases) page
2. Download the ZIP file for your web server:
   - `nginx_waf.zip` - Nginx configurations
   - `apache_waf.zip` - Apache ModSecurity rules
   - `traefik_waf.zip` - Traefik middleware
   - `haproxy_waf.zip` - HAProxy ACL files
3. Extract and integrate into your server configuration

### Option 2: Build from Source

If you prefer to generate the configurations yourself:

```bash
# Clone the repository
git clone https://github.com/fabriziosalmi/patterns.git
cd patterns

# Install dependencies
pip install -r requirements.txt

# Fetch latest OWASP rules
python owasp2json.py

# Generate configurations for your platform
python json2nginx.py    # For Nginx
python json2apache.py   # For Apache
python json2traefik.py  # For Traefik
python json2haproxy.py  # For HAProxy

# Generate bad bot blockers
python badbots.py
```

## Configuration Files

After running the scripts, you'll find the generated files in the `waf_patterns/` directory:

```
waf_patterns/
├── nginx/          # Nginx WAF configs
├── apache/         # Apache ModSecurity rules
├── traefik/        # Traefik middleware configs
└── haproxy/        # HAProxy ACL files
```

## Next Steps

Choose your web server to learn how to integrate the WAF configurations:

- [Nginx Integration](/nginx)
- [Apache Integration](/apache)
- [Traefik Integration](/traefik)
- [HAProxy Integration](/haproxy)

## Automatic Updates

The repository includes a GitHub Actions workflow that:
- Fetches the latest OWASP CRS rules **daily**
- Regenerates all WAF configurations
- Creates a new release with updated files

To get the latest rules, simply download from the [Releases](https://github.com/fabriziosalmi/patterns/releases) page or pull the latest changes if you cloned the repository.
