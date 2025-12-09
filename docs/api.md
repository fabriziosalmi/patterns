# API Reference

This page documents the Python scripts that power the Patterns project.

## Core Scripts

### owasp2json.py

Fetches and parses OWASP Core Rule Set patterns from GitHub.

```bash
python owasp2json.py
```

**Output**: `owasp_rules.json`

**Configuration**:
- Uses environment variable `OWASP_REPO` to specify source repository
- Default: `coreruleset/coreruleset`

**Features**:
- Fetches latest CRS rules from GitHub
- Parses `.conf` files for regex patterns
- Extracts rule metadata (ID, severity, category)
- Outputs structured JSON for conversion scripts

---

### json2nginx.py

Converts OWASP JSON rules to Nginx WAF configuration.

```bash
python json2nginx.py
```

**Input**: `owasp_rules.json`  
**Output**: `waf_patterns/nginx/`

**Generated Files**:
| File | Purpose |
|------|---------|
| `waf_maps.conf` | Map directives (http block) |
| `waf_rules.conf` | If statements (server block) |
| `README.md` | Integration instructions |

**Environment Variables**:
- `INPUT_FILE` - Path to OWASP JSON (default: `owasp_rules.json`)
- `OUTPUT_DIR` - Output directory (default: `waf_patterns/nginx`)

---

### json2apache.py

Converts OWASP JSON rules to Apache ModSecurity format.

```bash
python json2apache.py
```

**Input**: `owasp_rules.json`  
**Output**: `waf_patterns/apache/`

**Generated Files**:
- Category-specific `.conf` files (sqli.conf, xss.conf, etc.)
- Each file contains ModSecurity `SecRule` directives

---

### json2traefik.py

Converts OWASP JSON rules to Traefik middleware configuration.

```bash
python json2traefik.py
```

**Input**: `owasp_rules.json`  
**Output**: `waf_patterns/traefik/`

**Generated Files**:
- `middleware.toml` - Traefik middleware configuration
- `README.md` - Integration instructions

---

### json2haproxy.py

Converts OWASP JSON rules to HAProxy ACL format.

```bash
python json2haproxy.py
```

**Input**: `owasp_rules.json`  
**Output**: `waf_patterns/haproxy/`

**Generated Files**:
- `waf.acl` - Main WAF ACL rules
- `README.md` - Integration instructions

---

### badbots.py

Generates bad bot blocking configurations from public bot lists.

```bash
python badbots.py
```

**Output**: Bot configurations in each `waf_patterns/*/` directory

**Features**:
- Fetches from multiple public bot lists
- Includes fallback sources for reliability
- Generates platform-specific configs

---

## Import Scripts

These scripts help import existing WAF configurations.

### import_nginx_waf.py

Import Nginx WAF patterns from external sources.

```bash
python import_nginx_waf.py --source /path/to/external/rules
```

### import_apache_waf.py

Import Apache ModSecurity rules.

```bash
python import_apache_waf.py --source /path/to/modsec/rules
```

### import_traefik_waf.py

Import Traefik middleware configurations.

```bash
python import_traefik_waf.py --source /path/to/traefik/config
```

### import_haproxy_waf.py

Import HAProxy ACL rules.

```bash
python import_haproxy_waf.py --source /path/to/haproxy/acl
```

---

## Data Structures

### owasp_rules.json Format

```json
[
  {
    "id": "942100",
    "pattern": "(?i:union.*select)",
    "category": "sqli",
    "severity": "critical",
    "location": "request-uri",
    "description": "SQL Injection Attack Detected"
  }
]
```

**Fields**:
| Field | Type | Description |
|-------|------|-------------|
| `id` | string | OWASP CRS rule ID |
| `pattern` | string | Regex pattern |
| `category` | string | Attack category (sqli, xss, rce, etc.) |
| `severity` | string | critical, high, medium, low |
| `location` | string | Where to match (request-uri, headers, etc.) |
| `description` | string | Human-readable description |

---

## Extending the Project

### Adding a New Platform

1. Create `json2<platform>.py` based on existing converters
2. Add output directory in `waf_patterns/<platform>/`
3. Update GitHub Actions workflow
4. Add documentation in `docs/`

### Custom Pattern Sources

Modify `owasp2json.py` to add new pattern sources:

```python
SOURCES = [
    "coreruleset/coreruleset",
    "your-org/your-rules",
]
```

---

## Dependencies

Listed in `requirements.txt`:

```
requests>=2.28.0
beautifulsoup4>=4.11.0
```

Install with:

```bash
pip install -r requirements.txt
```
