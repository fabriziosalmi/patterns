# API & Scripts Reference

Patterns is a small Python toolchain. Every script does one job and communicates with the rest through plain JSON or files on disk &mdash; no shared state, no daemon, no database.

```text
owasp2json.py  ──▶  owasp_rules.json  ──▶  json2{nginx,apache,traefik,haproxy}.py
                                       └▶  badbots.py (independent)
```

All scripts are configured through **environment variables** (not CLI flags) except `owasp2json.py`, which has a small `argparse` interface.

## Pipeline scripts

### `owasp2json.py`

Fetches the OWASP Core Rule Set from GitHub and emits a flat JSON rule list.

```bash
python owasp2json.py --ref v4.0 --output owasp_rules.json
```

| Argument / env | Default | Purpose |
|----------------|---------|---------|
| `--output` | `owasp_rules.json` | Output JSON path |
| `--ref` | `v4.0` | Tag prefix to resolve (e.g. `v4.0`, `v3.3`, `dev`) |
| `--dry-run` | off | Fetch and parse without writing |
| `GITHUB_TOKEN` (env) | unset | Raises the GitHub API rate limit while iterating |

The script verifies each blob's SHA against the GitHub-reported value before parsing it.

---

### `json2nginx.py`

Converts `owasp_rules.json` into Nginx `map`-based rules.

```bash
python json2nginx.py
INPUT_FILE=custom.json OUTPUT_DIR=/tmp/out python json2nginx.py
```

**Generated files** (in `OUTPUT_DIR`):

| File | Purpose |
|------|---------|
| `waf_maps.conf` | `map` directives &mdash; include in the `http` block |
| `waf_rules.conf` | `if` rules &mdash; include in the `server` block |
| `<category>.conf` | One file per OWASP category, **for inspection only** |
| `README.md` | In-tree usage notes |

| Env var | Default |
|---------|---------|
| `INPUT_FILE` | `owasp_rules.json` |
| `OUTPUT_DIR` | `waf_patterns/nginx` |

---

### `json2apache.py`

Converts `owasp_rules.json` into ModSecurity `SecRule` directives, partitioned by attack category.

```bash
python json2apache.py
```

**Generated files**: one `<category>.conf` per OWASP category (`sqli.conf`, `xss.conf`, `rce.conf`, `lfi.conf`, …) &mdash; each contains pure ModSecurity rules ready to `Include`.

| Env var | Default |
|---------|---------|
| `INPUT_FILE` | `owasp_rules.json` |
| `OUTPUT_DIR` | `waf_patterns/apache` |

---

### `json2traefik.py`

Converts `owasp_rules.json` into a Traefik file-provider middleware.

```bash
python json2traefik.py
```

**Generated files**:

- `middleware.toml` &mdash; complete WAF middleware definition
- `README.md` &mdash; in-tree integration notes

| Env var | Default |
|---------|---------|
| `INPUT_FILE` | `owasp_rules.json` |
| `OUTPUT_DIR` | `waf_patterns/traefik` |

---

### `json2haproxy.py`

Converts `owasp_rules.json` into HAProxy ACL files.

```bash
python json2haproxy.py
```

**Generated files**:

- `waf.acl` &mdash; one regex per line, designed for `-f /etc/haproxy/waf.acl`
- `README.md` &mdash; in-tree integration notes

| Env var | Default |
|---------|---------|
| `INPUT_FILE` | `owasp_rules.json` |
| `OUTPUT_DIR` | `waf_patterns/haproxy/` |

---

### `badbots.py`

Independently fetches public bad-bot User-Agent lists and emits a `bots.*` file in each platform output directory.

```bash
python badbots.py
```

**Generated files** (per platform):

| Platform | File |
|----------|------|
| Nginx | `waf_patterns/nginx/bots.conf` |
| Apache | `waf_patterns/apache/bots.conf` |
| Traefik | `waf_patterns/traefik/bots.toml` |
| HAProxy | `waf_patterns/haproxy/bots.acl` |

| Env var | Purpose |
|---------|---------|
| `GITHUB_TOKEN` | Raises the GitHub API rate limit when fetching upstream lists |

If a remote source is unreachable, the script falls back to a bundled list.

## Import / install scripts

The `import_*.py` scripts copy generated files into a server's runtime configuration directory and (optionally) splice an `Include` line into the main config. They are configured **entirely** through environment variables.

### `import_nginx_waf.py`

| Env var | Default |
|---------|---------|
| `WAF_DIR` | `waf_patterns/nginx` |
| `NGINX_WAF_DIR` | `/etc/nginx/waf/` |
| `NGINX_CONF` | `/etc/nginx/nginx.conf` |
| `BACKUP_DIR` | `/etc/nginx/waf_backup/` |

### `import_apache_waf.py`

| Env var | Default |
|---------|---------|
| `WAF_DIR` | `waf_patterns/apache` |
| `APACHE_WAF_DIR` | `/etc/modsecurity.d/` |
| `APACHE_CONF` | `/etc/apache2/apache2.conf` |
| `BACKUP_DIR` | `/etc/modsecurity.d/backup` |

### `import_traefik_waf.py`

| Env var | Default |
|---------|---------|
| `WAF_DIR` | `waf_patterns/traefik` |
| `TRAEFIK_WAF_DIR` | `/etc/traefik/waf/` |
| `TRAEFIK_DYNAMIC_CONF` | `/etc/traefik/dynamic.toml` |
| `BACKUP_DIR` | `/etc/traefik/waf_backup/` |

### `import_haproxy_waf.py`

| Env var | Default |
|---------|---------|
| `WAF_DIR` | `waf_patterns/haproxy` |
| `HAPROXY_WAF_DIR` | `/etc/haproxy/waf/` |
| `HAPROXY_CONF` | `/etc/haproxy/haproxy.cfg` |
| `BACKUP_DIR` | `/etc/haproxy/waf_backup/` |

::: warning Privileged paths
The defaults point at system directories (`/etc/...`). Run the import scripts as root, or override every env var to point at a sandbox before running them.
:::

## Data format

### `owasp_rules.json`

A flat JSON array. Each item is a single rule with two required fields:

```json
[
  {
    "category": "SQLI",
    "pattern": "(?i:union[\\s\\S]+select)"
  },
  {
    "category": "XSS",
    "pattern": "(?i:<script[^>]*>)"
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `category` | string | OWASP CRS category derived from the source filename (e.g. `SQLI`, `XSS`, `RCE`, `LFI`, `RFI`, `BOTS`) |
| `pattern` | string | Regex extracted from the matching `SecRule` directive |

The converters validate each pattern with Python's `re.compile` before emitting platform-specific output, so malformed regexes are dropped rather than propagated.

## Extending the toolchain

### Adding a new platform

1. Copy one of the existing `json2<platform>.py` converters as a starting point.
2. Implement `_sanitize_pattern()` for the target syntax (escape rules differ between Nginx, Apache, HAProxy, …).
3. Emit your output under `waf_patterns/<platform>/`.
4. Add a workflow step in `.github/workflows/update_patterns.yml` to package the result.
5. Add a documentation page under `docs/`.

### Pinning a different OWASP CRS version

```bash
python owasp2json.py --ref v3.3
```

### Pulling rules from a fork

`owasp2json.py` hardcodes the upstream repository constant `coreruleset/coreruleset`. To target a fork, edit `GITHUB_REPO_URL` near the top of the script.

## Dependencies

Listed in [`requirements.txt`](https://github.com/fabriziosalmi/patterns/blob/main/requirements.txt). Install with:

```bash
pip install -r requirements.txt
```

The pipeline targets Python **3.11+**.
