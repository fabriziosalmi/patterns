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

### `python3 -m patterns`

Compiles `owasp_rules.json` into the configuration of a web server. Every target is a backend registered in `patterns/backends/`.

```bash
python3 -m patterns list                          # the targets
python3 -m patterns validate                      # owasp_rules.json against its schema
python3 -m patterns build --all                   # every target into waf_patterns/<target>/
python3 -m patterns build --target nginx          # one; repeat --target for several
python3 -m patterns build --all --out /tmp/out    # somewhere else: /tmp/out/<target>/
python3 -m patterns build --all --check           # write nothing; exit 1 if the files on disk are stale
```

| Option | Default | Purpose |
|---|---|---|
| `--target T` / `--all` | (one is required) | What to build. |
| `--input FILE` | `owasp_rules.json` | The IR. |
| `--out DIR` | `waf_patterns` | The directory each target's directory goes in. |
| `--check` | off | Compare instead of write. This is how CI tells that the committed output is not what the IR produces. |

The same IR gives the same files, byte for byte, whatever the hash seed or the machine, **on Python 3.11 or later**. The backends keep a pattern only if Python's `re` compiles it, and from 3.11 `re` rejects a global flag such as `(?i)` that is not at the start of the pattern, where 3.9 accepts it: four Apache rules are in one output and not in the other. `build` warns on an older Python, and the committed files are the 3.11 ones. Exit codes: 0 on success, 1 when a file cannot be read or `--check` finds a difference, 2 on a usage error.

::: warning The `json2*.py` scripts are deprecated
`json2nginx.py`, `json2apache.py`, `json2traefik.py` and `json2haproxy.py` remain for one release as thin wrappers: each runs one target, reads `INPUT_FILE` and `OUTPUT_DIR` as before, and says it is deprecated. Use `python3 -m patterns build --target <name>`.
:::

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

A JSON document with a `schema_version`, the provenance of the rules, the anomaly score defaults and a `rules` list. Each record says which variables it is matched against, which operator it applies, in which phase, whether it is part of a chain and what score it adds.

```json
{
  "schema_version": 1,
  "_provenance": { "source_ref": "v4.29.0", "license": "Apache-2.0" },
  "score_defaults": { "critical": 5, "error": 4, "warning": 3, "notice": 2 },
  "rules": [
    {
      "id": "941110",
      "directive": "SecRule",
      "category": "XSS",
      "phase": 2,
      "variables": [{ "name": "ARGS", "selector": null, "count": false, "excluded": false }],
      "operator": { "name": "rx", "negated": false, "argument": "(?i)<script[^>]*>[\\s\\S]*?" },
      "transformations": ["utf8toUnicode", "urlDecodeUni", "htmlEntityDecode"],
      "action": "block",
      "crs_severity": "CRITICAL",
      "severity": "high",
      "score": { "direction": "inbound", "level": "critical", "paranoia_level": 1 },
      "chain": null
    }
  ]
}
```

The record above is abridged. Every field, its type and its meaning are in [Intermediate representation](/ir), and the format is specified by [`schema/ir.schema.json`](https://github.com/fabriziosalmi/patterns/blob/main/schema/ir.schema.json).

The converters currently read two older fields, `pattern` and `location`, and validate each pattern with Python's `re.compile` before emitting platform-specific output, so malformed regexes are dropped rather than propagated.

## Extending the toolchain

### Adding a new platform

1. Copy one of the modules in `patterns/backends/` as a starting point.
2. In it, define a `Backend` subclass with a `name` (what `--target` takes), a `title` (how generated files name the target) and `render(ir)`, which returns `{relative path: content}` and writes nothing. Decorate it with `@register`. Implement `_sanitize_pattern()` for the target syntax: escape rules differ between Nginx, Apache, HAProxy, &hellip;
3. Add the module to the import list at the bottom of `patterns/backends/__init__.py`. That is the whole registration.
4. Run `python3 -m patterns build --target <name>` and commit the result under `waf_patterns/<name>/`. `build --all --check` in CI keeps it current.
5. Add a zip step in `.github/workflows/update_patterns.yml` to package the result.
6. Add a documentation page under `docs/`.

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
