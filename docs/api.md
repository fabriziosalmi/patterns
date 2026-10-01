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
python3 -m patterns coverage                      # what each target does with each rule
python3 -m patterns coverage --write              # put that table in README.md and docs/coverage.md
python3 -m patterns coverage --check              # exit 1 if those tables are out of date
```

| Option | Default | Purpose |
|---|---|---|
| `--target T` / `--all` | (one is required) | What to build. |
| `--input FILE` | `owasp_rules.json` | The IR. |
| `--out DIR` | `waf_patterns` | The directory each target's directory goes in. |
| `--check` | off | Compare instead of write. This is how CI tells that the committed output is not what the IR produces. |

`diff` compares two IR files by rule and says what the change does to each target:

```bash
python3 -m patterns diff previous_rules.json owasp_rules.json               # the summary, as Markdown
python3 -m patterns diff old.json new.json --json changes.json              # and the whole of it
python3 -m patterns diff old.json new.json --no-targets                     # rules only: no compiling
```

It reports and does not judge: it exits 0 whatever it finds. The nightly release puts the summary in its notes and attaches `changes.json`; see [Changes between releases](#changes-between-releases).

`build --all` also writes `coverage.json` next to the targets: a verdict for every rule and target, which [Coverage](/coverage) explains. It refuses to write anything if a backend would write a regular expression its target's engine does not compile.

The same IR gives the same files, byte for byte, whatever the hash seed or the machine, **on Python 3.11 or later**. The dialect check that decides whether a target's engine compiles a pattern parses it with Python's own parser, and only from 3.11 does that parser know atomic groups and possessive quantifiers, which Go's RE2 does not have. `build` warns on an older Python, and the committed files are the 3.11 ones. Exit codes: 0 on success, 1 when a file cannot be read or `--check` finds a difference, 2 on a usage error.

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

- `waf.cfg` &mdash; the `acl` lines that load the pattern files, and one `deny`, to paste into a `frontend`
- `waf-<where>[-<converters>].acl` &mdash; pattern files: one regex per line, loaded with `-m reg -f`
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

A JSON document with a `schema_version`, the provenance of the rules, the anomaly score defaults, the phrase lists the `@pmFromFile` rules read (`data_files`) and a `rules` list. Each record says which variables it is matched against, which operator it applies, in which phase, whether it is part of a chain and what score it adds.

```json
{
  "schema_version": 2,
  "_provenance": { "source_ref": "v4.29.0", "license": "Apache-2.0" },
  "score_defaults": { "critical": 5, "error": 4, "warning": 3, "notice": 2 },
  "data_files": { "restricted-files.data": [".htaccess", ".env"] },
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

## Changes between releases

`python3 -m patterns diff OLD NEW --json changes.json` writes one document. A rule is found by its CRS id, and a record with none by what it is part of: a link of a chain by the chain and its position (`932207+1`), a `SecRuleUpdateTargetById` by the rule it updates and what it adds (`update:932240:...`). So a rule inserted before it does not make it look changed.

| Key | Meaning |
|---|---|
| `format` | The version of this document's shape. |
| `from`, `to` | `source_ref` (the CRS tag), `schema_version` and `records` of each file. |
| `compared_on` | The fields a rule was compared on: the IR's, or, if either file predates the IR, the ones both have (then `targets` is absent). |
| `summary` | `added`, `removed`, `changed`, `unchanged`, `source_ref_changed` and `data_files_changed`. |
| `added`, `removed` | One record per rule: `id`, `label`, `category`, `rule` (the operator and argument) and `written_by`, the targets that write it. |
| `changed` | One record per rule: `id`, `label`, `category` and `fields`, each changed field with its `from` and `to`. |
| `data_files` | The phrase lists the `@pmFromFile` rules read (absent if either file predates schema 2): the files `added` and `removed`, and for each `changed` one how many phrases were added and removed and which rules read it. A list can change when no rule does, and what a target writes for its rules then changes with it. |
| `targets` | Per target: `written` (`from`, `to`), `output_changed` (the rules that changed and that the target writes both times: its output changes), and `status_changed` (the rules whose verdict changed, with `from` and `to`). |

The two lists in `targets` are not the same event. A rule that changed and is written both times changes the target's output, which a person reviewing a release wants to know. A rule that a target started or stopped writing is a status change, and is the one to read first: `941100` on HAProxy: `approximate` to `dropped (invalid-regex)`.

One record is a line in each list, in numeric order of id, so the file diffs and compares cleanly.

## Extending the toolchain

### Adding a new platform

1. Copy one of the modules in `patterns/backends/` as a starting point.
2. In it, define a `Backend` subclass with a `name` (what `--target` takes), a `title` (how generated files name the target) and `compile(ir)`, which returns `Compiled(files, decisions)` and writes nothing: `files` is `{relative path: content}`, and `decisions` has one `Decision` per rule, recorded where the backend writes the rule or drops it (with a reason from `patterns.coverage.REASONS`). Decorate it with `@register`. Implement `_sanitize_pattern()` for the target syntax: escape rules differ between Nginx, Apache, HAProxy, &hellip;
   Declare `capabilities` too: the regular expression dialect, the operators and transformations the backend *writes* (not what the target could do), whether it honours case-insensitivity, and the request components it matches on. The [coverage matrix](/coverage) is computed from it, and `tests/test_coverage.py` fails if a declaration claims something the output does not show.
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
