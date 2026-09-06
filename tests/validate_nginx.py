#!/usr/bin/env python3
"""
Validates the generated nginx configuration with nginx itself.

CI validated this output with `crossplane`, a Python nginx parser. A parser
checks that the file tokenises; it does not know that `http` cannot nest, that a
parameter may not exceed 4096 characters, or that `add_header` is not allowed
inside an `if` in server context. All three shipped for months with CI green
(#21, #22, #23), so this runs the real `nginx -t` instead.

Usage:
    python3 tests/validate_nginx.py [directory]

`directory` defaults to waf_patterns/nginx. Requires the `nginx` binary.
Exits non-zero if the configuration nginx is asked to load is rejected.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import json2nginx  # noqa: E402
DEFAULT_DIR = REPO_ROOT / "waf_patterns" / "nginx"


def wrap(maps_file: Path, rules_file: Path, workdir: Path) -> str:
    """
    Builds the smallest nginx.conf that loads the two generated files the way
    the documentation tells people to: maps in `http`, rules in `server`.

    Every path nginx opens during `-t` is pointed inside the work directory,
    because the packaged defaults under /run and /var/log are not writable by an
    unprivileged user.
    """
    return f"""pid {workdir}/nginx.pid;
error_log {workdir}/error.log;
events {{ worker_connections 64; }}
http {{
  access_log off;
  client_body_temp_path {workdir}/client_body;
  proxy_temp_path {workdir}/proxy;
  fastcgi_temp_path {workdir}/fastcgi;
  uwsgi_temp_path {workdir}/uwsgi;
  scgi_temp_path {workdir}/scgi;

  include {maps_file};

  server {{
    listen 18999;
    include {rules_file};
    location / {{ return 204; }}
  }}
}}
"""


def main() -> int:
    if shutil.which("nginx") is None:
        print("nginx is not on PATH: cannot validate the generated configuration.")
        return 2

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DIR
    maps_file = target / "waf_maps.conf"
    rules_file = target / "waf_rules.conf"

    for path in (maps_file, rules_file):
        if not path.is_file():
            print(f"FAIL  missing {path}")
            return 1

    # An over-long parameter is reported by nginx with a line number but no
    # measurement, so report it here where the number is useful.
    over_limit = [
        (n, len(line.encode("utf-8")))
        for n, line in enumerate(maps_file.read_text().splitlines(), 1)
        if len(line.strip().encode("utf-8")) > json2nginx.NGINX_MAX_PARAMETER
    ]
    for line_number, length in over_limit:
        print(f"      {maps_file.name}:{line_number} is {length} bytes")

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        conf = workdir / "nginx.conf"
        conf.write_text(wrap(maps_file.resolve(), rules_file.resolve(), workdir))
        result = subprocess.run(
            ["nginx", "-t", "-c", str(conf), "-p", str(workdir)],
            capture_output=True, text=True,
        )

    if result.returncode == 0:
        entries = sum(
            1 for line in maps_file.read_text().splitlines()
            if line.strip().startswith('"~')
        )
        maps = sum(
            1 for line in maps_file.read_text().splitlines()
            if line.startswith("map ")
        )
        print(f"ok    nginx accepts the generated configuration "
              f"({maps} maps, {entries} entries)")
        return 0

    print("FAIL  nginx rejected the generated configuration")
    for line in result.stderr.strip().splitlines():
        print(f"      {line}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
