#!/usr/bin/env python3
"""
NGINX_MAX_PARAMETER, checked against nginx rather than against a comment.

One over-long parameter is not one lost rule. nginx refuses the file, so the
whole generated rule set stops loading, and that failure shipped once already
(#22). The constant is therefore worth pinning to what nginx actually does,
which is what this does: it builds a map with a key of exactly the declared
limit and one a single byte longer, and asserts nginx accepts the first and
refuses the second.

Two things it protects:

  - the boundary itself. The constant was 4096 and the comparison was `>`, so a
    key nginx refuses was emitted. The boundary is discovered here rather than
    written down, so a build that moved it fails this instead of shipping a
    configuration that will not load.
  - the unit. nginx counts bytes; a Python string counts characters. Every
    pattern CRS writes in a .conf file is ASCII, because non-ASCII is spelled
    `\\x{...}`, so the two agree today. They stop agreeing the moment anything
    reads the .data files behind `@pmFromFile`: ssrf.data contains `\\u2460`
    and `\\u3002`, three bytes each.

Usage:
    python3 tests/test_parameter_limit.py

Requires the `nginx` binary; skips with status 0 if it is not on PATH.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import json2nginx  # noqa: E402

failures = 0
checks = 0


def check(description, actual, expected):
    global failures, checks
    checks += 1
    if actual != expected:
        failures += 1
        print(f"  FAIL  {description}")
        print(f"        expected {expected!r}, got {actual!r}")


def loads(key: str) -> bool:
    """Reports whether nginx accepts a map holding this one key."""
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        conf = workdir / "nginx.conf"
        # Every path nginx opens during `-t` is pointed inside the work
        # directory. The packaged defaults under /run, /var/log and
        # /var/lib/nginx are not writable by an unprivileged user, and nginx
        # refuses the configuration for that reason rather than for the key,
        # which turns this probe into one that answers no to everything.
        conf.write_text(
            f"pid {workdir}/nginx.pid;\n"
            f"error_log {workdir}/error.log;\n"
            "events { worker_connections 64; }\n"
            "http {\n"
            "  access_log off;\n"
            f"  client_body_temp_path {workdir}/client_body;\n"
            f"  proxy_temp_path {workdir}/proxy;\n"
            f"  fastcgi_temp_path {workdir}/fastcgi;\n"
            f"  uwsgi_temp_path {workdir}/uwsgi;\n"
            f"  scgi_temp_path {workdir}/scgi;\n"
            "  map $args $probe {\n"
            '    default "";\n'
            f'    {key} "1";\n'
            "  }\n"
            "  server { listen 18997; location / { return 204; } }\n"
            "}\n"
        )
        result = subprocess.run(
            ["nginx", "-t", "-c", str(conf), "-p", str(workdir)],
            # nginx quotes the offending key back, truncated at a byte
            # boundary, so its own error message is not valid UTF-8 when the
            # key is multibyte. That is itself the point being tested.
            capture_output=True, encoding="utf-8", errors="replace",
        )
        return result.returncode == 0


def key_of(size_in_bytes: int, filler: str = "a") -> str:
    """A quoted, valid map key of exactly this many bytes."""
    unit = len(filler.encode("utf-8"))
    body = filler * ((size_in_bytes - 4) // unit)
    key = '"~*' + body + '"'
    assert len(key.encode("utf-8")) == size_in_bytes, len(key.encode("utf-8"))
    return key


if shutil.which("nginx") is None:
    print("nginx is not on PATH: skipping the parameter limit check.")
    sys.exit(0)

limit = json2nginx.NGINX_MAX_PARAMETER

# Discovered rather than asserted. Measured at 4095 bytes on nginx 1.31.5 and on
# the nginx the Ubuntu runners install, which is NGX_CONF_BUFFER less the
# terminating byte, but a build that compiled it differently would move it. What
# this needs to know is not the number, it is that the constant is at or below
# whatever the nginx in use accepts.
low, high = 16, 8192
while low < high:
    middle = (low + high + 1) // 2
    if loads(key_of(middle)):
        low = middle
    else:
        high = middle - 1
accepted = low
print(f"\nthis nginx accepts a map key of at most {accepted} bytes")

print("the boundary")
check(f"NGINX_MAX_PARAMETER ({limit}) is not above it",
      limit <= accepted, True)
check("a key one byte over what it accepts is refused",
      loads(key_of(accepted + 1)), False)

print("the unit")
# Three bytes per character, so this key is over the limit in bytes and a third
# of it in characters. Measuring in characters would call it comfortably short,
# emit it, and take the whole file down.
oversize = next(n for n in range(accepted + 1, accepted + 8) if (n - 4) % 3 == 0)
multibyte = key_of(oversize, filler="\u2460")
check(f"a multibyte key of {oversize} bytes is refused", loads(multibyte), False)
check("and it is under the limit in characters, which is the trap",
      len(multibyte) < limit, True)

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
