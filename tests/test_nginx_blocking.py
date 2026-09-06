#!/usr/bin/env python3
"""
What the generated nginx configuration does to real requests.

`validate_nginx.py` proves the file loads. Loading was never the hard part: the
released configuration loaded and blocked nothing, because every map was keyed
on `$1` (#44), and once that was fixed it still blocked almost nothing, because
the generator ran `re.escape` over each pattern and unescaped fourteen
metacharacters by hand. That turned `[0-9]` into `[0\\-9]` (the three characters
0, - and 9), `.*` into `\\.*` (zero or more literal dots) and `foo$` into
`foo\\$` (a literal dollar). Every rule emitted was a different rule from the
one CRS wrote, and no file-level check can see that.

So this starts nginx and sends traffic.

Two things are asserted, and they are not the same kind of claim:

  * No ordinary request may be refused. This is an invariant. json2nginx.py
    excludes any rule matching corpus.BENIGN before emitting it, so a failure
    here means that exclusion stopped working.

  * Attacks are counted, against a floor rather than an exact figure. CRS
    changes upstream every few weeks and the daily workflow regenerates from it,
    so pinning an exact number would fail on someone else's release. The floor
    catches what matters: detection collapsing back to nothing.

Usage:
    python3 tests/test_nginx_blocking.py [directory]

`directory` defaults to waf_patterns/nginx. Requires the `nginx` binary.
"""

import http.client
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from corpus import ATTACKS, BENIGN  # noqa: E402

PORT = 18998

# A blocking subset converted without CRS's transformations catches an attack
# written in clear and misses the same attack percent-encoded, because the
# pattern was written to run after `t:urlDecodeUni` and nginx cannot apply it.
# Both floors are below what the current rule set achieves; they exist to catch
# a collapse, not to pin a number. See README, "What this catches".
MINIMUM_CAUGHT_IN_CLEAR = 12
MINIMUM_CAUGHT_ENCODED = 2


def in_clear(entry):
    """
    The same attack with nothing hidden: what is sent when there is no reason
    to encode. Control characters stay encoded because they cannot travel in a
    request line, and `&` and `#` stay encoded because decoding them would
    change the request rather than the payload.
    """
    decoded = urllib.parse.unquote(entry["args"])
    decoded = decoded.replace(" ", "+").replace("&", "%26").replace("#", "%23")
    decoded = "".join(c if c.isprintable() else "%%%02X" % ord(c) for c in decoded)
    return dict(entry, args=decoded,
                request_uri=f"{entry['path']}?{decoded}" if decoded else entry["path"])


def wrap(maps_file: Path, rules_file: Path, workdir: Path) -> str:
    """The configuration the documentation tells people to build."""
    root = workdir / "www"
    root.mkdir(exist_ok=True)
    (root / "index.html").write_text("ok\n")
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
    listen {PORT};
    root {root};
    include {rules_file};
    location / {{ index index.html; }}
  }}
}}
"""


def send(entry) -> int:
    """Sends one corpus entry and returns the status code."""
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    headers = {"Host": entry["host"]}
    if entry["user_agent"]:
        headers["User-Agent"] = entry["user_agent"]
    if entry["referer"]:
        headers["Referer"] = entry["referer"]
    if entry["content_type"]:
        headers["Content-Type"] = entry["content_type"]
    try:
        connection.request("GET", entry["request_uri"], headers=headers)
        return connection.getresponse().status
    finally:
        connection.close()


def main() -> int:
    if shutil.which("nginx") is None:
        print("nginx is not on PATH: cannot exercise the generated configuration.")
        return 2

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "waf_patterns" / "nginx"
    maps_file, rules_file = target / "waf_maps.conf", target / "waf_rules.conf"
    for path in (maps_file, rules_file):
        if not path.is_file():
            print(f"FAIL  missing {path}")
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        conf = workdir / "nginx.conf"
        conf.write_text(wrap(maps_file.resolve(), rules_file.resolve(), workdir))
        started = subprocess.run(["nginx", "-c", str(conf), "-p", str(workdir)],
                                 capture_output=True, text=True)
        if started.returncode != 0:
            print("FAIL  nginx would not start")
            print(started.stderr.strip())
            return 1
        try:
            time.sleep(1)
            refused_benign = [e["name"] for e in BENIGN if send(e) == 403]
            caught_encoded = [e["name"] for e in ATTACKS if send(e) == 403]
            caught_clear = [e["name"] for e in ATTACKS if send(in_clear(e)) == 403]
        finally:
            subprocess.run(["nginx", "-s", "stop", "-c", str(conf), "-p", str(workdir)],
                           capture_output=True)

    failures = 0

    print(f"\nordinary traffic ({len(BENIGN)} requests)")
    if refused_benign:
        failures += 1
        print(f"  FAIL  {len(refused_benign)} ordinary requests were refused:")
        for name in refused_benign:
            print(f"        {name}")
        print("        json2nginx.py is meant to exclude any rule matching "
              "corpus.BENIGN before emitting it.")
    else:
        print(f"  ok    none refused")

    print(f"\nattacks ({len(ATTACKS)} requests, each sent twice)")
    print(f"  in clear:          {len(caught_clear)}/{len(ATTACKS)} refused")
    print(f"  percent-encoded:   {len(caught_encoded)}/{len(ATTACKS)} refused")
    for label, caught, floor in (("in clear", caught_clear, MINIMUM_CAUGHT_IN_CLEAR),
                                 ("percent-encoded", caught_encoded, MINIMUM_CAUGHT_ENCODED)):
        if len(caught) < floor:
            failures += 1
            print(f"  FAIL  {label}: {len(caught)} refused, floor is {floor}")
    if not failures:
        print("  ok    both above the floor")

    print("\nnot caught in clear:")
    for entry in ATTACKS:
        if entry["name"] not in caught_clear:
            print(f"        {entry['name']}")

    if failures:
        return 1
    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
