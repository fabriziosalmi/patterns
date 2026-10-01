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

  * No ordinary request may be refused. This is an invariant. The nginx
    backend excludes any rule matching corpus.BENIGN before emitting it, so a failure
    here means that exclusion stopped working.

  * Attacks are counted, against a floor rather than an exact figure. CRS
    changes upstream every few weeks and the daily workflow regenerates from it,
    so pinning an exact number would fail on someone else's release. The floor
    catches what matters: detection collapsing back to nothing.

Usage:
    python3 tests/test_nginx_blocking.py [directory]

`directory` defaults to waf_patterns/nginx. Requires the `nginx` binary.
"""

import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from patterns.corpus import ATTACKS, BENIGN  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conformance  # noqa: E402
from conformance import in_clear  # noqa: E402

PORT = 18998
BOTS_PORT = 18999

# A blocking subset converted without CRS's transformations catches an attack
# written in clear and misses the same attack percent-encoded, because the
# pattern was written to run after `t:urlDecodeUni` and nginx cannot apply it.
# Both floors are below what the current rule set achieves; they exist to catch
# a collapse, not to pin a number. See README, "What this catches".
MINIMUM_CAUGHT_IN_CLEAR = 16
MINIMUM_CAUGHT_ENCODED = 5

# What only a phrase list and `$uri` catch (#52): CRS refuses `/.env` and `/.git/config`
# with `@pmFromFile restricted-files.data` on REQUEST_FILENAME, and a scanner's User-Agent
# with `@pmFromFile scanners-user-agents.data`. None of them is a regular expression, so
# they were all lost until the lists were written as alternations and the path was read
# from `$uri`, which nginx has already decoded. They are caught percent-encoded as well,
# because `$uri` arrives decoded. A named list is a stronger guard than a floor: the floors
# above would still pass if these three were lost and some other rule took their place.
MUST_CATCH = ["sensitive file", "git directory", "scanner user agent"]


def wrap(maps_file: Path, rules_file: Path, workdir: Path, bots_file: Optional[Path] = None) -> str:
    """
    The configuration the documentation tells people to build.

    The bad-bot list, if there is one, is a server of its own on the next port, so that
    what it refuses is the list and not the rules: a scanner's agent is refused by both.
    """
    root = workdir / "www"
    root.mkdir(exist_ok=True)
    (root / "index.html").write_text("ok\n")
    bots = ""
    if bots_file:
        bots = f"""
  include {bots_file};

  server {{
    listen {BOTS_PORT};
    root {root};
    if ($bad_bot) {{ return 403; }}
    location / {{ index index.html; }}
  }}
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
{bots}
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
    return conformance.send(PORT, entry)


def synthetic_rule(rule_id: str, argument: str, severity: str) -> dict:
    """A rule on the query string, as the IR holds one, for a check that needs two that overlap."""
    return {"id": rule_id, "directive": "SecRule", "category": "TEST", "phase": 2,
            "variables": [{"name": "QUERY_STRING", "selector": None, "count": False, "excluded": False}],
            "operator": {"name": "rx", "negated": False, "argument": argument}, "transformations": [],
            "action": "block", "severity": severity, "crs_severity": "CRITICAL", "score": None,
            "chain": None, "target_rule_id": None, "pattern": "@rx " + argument, "location": "Query-String"}


def key_order() -> int:
    """
    nginx takes the first key of a map that matches, and `if ($waf_x ~ "^high")` reads what that
    key said. A `medium` key ahead of a `high` one that matches the same value made the request
    pass: the high rule was in the file and never spoke. Two rules that overlap, the medium one
    first as CRS has them, go through the real nginx.

    Returns:
        The number of failures.
    """
    from patterns import backends, ir  # here: the rest of this file reads the generated files
    files = backends.get("nginx").compile(ir.IR(rules=[
        synthetic_rule("1", "zqxjk", "medium"), synthetic_rule("2", "zqxjk.*attack", "high")])).files
    print("\nthe order of the keys of a map, in nginx")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "maps.conf").write_text(files["waf_maps.conf"])
        (work / "rules.conf").write_text(files["waf_rules.conf"])
        conf = work / "nginx.conf"
        conf.write_text(wrap(work / "maps.conf", work / "rules.conf", work))
        started = subprocess.run(["nginx", "-c", str(conf), "-p", str(work)], capture_output=True, text=True)
        if started.returncode != 0:
            print(f"  FAIL  nginx would not start: {started.stderr.strip()}")
            return 1
        try:
            time.sleep(1)
            from patterns.corpus import request  # noqa: E402
            status = send(request("a value that a medium rule and a high rule both match", "/", "q=zqxjk+attack"))
        finally:
            subprocess.run(["nginx", "-s", "stop", "-c", str(conf), "-p", str(work)], capture_output=True)
    if status != 403:
        print(f"  FAIL  a value that a high rule matches was answered {status}: a medium key written first hid it")
        return 1
    print("  ok    a value that a high rule matches is refused, though a medium key comes first in CRS")
    return 0


def main() -> int:
    if shutil.which("nginx") is None:
        print("nginx is not on PATH: cannot exercise the generated configuration.")
        return 2

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "waf_patterns" / "nginx"
    maps_file, rules_file = target / "waf_maps.conf", target / "waf_rules.conf"
    bots_file = target / "bots.conf" if (target / "bots.conf").is_file() else None
    for path in (maps_file, rules_file):
        if not path.is_file():
            print(f"FAIL  missing {path}")
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        conf = workdir / "nginx.conf"
        conf.write_text(wrap(maps_file.resolve(), rules_file.resolve(), workdir,
                              bots_file.resolve() if bots_file else None))
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
            bots = conformance.Checker("the bad-bot list (bots.conf)")
            if bots_file:
                conformance.report_bots(bots, lambda agent: conformance.send(
                    BOTS_PORT, conformance.user_agent_request(agent, "/")) == 403)
            else:
                bots.note("no bots.conf in this directory")
        finally:
            subprocess.run(["nginx", "-s", "stop", "-c", str(conf), "-p", str(workdir)],
                           capture_output=True)

    failures = bots.failures + key_order()

    print(f"\nordinary traffic ({len(BENIGN)} requests)")
    if refused_benign:
        failures += 1
        print(f"  FAIL  {len(refused_benign)} ordinary requests were refused:")
        for name in refused_benign:
            print(f"        {name}")
        print("        the nginx backend is meant to exclude any rule matching "
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

    # The rules the corpus kept out, and the request each one matched. A rule is
    # only excluded because an ordinary request matched it, so each line is a
    # decision to check: was the request ordinary, or was the rule wrong?
    excluded = re.findall(r"^#\s+(\S+) \(([^)]+)\) matches: (.+)$", maps_file.read_text(), re.M)
    by_name = {e["name"]: e for e in BENIGN}
    print(f"\nrules kept out because they match ordinary traffic ({len(excluded)})")
    for rule_id, category, name in excluded:
        entry = by_name.get(name)
        if entry is None:
            failures += 1
            print(f"  FAIL  {rule_id} names a request that is not in the corpus: {name}")
            continue
        print(f"        {rule_id} ({category}) matches {name!r}: {entry['why']}")

    print("\nwhat only a phrase list and $uri catch (#52)")
    for label, caught in (("in clear", caught_clear), ("percent-encoded", caught_encoded)):
        lost = [name for name in MUST_CATCH if name not in caught]
        if lost:
            failures += 1
            print(f"  FAIL  {label}: not refused: {', '.join(lost)}")
        else:
            print(f"  ok    {label}: {', '.join(MUST_CATCH)}")

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
