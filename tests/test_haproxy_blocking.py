#!/usr/bin/env python3
"""
What the generated HAProxy configuration does in a real HAProxy.

The HAProxy backend wrote `waf.acl` and nothing ever loaded it. Run through
haproxy itself it does not load, however it is loaded, and this says how:

  fragment    the file as it is: `acl` and `http-request` lines, which belong in a
              `frontend`. This is what the generated file is shaped like.
  documented  the file as docs/haproxy.md says to use it: `-f waf.acl`, a file of
              patterns, one regular expression per line. The generated file is not
              one, so each line of it is taken as an expression.

Neither loads, for different reasons, and that is what EXPECTED records. The
phases are the ones in tests/conformance.py. A target that does not load is not
sent traffic. So that the traffic phase is not left untested until it can run, the
same code is first run against a configuration that is known to load
(tests/fixtures/haproxy): if that does not pass, the harness is what is broken.

Usage:
    python3 tests/test_haproxy_blocking.py [directory]

`directory` defaults to waf_patterns/haproxy. Requires docker.
"""

import re
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402
from conformance import REPO_ROOT  # noqa: E402

IMAGE = "haproxy:latest"
PORT = 18901

# What the generated configuration does today. `alert` is a part of the first
# thing haproxy complains about. `issue` tracks it. When a line here stops being
# true, the test fails and says which: change it then, and add the floors.
EXPECTED: Dict[str, Dict] = {
    "fragment": {"loads": False, "alert": "unmatched quote", "issue": "#67"},
    "documented": {"loads": False, "alert": "error detected while parsing ACL", "issue": "#68"},
}

# For the known-good configuration: it loads, refuses nothing ordinary, and
# refuses the scanner and the script tag.
FIXTURE = {"loads": True, "benign": [], "floor_clear": 2, "floor_encoded": 0}

HEAD = """global
    maxconn 64
defaults
    mode http
    timeout connect 5s
    timeout client 10s
    timeout server 10s
"""
ANSWER = "    http-request return status 200 content-type text/plain string ok\n"


def configuration(mode: str, waf_dir: Path) -> str:
    """The configuration a person would write to load the generated files."""
    if mode == "fragment":
        lines = [l for l in (waf_dir / "waf.acl").read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        body = "".join(f"    {line}\n" for line in lines)
        return f"{HEAD}frontend f\n    bind *:8080\n{body}{ANSWER}"
    return f"""{HEAD}frontend f
    bind *:8080
    acl waf_match    path,url_dec -m reg -i -f /waf/waf.acl
    acl waf_match_q  query        -m reg -i -f /waf/waf.acl
    http-request deny deny_status 403 if waf_match || waf_match_q
{ANSWER}"""


def alerts(output: str) -> List[str]:
    """The [ALERT] lines haproxy printed, without the file and line."""
    return [re.sub(r"^\[ALERT\]\s+\(\d+\) : config : parsing \[[^\]]*\]:?\s*", "", l).strip()
            for l in output.splitlines() if l.startswith("[ALERT]")]


def exercise(waf_dir: Path, modes: Dict[str, Dict], check: c.Checker) -> None:
    """Loads the files in each mode and, where they load, sends the corpus."""
    for mode, expected in modes.items():
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / f"{mode}.cfg").write_text(configuration(mode, waf_dir))
            volumes = {workdir: "/cfg", waf_dir.resolve(): "/waf"}
            checked = c.run_once(IMAGE, ["haproxy", "-c", "-f", f"/cfg/{mode}.cfg"], volumes)
            found = alerts(checked.stdout + checked.stderr)
            loads = checked.returncode == 0

            print(f"\n{mode}")
            if not check.loads("haproxy", loads, expected["loads"], expected.get("issue")):
                for line in found[:3]:
                    check.note(line[:160])
                continue
            if not loads:
                first = found[0] if found else ""
                if expected["alert"] not in first:
                    check.fail(f"the first alert is not the expected one ({expected['alert']!r}): {first[:140]}")
                else:
                    check.note(first[:150])
                continue

            with c.Container(["haproxy", "-f", f"/cfg/{mode}.cfg"], {PORT: 8080}, volumes) as server:
                if not server.wait(PORT):
                    check.fail("haproxy loaded the file and did not answer")
                    check.note(server.logs()[-300:])
                    continue
                traffic = c.measure(PORT)
            c.report_traffic(check, traffic, expected["benign"], expected["floor_clear"],
                             expected["floor_encoded"])


def main() -> int:
    if c.docker() is None:
        print("docker is not available: cannot run haproxy.")
        return 2
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "waf_patterns" / "haproxy"
    if not (target / "waf.acl").is_file():
        print(f"FAIL  missing {target / 'waf.acl'}")
        return 1

    check = c.Checker("the harness, on a configuration known to load")
    exercise(REPO_ROOT / "tests" / "fixtures" / "haproxy", {"fragment": FIXTURE}, check)
    if check.failures:
        print("\nthe harness fails on a configuration that is known to be good; "
              "the result for the generated files would mean nothing")
        return 1

    check = c.Checker(f"the generated files ({target})")
    exercise(target, EXPECTED, check)
    return c.finish(check)


if __name__ == "__main__":
    sys.exit(main())
