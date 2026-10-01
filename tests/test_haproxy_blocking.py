#!/usr/bin/env python3
"""
What the generated HAProxy configuration does in a real HAProxy.

The HAProxy backend wrote `waf.acl` and nothing ever loaded it (#67, #68). Run through
haproxy itself it did not load however it was loaded: as the fragment of a frontend it is
shaped like, it failed on unmatched quotes, on fetches HAProxy does not have and on a line
of hundreds of names; and as the pattern file docs/haproxy.md said to use it as, every
line of it was taken for a regular expression. And the bad-bot list, used as a fragment,
refused every browser (#78), because a space ends a word in a line of HAProxy configuration.

It is now what the documentation always said: pattern files, which HAProxy reads a regular
expression to a line, and `waf.cfg`, the `acl` lines that load them and the `deny`, to
paste into a `frontend`. This does what a person does with them:

  load     `haproxy -c` on a frontend with `waf.cfg` pasted in and the pattern files where
           it says they are (/etc/haproxy/waf). If it does not load, the alert says why.
  traffic  where it loads, the corpus through the rules, as in tests/conformance.py.
  bots     `bots.acl`, a pattern file for `acl bad_bot hdr(user-agent) -m reg -i -f`, on its
           own, held to what the other targets' lists are (tests/conformance.py `report_bots`).
  both     the two in one frontend, as docs/haproxy.md shows: they load together.

What a target does today is EXPECTED. So that the phases are tested before they have
anything real to measure, the same code is first run against files that are known to be
right (tests/fixtures/haproxy): if that does not pass, the harness is what is broken.

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

# Where waf.cfg says the pattern files are.
WAF_DIR = "/etc/haproxy/waf"

# The two lines docs/haproxy.md shows for the bad-bot list.
BOT_LINES = [f"acl bad_bot hdr(user-agent) -m reg -i -f {WAF_DIR}/bots.acl",
             "http-request deny deny_status 403 if bad_bot"]

# What the generated files do today. A rule that matches an ordinary request is not
# written, so none is refused; the floors are below what the rules refuse now, and are
# there to catch a collapse (see tests/test_nginx_blocking.py).
EXPECTED: Dict = {"loads": True, "benign": [], "floor_clear": 15, "floor_encoded": 12,
                  # What only a phrase list catches (#52, #92): CRS refuses `/.env` and `/.git/config` with
                  # `@pmFromFile restricted-files.data` on the path, and a scanner's User-Agent with
                  # `@pmFromFile scanners-user-agents.data`, which HAProxy reads with `-m sub -i -f`. A named
                  # list is a stronger guard than a floor: the floor would pass if some other rule took their place.
                  "must_catch": ["sensitive file", "git directory", "scanner user agent"]}

# For the known-good files: they load, refuse nothing ordinary, and refuse the scanner and
# the script tag, in clear and (the query string is decoded) percent-encoded.
FIXTURE = {"loads": True, "benign": [], "floor_clear": 2, "floor_encoded": 2}

HEAD = """global
    maxconn 64
defaults
    mode http
    timeout connect 5s
    timeout client 10s
    timeout server 10s
"""
ANSWER = "    http-request return status 200 content-type text/plain string ok\n"


def alerts(output: str) -> List[str]:
    """The [ALERT] lines haproxy printed, without the file and line."""
    return [re.sub(r"^\[ALERT\]\s+\(\d+\) : config : parsing \[[^\]]*\]:?\s*", "", l).strip()
            for l in output.splitlines() if l.startswith("[ALERT]")]


def lines_of(path: Path) -> List[str]:
    """The lines of a configuration fragment: what is not blank and not a comment."""
    return [l for l in path.read_text().splitlines() if l.strip() and not l.lstrip().startswith("#")]


def frontend(fragments: List[str]) -> str:
    """A configuration with these lines pasted into the one frontend, as the docs say."""
    body = "".join(f"    {line}\n" for line in fragments)
    return f"{HEAD}frontend f\n    bind *:8080\n{body}{ANSWER}"


def check_load(configuration: str, waf_dir: Path):
    """
    Runs `haproxy -c` on a configuration, with the pattern files where the lines say.

    Returns:
        Whether it loads, and the alerts when it does not.
    """
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        # The image runs haproxy as an unprivileged user, and a temporary directory is
        # private to the one that made it: on Linux the configuration cannot be opened.
        workdir.chmod(0o755)
        (workdir / "haproxy.cfg").write_text(configuration)
        checked = c.run_once(IMAGE, ["haproxy", "-c", "-f", "/cfg/haproxy.cfg"],
                             {workdir: "/cfg", waf_dir.resolve(): WAF_DIR})
        return checked.returncode == 0, alerts(checked.stdout + checked.stderr)


def serve(configuration: str, waf_dir: Path):
    """A container running haproxy on this configuration, as a context manager."""
    holder = tempfile.TemporaryDirectory()
    workdir = Path(holder.name)
    workdir.chmod(0o755)
    (workdir / "haproxy.cfg").write_text(configuration)
    container = c.Container(["haproxy", "-f", "/cfg/haproxy.cfg"], {PORT: 8080},
                            {workdir: "/cfg", waf_dir.resolve(): WAF_DIR})
    container.holder = holder  # the directory lives as long as the container
    return container


def exercise(waf_dir: Path, expected: Dict, check: c.Checker) -> None:
    """Loads the rules and the bad-bot list, and sends the corpus."""
    rules = lines_of(waf_dir / "waf.cfg")
    configuration = frontend(rules)
    loads, found = check_load(configuration, waf_dir)

    print("\nload")
    if not check.loads("haproxy", loads, expected["loads"], expected.get("issue")):
        for line in found[:3]:
            check.note(line[:200])
        return
    if loads:
        with serve(configuration, waf_dir) as server:
            if not server.wait(PORT):
                check.fail("haproxy loaded the files and did not answer")
                check.note(server.logs()[-300:])
                return
            traffic = c.measure(PORT)
        c.report_traffic(check, traffic, expected["benign"], expected["floor_clear"],
                         expected["floor_encoded"])
        if expected.get("must_catch"):
            print("\nwhat only a phrase list catches")
            for label, caught in (("in clear", traffic.caught_clear), ("percent-encoded", traffic.caught_encoded)):
                check.expect(f"{label}: {', '.join(expected['must_catch'])}",
                             [n for n in expected["must_catch"] if n not in caught], [])

    print("\nthe bad-bot list (bots.acl)")
    if not (waf_dir / "bots.acl").is_file():
        check.note("no bots.acl in this directory")
        return
    bots = frontend(BOT_LINES)
    loads_bots, found = check_load(bots, waf_dir)
    if not check.expect("haproxy loads it", loads_bots, True):
        for line in found[:3]:
            check.note(line[:200])
        return
    with serve(bots, waf_dir) as server:
        if not server.wait(PORT):
            check.fail("haproxy loaded bots.acl and did not answer")
            return
        c.report_bots(check, lambda agent: c.send(PORT, c.user_agent_request(agent, "/")) == 403)

    print("\nthe two together")
    both, found = check_load(frontend(rules + BOT_LINES), waf_dir)
    if not check.expect("they load in one frontend", both, True):
        for line in found[:3]:
            check.note(line[:200])


def main() -> int:
    if c.docker() is None:
        print("docker is not available: cannot run haproxy.")
        return 2
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "waf_patterns" / "haproxy"
    if not (target / "waf.cfg").is_file():
        print(f"FAIL  missing {target / 'waf.cfg'}")
        return 1

    check = c.Checker("the harness, on files known to be right")
    exercise(REPO_ROOT / "tests" / "fixtures" / "haproxy", FIXTURE, check)
    if check.failures:
        print("\nthe harness fails on files that are known to be good; "
              "the result for the generated files would mean nothing")
        return 1

    check = c.Checker(f"the generated files ({target})")
    exercise(target, EXPECTED, check)
    return c.finish(check)


if __name__ == "__main__":
    sys.exit(main())
