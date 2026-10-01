#!/usr/bin/env python3
"""
What the generated Envoy configuration does in a real Envoy.

Envoy has no rule language, and the one thing in it that can refuse a request on what it
says is the RBAC HTTP filter with `action: DENY`, which matches a header or the path against
a regular expression. That is what the Envoy target writes (patterns/backends/envoy.py), and
what Envoy does with it is not what a reading of the filter's documentation says: it matches
the *whole* value, so an expression has to be put between two `.*`; it does not decode the
path or the query string; and it refuses an expression whose compiled RE2 program is bigger
than 100 unless a runtime layer says otherwise, which every CRS expression is.

This does what a person does with the files:

  load     `envoy --mode validate` on a bootstrap with `waf-rbac.yaml` as an item of
           `http_filters` before the router, and `runtime.yaml` merged in. If it does not
           load, the error says why.
  traffic  where it loads, the corpus through the rules, as in tests/conformance.py.
  bots     `bots-rbac.yaml`, a second filter, on its own, held to what the other targets'
           lists are (tests/conformance.py `report_bots`).
  both     the two in one bootstrap: they load together.

What a target does today is EXPECTED. So that the phases are tested before they have anything
real to measure, the same code is first run against files that are known to be right
(tests/fixtures/envoy): if that does not pass, the harness is what is broken.

Usage:
    python3 tests/test_envoy_blocking.py [directory]

`directory` defaults to waf_patterns/envoy. Requires docker and PyYAML.
"""

import re
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402
from conformance import REPO_ROOT  # noqa: E402

IMAGE = "envoyproxy/envoy:v1.32.13"
PORT = 18904

# What the generated files do today. A rule that matches an ordinary request is not written, so
# none is refused. The floors are below what the rules refuse now: Envoy decodes nothing, so the
# attacks percent-encoded are the ones that pass (see tests/test_nginx_blocking.py).
EXPECTED: Dict = {"loads": True, "benign": [], "floor_clear": 15, "floor_encoded": 5,
                  # What only a phrase list catches (#52, #92): CRS refuses `/.env` and `/.git/config` with
                  # `@pmFromFile restricted-files.data` on the path, and a scanner's User-Agent with
                  # `@pmFromFile scanners-user-agents.data`, which Envoy gets as one `contains` permission for each
                  # phrase. A named list is a stronger guard than a floor: the floor would pass if some other rule
                  # took their place. Nothing is decoded, but these three have nothing in them to encode.
                  "must_catch": ["sensitive file", "git directory", "scanner user agent"]}

# For the known-good files: they load, refuse nothing ordinary, and refuse the scanner and the
# script tag in clear, and only the scanner when the tag is percent-encoded.
FIXTURE = {"loads": True, "benign": [], "floor_clear": 2, "floor_encoded": 1}


def bootstrap(filters: List[dict], runtime: dict) -> str:
    """A bootstrap with these filters before the router and this runtime, answering 200."""
    document = {
        "static_resources": {"listeners": [{
            "name": "ingress",
            "address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}},
            "filter_chains": [{"filters": [{
                "name": "envoy.filters.network.http_connection_manager",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3."
                             "HttpConnectionManager",
                    "stat_prefix": "ingress",
                    "route_config": {"virtual_hosts": [{
                        "name": "all", "domains": ["*"],
                        "routes": [{"match": {"prefix": "/"},
                                    "direct_response": {"status": 200, "body": {"inline_string": "ok\n"}}}]}]},
                    "http_filters": filters + [{
                        "name": "envoy.filters.http.router",
                        "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"},
                    }],
                },
            }]}],
        }]},
        **runtime,
    }
    return yaml.safe_dump(document, sort_keys=False)


def fragments(directory: Path, names: List[str]) -> List[dict]:
    """The filters of the files, each an item of `http_filters`."""
    found: List[dict] = []
    for name in names:
        found += yaml.safe_load((directory / name).read_text())
    return found


def check_load(configuration: str):
    """Runs `envoy --mode validate`. Returns whether it loads, and the error when it does not."""
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        workdir.chmod(0o755)
        (workdir / "envoy.yaml").write_text(configuration)
        (workdir / "envoy.yaml").chmod(0o644)
        checked = c.run_once(IMAGE, ["-c", "/cfg/envoy.yaml", "--mode", "validate"], {workdir: "/cfg"})
        output = checked.stdout + checked.stderr
        errors = [re.sub(r"^\[[^\]]*\]\[[^\]]*\]\[[^\]]*\]\s*(\[[^\]]*\]\s*)?", "", line).strip()
                  for line in output.splitlines() if "error" in line.lower() or "exception" in line.lower()]
        return checked.returncode == 0, errors or output.strip().splitlines()[-2:]


def serve(configuration: str):
    """A container running envoy on this configuration, as a context manager."""
    holder = tempfile.TemporaryDirectory()
    workdir = Path(holder.name)
    workdir.chmod(0o755)
    (workdir / "envoy.yaml").write_text(configuration)
    (workdir / "envoy.yaml").chmod(0o644)
    container = c.Container([IMAGE, "-c", "/cfg/envoy.yaml", "--log-level", "warn"], {PORT: 8080},
                            {workdir: "/cfg"})
    container.holder = holder  # the directory lives as long as the container
    return container


def exercise(directory: Path, expected: Dict, check: c.Checker) -> None:
    """Loads the rules and the bad-bot list, and sends the corpus."""
    runtime = yaml.safe_load((directory / "runtime.yaml").read_text())
    rules = bootstrap(fragments(directory, ["waf-rbac.yaml"]), runtime)
    loads, errors = check_load(rules)

    print("\nload")
    if not check.loads("envoy", loads, expected["loads"], expected.get("issue")):
        for line in errors[:3]:
            check.note(line[:220])
        return
    if loads:
        with serve(rules) as server:
            if not server.wait(PORT, timeout=60):
                check.fail("envoy loaded the files and did not answer")
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

    print("\nthe bad-bot list (bots-rbac.yaml)")
    if not (directory / "bots-rbac.yaml").is_file():
        check.note("no bots-rbac.yaml in this directory")
        return
    bots = bootstrap(fragments(directory, ["bots-rbac.yaml"]), runtime)
    loads_bots, errors = check_load(bots)
    if not check.expect("envoy loads it", loads_bots, True):
        for line in errors[:3]:
            check.note(line[:220])
        return
    with serve(bots) as server:
        if not server.wait(PORT, timeout=60):
            check.fail("envoy loaded bots-rbac.yaml and did not answer")
            return
        c.report_bots(check, lambda agent: c.send(PORT, c.user_agent_request(agent, "/")) == 403)

    print("\nthe two together")
    both, errors = check_load(bootstrap(fragments(directory, ["waf-rbac.yaml", "bots-rbac.yaml"]), runtime))
    if not check.expect("they load in one bootstrap", both, True):
        for line in errors[:3]:
            check.note(line[:220])


def main() -> int:
    if c.docker() is None:
        print("docker is not available: cannot run envoy.")
        return 2
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "waf_patterns" / "envoy"
    if not (target / "waf-rbac.yaml").is_file():
        print(f"FAIL  missing {target / 'waf-rbac.yaml'}")
        return 1

    check = c.Checker("the harness, on files known to be right")
    exercise(REPO_ROOT / "tests" / "fixtures" / "envoy", FIXTURE, check)
    if check.failures:
        print("\nthe harness fails on files that are known to be good; "
              "the result for the generated files would mean nothing")
        return 1

    check = c.Checker(f"the generated files ({target})")
    exercise(target, EXPECTED, check)
    return c.finish(check)


if __name__ == "__main__":
    sys.exit(main())
