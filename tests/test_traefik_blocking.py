#!/usr/bin/env python3
"""
What the generated Traefik middleware does in a real Traefik.

The Traefik output had no check at all. Run through Traefik itself it is refused
before it reaches a middleware: the expressions are written into TOML basic
strings, where `\\$` is not an escape (#69).

The output is `[http.middlewares.NAME.plugin.badbot]` with `userAgent = [...]`,
which needs a plugin. The one it is written for is not named anywhere and I could
not identify it in the public catalog, so the test runs a stand-in, the smallest
thing that honours that contract (tests/fixtures/traefik/plugin): it compiles each
expression with Go's regexp, which is RE2, and refuses with 403 when one matches
the User-Agent. That checks that Traefik accepts the file and what the expressions
do in RE2. It says nothing about any published plugin.

  load     Traefik starts on the generated file, through the file provider as
           docs/traefik.md says, and logs no error.
  traffic  where it loads, the corpus, as in tests/conformance.py. A request that
           gets through is answered by Traefik's own `ping`.

What a target does today is EXPECTED, with its issue. A target that does not load
is not sent traffic. So that the traffic phase is not left untested until it can
run, the same code first runs a configuration that is known to load
(tests/fixtures/traefik).

Usage:
    python3 tests/test_traefik_blocking.py [directory]

`directory` defaults to waf_patterns/traefik. Requires docker.
"""

import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402
from conformance import REPO_ROOT  # noqa: E402

IMAGE = "traefik:3.7"
PORT = 18903
PLUGIN_MODULE = "github.com/fabriziosalmi/badbot"

# What the generated output does today. `alert` is a part of the first error.
EXPECTED: Dict = {"loads": False, "alert": "toml", "issue": "#69"}

# Known to load: refuses nothing ordinary, and refuses the scanner.
FIXTURE = {"loads": True, "benign": [], "floor_clear": 1, "floor_encoded": 1}

STATIC = """[entryPoints.web]
  address = ":8000"
[providers.file]
  directory = "/etc/traefik/dynamic"
[experimental.localPlugins.badbot]
  moduleName = "%s"
[ping]
[log]
  level = "INFO"
""" % PLUGIN_MODULE

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def middleware_names(text: str) -> List[str]:
    """The middlewares a file defines, from its `[http.middlewares.NAME]` headers."""
    return sorted(set(re.findall(r"^\[http\.middlewares\.([A-Za-z0-9_]+)\]\s*$", text, re.M)))


def routes(names: List[str]) -> str:
    """A router that sends everything through the middlewares, to Traefik's ping."""
    chain = ", ".join(f'"{n}"' for n in names)
    return ('[http.routers.app]\n  rule = "PathPrefix(`/`)"\n  entryPoints = ["web"]\n'
            f"  middlewares = [{chain}]\n  service = \"ping@internal\"\n")


def errors(logs: str) -> List[str]:
    """The error lines Traefik logged, without colour or timestamp."""
    lines = [ANSI.sub("", l) for l in logs.splitlines()]
    return [re.sub(r"^\S+\s+ERR\s+", "", l) for l in lines if " ERR " in l]


def exercise(traefik_dir: Path, expected: Dict, check: c.Checker) -> None:
    """Starts Traefik on the files and, if it accepts them, sends the corpus."""
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        dynamic = work / "dynamic"
        dynamic.mkdir()
        plugin = work / "plugins" / "src" / PLUGIN_MODULE
        plugin.parent.mkdir(parents=True)
        shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "traefik" / "plugin", plugin)
        shutil.copy(traefik_dir / "middleware.toml", dynamic / "middleware.toml")
        names = middleware_names((traefik_dir / "middleware.toml").read_text())
        (dynamic / "routes.toml").write_text(routes(names))
        (work / "traefik.toml").write_text(STATIC)

        volumes = {work / "traefik.toml": "/etc/traefik/traefik.toml",
                   dynamic: "/etc/traefik/dynamic",
                   work / "plugins": "/plugins-local"}
        print("\nload")
        with c.Container([IMAGE], {PORT: 8000}, volumes) as server:
            answered = server.wait(PORT, timeout=60)
            time.sleep(3)
            logged = errors(server.logs())
            loads = answered and not logged
            if not check.loads("traefik", loads, expected["loads"], expected.get("issue")):
                for line in logged[:3]:
                    check.note(line[:200])
                return
            if not loads:
                first = logged[0] if logged else "(did not start)"
                if expected["alert"] not in first.lower():
                    check.fail(f"the first error is not the expected one ({expected['alert']!r}): {first[:160]}")
                else:
                    check.note(first[:150])
                return
            # The file provider reads the files a moment after start.
            deadline = time.time() + 15
            while time.time() < deadline and c.send(PORT, {
                    "host": "example.com", "user_agent": "probe", "referer": "",
                    "content_type": "", "request_uri": "/"}) == 404:
                time.sleep(0.5)
            traffic = c.measure(PORT)
    c.report_traffic(check, traffic, expected["benign"], expected["floor_clear"],
                     expected["floor_encoded"])


def main() -> int:
    if c.docker() is None:
        print("docker is not available: cannot run traefik.")
        return 2
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "waf_patterns" / "traefik"
    if not (target / "middleware.toml").is_file():
        print(f"FAIL  missing {target / 'middleware.toml'}")
        return 1

    check = c.Checker("the harness, on a configuration known to load")
    exercise(REPO_ROOT / "tests" / "fixtures" / "traefik", FIXTURE, check)
    if check.failures:
        print("\nthe harness fails on a configuration that is known to be good; "
              "the result for the generated files would mean nothing")
        return 1

    check = c.Checker(f"the generated files ({target})")
    exercise(target, EXPECTED, check)
    return c.finish(check)


if __name__ == "__main__":
    sys.exit(main())
