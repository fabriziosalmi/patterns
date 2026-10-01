#!/usr/bin/env python3
"""
What the generated Traefik middleware does in a real Traefik, with the real plugin.

The Traefik output had no check at all. It was refused before it reached a middleware,
because the expressions were written into TOML basic strings, where `\\$` is not an
escape, and it asked for a plugin called `badbot` that takes `userAgent`, which is no
plugin that exists (#69). It is now written for `agence-gaya/traefik-plugin-blockuseragent`
(Apache-2.0, in Traefik's plugin catalog): a list of Go regular expressions, `regex`,
and a 403 when the User-Agent matches one.

The test runs that plugin, v0.1.8, unmodified (tests/fixtures/traefik/plugin, with its
licence and where it came from). `TRAEFIK_PLUGIN=catalog` has Traefik download the same
version from the catalog instead, which is what a person would do, and is how the copy
was checked.

  load     Traefik starts on the generated files, through the file provider as
           docs/traefik.md says, and logs no error. Both files: a middleware that no
           router uses is never built, so the bad-bot list is given a router of its own.
  traffic  the corpus through the rules, as in tests/conformance.py. A request that gets
           through is answered by Traefik's own `ping`.
  bots     what the bad-bot list does to scanners, to browsers and to search engines.

What a target does today is EXPECTED. So that the traffic phase is tested before it has
anything to measure, the same code first runs a configuration that is known to load
(tests/fixtures/traefik).

Usage:
    python3 tests/test_traefik_blocking.py [directory]

`directory` defaults to waf_patterns/traefik. Requires docker.
"""

import os
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
from patterns.corpus import BENIGN  # noqa: E402

IMAGE = "traefik:3.7"
PORT = 18903
PLUGIN = "blockuseragent"
PLUGIN_MODULE = "github.com/agence-gaya/traefik-plugin-blockuseragent"
PLUGIN_VERSION = "v0.1.8"
SCANNER = "sqlmap/1.8#stable"

# What the generated output does today.
EXPECTED: Dict = {
    "loads": True,
    # Ordinary requests the rules refuse, by name: none, since a rule that matches one is not written.
    "benign": [],
    "floor_clear": 0,
    "floor_encoded": 0,
    # The bad-bot list: it must refuse a scanner, and must not refuse a browser or a search engine.
    "bots_refuse_scanner": True,
    # A command substitution in the User-Agent, which the first expression of
    # middleware.toml matches: the written rules refuse, and the plugin reads `regex`.
    "probe_user_agent": "$(id)",
    # Today's list refuses these, and two of them are search engines it is documented
    # not to refuse (#78). curl, python-requests and Go-http-client are in it on
    # purpose; the monitor and the link unfurler are a side effect of one catch-all.
    "bots_refused_ordinary": ["a link unfurler", "a search engine", "an uptime monitor", "bingbot",
                              "curl", "go http client", "python requests"],
    "bots_issue": "#78",
}

# Known to load: refuses nothing ordinary, and refuses the scanner.
FIXTURE = {"loads": True, "benign": [], "floor_clear": 1, "floor_encoded": 1,
           "probe_user_agent": SCANNER, "bots_refuse_scanner": False, "bots_refused_ordinary": []}

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def static_config() -> str:
    """The static configuration: a local copy of the plugin, or the one the catalog serves."""
    if os.getenv("TRAEFIK_PLUGIN") == "catalog":
        plugin = (f'[experimental.plugins.{PLUGIN}]\n  moduleName = "{PLUGIN_MODULE}"\n'
                  f'  version = "{PLUGIN_VERSION}"\n')
    else:
        plugin = f'[experimental.localPlugins.{PLUGIN}]\n  moduleName = "{PLUGIN_MODULE}"\n'
    return f"""[entryPoints.web]
  address = ":8000"
[providers.file]
  directory = "/etc/traefik/dynamic"
{plugin}[ping]
[log]
  level = "INFO"
"""


def middleware_names(text: str) -> List[str]:
    """The middlewares a file defines, from its `[http.middlewares.NAME...]` table headers."""
    return sorted(set(re.findall(r"^\[http\.middlewares\.([A-Za-z0-9_]+)(?:\.[^\]]*)?\]\s*$", text, re.M)))


def routes(waf: List[str], bots: List[str]) -> str:
    """Two routers: the rules on everything, and the bad-bot list on a path of its own."""
    def router(name, rule, names):
        chain = ", ".join(f'"{n}"' for n in names)
        return (f'[http.routers.{name}]\n  rule = "{rule}"\n  entryPoints = ["web"]\n'
                f'  middlewares = [{chain}]\n  service = "ping@internal"\n')
    text = router("waf", "PathPrefix(`/`)", waf)
    if bots:
        text += router("bots", "PathPrefix(`/__bots__`)", bots)
    return text


def errors(logs: str) -> List[str]:
    """The error lines Traefik logged, without colour or timestamp."""
    lines = [ANSI.sub("", l) for l in logs.splitlines()]
    return [re.sub(r"^\S+\s+ERR\s+", "", l) for l in lines if " ERR " in l]


def user_agent_request(user_agent: str, path: str) -> Dict[str, str]:
    return {"host": "example.com", "user_agent": user_agent, "referer": "", "content_type": "",
            "request_uri": path, "method": "GET", "body": ""}


def exercise(traefik_dir: Path, expected: Dict, check: c.Checker) -> None:
    """Starts Traefik on the files and, if it accepts them, sends the corpus and the bots."""
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        dynamic = work / "dynamic"
        dynamic.mkdir()
        plugin = work / "plugins" / "src" / PLUGIN_MODULE
        plugin.parent.mkdir(parents=True)
        shutil.copytree(REPO_ROOT / "tests" / "fixtures" / "traefik" / "plugin", plugin)
        waf, bots = [], []
        for name, names in (("middleware.toml", waf), ("bots.toml", bots)):
            if (traefik_dir / name).is_file():
                shutil.copy(traefik_dir / name, dynamic / name)
                names += middleware_names((traefik_dir / name).read_text())
        (dynamic / "routes.toml").write_text(routes(waf, bots))
        (work / "traefik.toml").write_text(static_config())

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
                return
            # The file provider reads the files a moment after start.
            deadline = time.time() + 15
            while time.time() < deadline and c.send(PORT, user_agent_request("probe", "/")) == 404:
                time.sleep(0.5)
            traffic = c.measure(PORT)
            probe = expected["probe_user_agent"]
            probed = c.send(PORT, user_agent_request(probe, "/")) == 403

            print("\nthe bad-bot list")
            refuses_scanner = c.send(PORT, user_agent_request(SCANNER, "/__bots__")) == 403
            refused = sorted(e["name"] for e in BENIGN
                             if e["category"] == "clients"
                             and c.send(PORT, user_agent_request(e["user_agent"], "/__bots__")) == 403)
            if bots:
                check.expect("refuses a scanner", refuses_scanner, expected["bots_refuse_scanner"])
                known = expected.get("bots_issue")
                check.expect("ordinary clients it refuses" + (f", as known ({known})" if known else ""),
                             refused, sorted(expected["bots_refused_ordinary"]))
            else:
                check.note("no bots.toml in this directory")
    print("\nthe rules")
    check.expect(f"refuse {expected['probe_user_agent']!r} in the User-Agent", probed, True)
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
