#!/usr/bin/env python3
"""
What the generated Apache configuration does in a real Apache with ModSecurity.

The Apache workflow ran `httpd -t` in a loop that never used the file it was
looping over, in an image with no ModSecurity, on files mounted where Apache does
not read them. It could not fail. Loaded by the real thing, through the include
docs/apache.md recommends, the committed output did not load (#55): operators CRS
writes as `@lt` and `@pm` were written out as if they were patterns, after `re.escape`
had turned them into other patterns. And `bots.conf` gave every rule the same id,
which ModSecurity refuses (#80).

  load      `httpd -t` with `Include /waf/*.conf`, as the documentation says. If it
            does not load, each file is tried alone, to say how many do.
  traffic   where it loads, the corpus through the rule files, as in tests/conformance.py.
  engine    the rule files do not say `SecRuleEngine`: docs/apache.md says to start in
            `DetectionOnly`, and a file that says `On` takes that away. The engine is
            set to `DetectionOnly` before the include, and nothing may be refused.
  bots      `bots.conf` on its own, held to what the other targets' lists are
            (tests/conformance.py `report_bots`).

What a target does today is EXPECTED, with its issue. A target that does not load
is not sent traffic. So that the traffic phase is not left untested until it can
run, the same code first runs a configuration that is known to load
(tests/fixtures/apache).

Usage:
    python3 tests/test_apache_blocking.py [directory]

`directory` defaults to waf_patterns/apache. Requires docker.
"""

import re
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402
from conformance import REPO_ROOT  # noqa: E402
from patterns.corpus import ATTACKS  # noqa: E402

# Apache 2.4 with ModSecurity 2 (mod_security2) and nothing else, from the OWASP
# project. The Core Rule Set is not in it: the rules under test are ours.
IMAGE = "owasp/modsecurity:apache"
PORT = 18902

# What the generated output does today. A rule that matches an ordinary request is not
# written, so none is refused; the floors are below what the rules refuse now, and are
# there to catch a collapse (see tests/test_nginx_blocking.py).
EXPECTED: Dict = {"loads": True, "benign": [], "floor_clear": 11, "floor_encoded": 11}

FIXTURE = {"loads": True, "benign": [], "floor_clear": 2, "floor_encoded": 0}


LOCATION = '<Location "/">\n    ProxyPass !\n</Location>\n'


def includes(files: List[str]) -> str:
    """
    The file Apache reads for extra configuration: the rules, as the
    documentation says to include them, after the one thing the image needs to
    answer for itself. It is a reverse proxy to a backend that is not there, so
    `/` is taken out of the proxy and Apache serves it.
    """
    return LOCATION + "".join(f"Include /waf/{name}\n" for name in files)


def setup(files: List[str], engine: str) -> str:
    """
    The image's ModSecurity setup, with the engine set as docs/apache.md says and the
    rules included after it: what a person's configuration looks like. The image reads
    the extra file above before it reads its own setup, so a rule file that sets the
    engine would be overridden there, and the order cannot be tested from it.
    """
    return ("Include /etc/modsecurity.d/modsecurity.conf\n"
            "Include /etc/modsecurity.d/modsecurity-override.conf\n"
            f"SecRuleEngine {engine}\n" + "".join(f"Include /waf/{name}\n" for name in files))


def configtest(waf_dir: Path, files: List[str]) -> Tuple[bool, Optional[str]]:
    """Runs `httpd -t` with the given rule files included. Returns (loads, first error)."""
    with tempfile.TemporaryDirectory() as tmp:
        extra = Path(tmp) / "httpd-locations.conf"
        extra.write_text(includes(files))
        done = c.run_once(
            IMAGE, ["httpd", "-t"],
            {waf_dir.resolve(): "/waf",
             extra: "/usr/local/apache2/conf/extra/httpd-locations.conf"},
            env={"PORT": "8080"})
    if done.returncode == 0:
        return True, None
    lines = [l.strip() for l in (done.stdout + done.stderr).splitlines() if l.strip()]
    error = next((l for l in lines if l.startswith("AH")), lines[-1] if lines else "")
    detail = lines[lines.index(error) + 1] if error in lines and lines.index(error) + 1 < len(lines) else ""
    return False, f"{error} {detail}".strip()


_KEEP: List[tempfile.TemporaryDirectory] = []


def _mounted(name: str, text: str, inside: str) -> Dict[Path, str]:
    """A file with this content, mounted at `inside`. It lives as long as the process."""
    holder = tempfile.TemporaryDirectory()
    holder_path = Path(holder.name)
    holder_path.chmod(0o755)
    _KEEP.append(holder)
    path = holder_path / name
    path.write_text(text)
    path.chmod(0o644)
    return {path: inside}


def serve(waf_dir: Path, files: List[str], engine: Optional[str] = None):
    """
    A container running Apache with these files included. With `engine`, the image's
    ModSecurity setup sets it and then includes the files; without, they are included
    the way docs/apache.md shows and the image sets the engine itself.
    """
    volumes = {waf_dir.resolve(): "/waf"}
    if engine:
        volumes.update(_mounted("httpd-locations.conf", LOCATION,
                                "/usr/local/apache2/conf/extra/httpd-locations.conf"))
        volumes.update(_mounted("setup.conf", setup(files, engine), "/etc/modsecurity.d/setup.conf"))
    else:
        volumes.update(_mounted("httpd-locations.conf", includes(files),
                                "/usr/local/apache2/conf/extra/httpd-locations.conf"))
    return c.Container([IMAGE], {PORT: 8080}, volumes, env={"PORT": "8080"})


def exercise(waf_dir: Path, expected: Dict, check: c.Checker, each: bool) -> None:
    """Loads every file together and, if they load, sends the corpus and the bots."""
    files = sorted(p.name for p in waf_dir.glob("*.conf"))
    rules = [name for name in files if name != "bots.conf"]
    loads, error = configtest(waf_dir, files)

    print("\nload")
    if not check.loads("apache", loads, expected["loads"], expected.get("issue")):
        if error:
            check.note(error[:200])
        return
    if not loads:
        if expected["alert"] not in (error or ""):
            check.fail(f"the first error is not the expected one ({expected['alert']!r}): {(error or '')[:160]}")
        else:
            check.note((error or "")[:150])
        if each:
            loading = [name for name in files if configtest(waf_dir, [name])[0]]
            check.note(f"{len(loading)} of {len(files)} files load on their own"
                       + (f": {', '.join(loading)}" if loading else ""))
        return

    with serve(waf_dir, rules) as server:
        if not server.wait(PORT, timeout=60):
            check.fail("apache loaded the rules and did not answer")
            check.note(server.logs()[-300:])
            return
        traffic = c.measure(PORT)
    c.report_traffic(check, traffic, expected["benign"], expected["floor_clear"],
                     expected["floor_encoded"])

    print("\nthe engine mode is the deployment's")
    check.expect("the rule files say nothing about SecRuleEngine",
                 [n for n in rules if re.search(r"^\s*SecRuleEngine\b", (waf_dir / n).read_text(), re.M)], [])
    for engine, refuses in (("DetectionOnly", False), ("On", True)):
        with serve(waf_dir, rules, engine=engine) as server:
            if not server.wait(PORT, timeout=60):
                check.fail(f"apache did not answer with SecRuleEngine {engine}")
                check.note(server.logs()[-300:])
                return
            refused = [e["name"] for e in ATTACKS if c.send(PORT, e) == 403 or c.send(PORT, c.in_clear(e)) == 403]
            if refuses:
                check.expect(f"with SecRuleEngine {engine} the rules refuse something", bool(refused), True)
            else:
                check.expect(f"with SecRuleEngine {engine} nothing is refused", refused, [])

    if "bots.conf" in files:
        print("\nthe bad-bot list (bots.conf)")
        with serve(waf_dir, ["bots.conf"]) as server:
            if not server.wait(PORT, timeout=60):
                check.fail("apache loaded bots.conf and did not answer")
                check.note(server.logs()[-300:])
                return
            c.report_bots(check, lambda agent: c.send(PORT, c.user_agent_request(agent, "/")) == 403)


def main() -> int:
    if c.docker() is None:
        print("docker is not available: cannot run apache.")
        return 2
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "waf_patterns" / "apache"
    if not list(target.glob("*.conf")):
        print(f"FAIL  no .conf files in {target}")
        return 1

    check = c.Checker("the harness, on a configuration known to load")
    exercise(REPO_ROOT / "tests" / "fixtures" / "apache", FIXTURE, check, each=False)
    if check.failures:
        print("\nthe harness fails on a configuration that is known to be good; "
              "the result for the generated files would mean nothing")
        return 1

    check = c.Checker(f"the generated files ({target})")
    exercise(target, EXPECTED, check, each=True)
    return c.finish(check)


if __name__ == "__main__":
    sys.exit(main())
