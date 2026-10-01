#!/usr/bin/env python3
"""
What badbots.py writes for Traefik.

The bad-bot lists are written by badbots.py, not by a backend, so nothing that checks
a backend looked at them. Run through a real Traefik with the real plugin, `bots.toml`
did not start: one entry, `Yandex(?!Search)`, uses a lookahead that Go's RE2 does not
have, and one entry the engine cannot compile stops the whole middleware (#69). And it
was not valid TOML in the first place, for the reason the rules were not (backslashes
in basic strings).

This holds the writer to what it should do:

  * the file is TOML, and every entry is read back as what it was;
  * an entry RE2 cannot compile is left out, and the file says which and why;
  * what is left is still every other entry, so one bad entry does not take the list;
  * case is ignored, as the nginx list does it.

Usage:
    python3 tests/test_badbots.py
"""

import logging
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import badbots  # noqa: E402

try:
    import tomllib
except ImportError:  # before 3.11
    tomllib = None

logging.disable(logging.CRITICAL)

failures = 0
checks = 0


def check(description, actual, expected=True):
    global failures, checks
    checks += 1
    if actual != expected:
        failures += 1
        print(f"  FAIL  {description}")
        print(f"        expected {expected!r}, got {actual!r}")


def written(bots):
    """What badbots writes to bots.toml for a list of bots."""
    with tempfile.TemporaryDirectory() as tmp:
        badbots.OUTPUT_DIRS["traefik"] = tmp
        badbots.generate_traefik_conf(bots)
        return (Path(tmp) / "bots.toml").read_text()


BOTS = [r"008\/", r"2ip\.ru", "Acunetix", r"[a-z0-9\-_]*(bot|crawl)", "O'Brien-bot", 'say"hi',
        "Yandex(?!Search)", r"(?<!x)bad", r"(a)\1"]
text = written(BOTS)

print("\nthe plugin")
check("it is the plugin the backend is written for",
      f"plugin.{badbots.PLUGIN}]" in text and badbots.PLUGIN == "blockuseragent", True)
check("and its list is `regex`, not the `userAgent` of a plugin that does not exist",
      "regex = [" in text and "userAgent" not in text, True)

print("what is left out")
check("an entry with a lookahead is left out, and named", "# Not written: Yandex(?!Search)" in text, True)
check("so are a lookbehind and a backreference", all(
    f"# Not written: {b}" in text for b in (r"(?<!x)bad", r"(a)\1")), True)
check("and the reason is said", "which re2 does not have" in text, True)

if tomllib:
    read = tomllib.loads(text)["http"]["middlewares"]["bad_bot_block"]["plugin"]["blockuseragent"]["regex"]
    print("what is written")
    check("the file is TOML", bool(read), True)
    check("every entry that can be written is, as it was given, with case ignored",
          read, ["(?i)" + b for b in BOTS if b not in ("Yandex(?!Search)", r"(?<!x)bad", r"(a)\1")])
    check("one entry the engine cannot compile does not take the list with it", len(read), 6)
    check("a backslash is a backslash", r"(?i)008\/" in read and r"(?i)2ip\.ru" in read, True)
    check("a quote does not end the string", "(?i)O'Brien-bot" in read and '(?i)say"hi' in read, True)
else:
    print("Python before 3.11: the TOML itself is not read back here, and the checks that need it are skipped")

print("the committed list")
committed = (REPO_ROOT / "waf_patterns" / "traefik" / "bots.toml").read_text()
check("is written for the same plugin", f"plugin.{badbots.PLUGIN}]" in committed, True)
if tomllib:
    entries = tomllib.loads(committed)["http"]["middlewares"]["bad_bot_block"]["plugin"]["blockuseragent"]["regex"]
    check("is TOML, with the entries of the list", len(entries) > 1000, True)
    check("and nothing in it is an expression RE2 refuses",
          [e for e in entries if __import__("patterns.dialects", fromlist=["x"]).check("re2", e)], [])

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
