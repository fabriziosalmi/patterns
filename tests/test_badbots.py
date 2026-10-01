#!/usr/bin/env python3
"""
What badbots.py writes for Traefik.

The bad-bot lists are written by badbots.py, not by a backend, so nothing that checks
a backend looked at them. Run through a real Traefik with the real plugin, `bots.toml`
did not start: one entry, `Yandex(?!Search)`, uses a lookahead that Go's RE2 does not
have, and one entry the engine cannot compile stops the whole middleware (#69). And it
was not valid TOML in the first place, for the reason the rules were not (backslashes
in basic strings).

A second finding of the same run (#78): the lists refused Google, Bing, every link
preview and every uptime monitor, because one entry matches any agent with `bot` in it
and others name a monitor or a messenger. A bad-bot list that does that is an outage
with a name. The corpus says who a site wants (`corpus.wanted_user_agents`), and an
entry that matches one of them is left out.

This holds the writer to what it should do:

  * the file is TOML, and every entry is read back as what it was;
  * an entry RE2 cannot compile is left out, and the file says which and why;
  * what is left is still every other entry, so one bad entry does not take the list;
  * case is ignored, as the nginx list does it;
  * an entry that an ordinary client matches is left out, and each file says which and
    who it would have refused, in the four formats; HTTP libraries are not "ordinary"
    here, because refusing them is what the list is for;
  * the shared check that real servers are held to is itself shown to fail on a list
    that refuses a search engine, and on one that refuses nothing.

Usage:
    python3 tests/test_badbots.py
"""

import logging
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import badbots  # noqa: E402
from patterns import corpus  # noqa: E402

sys.path.insert(0, str(REPO_ROOT / "tests"))
import conformance  # noqa: E402

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

print("what RE2 cannot compile is left out")
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

print("what is left out for a client a site wants")
WANTED = corpus.wanted_user_agents()
SAMPLE = ["AhrefsBot", "sqlmap", "curl", "python-requests", "Go-http-client",
          r"[a-z0-9\-_]*(bot|crawl|spider|uptime)", "Pingdom", "WhatsApp", r"facebookexternalhit\/",
          "baidu\\.com", "Yandex(?!Search)", "oBot", "Mozilla", "Windows NT 10", "Googlebot"]
kept, left = badbots.leave_out_wanted(SAMPLE)
left_names = [b for b, _ in left]
check("a catch-all for `bot` is left out", r"[a-z0-9\-_]*(bot|crawl|spider|uptime)" in left_names, True)
check("so is an entry that names a search engine, a monitor or a messenger",
      all(b in left_names for b in ("Googlebot", "Pingdom", "WhatsApp", r"facebookexternalhit\/",
                                   "baidu\\.com", "Yandex(?!Search)")), True)
check("and one that is a browser's own word", all(b in left_names for b in ("Mozilla", "Windows NT 10")), True)
check("one that is a piece of a longer word of a client is, too", "oBot" in left_names, True)
check("a scanner stays", "sqlmap" in kept and "AhrefsBot" in kept, True)
check("HTTP libraries stay: refusing them is what the list is for",
      all(b in kept for b in ("curl", "python-requests", "Go-http-client")), True)
check("each is left out with the client it would have refused",
      all(c in WANTED for _, c in left), True)
check("an entry that is not a regular expression is read as the text it is",
      badbots.matching_client("(", {"x": "a ( b"}), "x")
check("and one that is, as the expression", badbots.matching_client("g.*bot", {"x": "Googlebot/2.1"}), "x")
check("an expression is matched with case ignored, as the lists do", badbots.matching_client("g[o]{2}glebot", WANTED),
      "googlebot")
check("and the text of an entry the same", badbots.matching_client("PINGDOM", WANTED), "pingdom")
check("nothing is left out of an empty list", badbots.leave_out_wanted([]), ([], []))
check("the note says which entry and who, one line each", badbots.left_out_note(left[:1]).count("\n"), 1)
check("and in the comment syntax of the file", badbots.left_out_note(left[:1], "# ").startswith("# Left out"), True)

print("the four lists, as written")
FILES = {"nginx": "bots.conf", "apache": "bots.conf", "traefik": "bots.toml", "haproxy": "bots.acl"}
for fmt in ("nginx", "apache", "traefik", "haproxy"):
    with tempfile.TemporaryDirectory() as tmp:
        for name in badbots.OUTPUT_DIRS:
            badbots.OUTPUT_DIRS[name] = tmp
        getattr(badbots, f"generate_{fmt}_conf")(kept, left)
        text = (Path(tmp) / FILES[fmt]).read_text()
    check(f"{fmt}: each entry left out is named at the top", text.count("# Left out") >= len(left), True)
    check(f"{fmt}: and the entries are not in the file as entries",
          "Pingdom\"" not in text.replace("# Left out", "") and "Googlebot\"" not in text, True)

print("the committed lists")
ROOT = REPO_ROOT / "waf_patterns"
entries = {
    "nginx": re.findall(r'^\s+"~\*(.*)" 1;$', (ROOT / "nginx" / "bots.conf").read_text(), re.M),
    "apache": re.findall(r'^SecRule REQUEST_HEADERS:User-Agent "@contains (.*)" "id:',
                         (ROOT / "apache" / "bots.conf").read_text(), re.M),
    "haproxy": re.findall(r"^acl bad_bot hdr_sub\(User-Agent\) -i (.*)$",
                          (ROOT / "haproxy" / "bots.acl").read_text(), re.M),
}
if tomllib:
    toml_entries = tomllib.loads((ROOT / "traefik" / "bots.toml").read_text())[
        "http"]["middlewares"]["bad_bot_block"]["plugin"][badbots.PLUGIN]["regex"]
    entries["traefik"] = [e[len("(?i)"):] for e in toml_entries]
for fmt, found in entries.items():
    check(f"{fmt}: the list is there, with its entries", len(found) > 1000, True)
    check(f"{fmt}: no entry refuses a client a site wants",
          sorted((e, badbots.matching_client(e, WANTED)) for e in found if badbots.matching_client(e, WANTED)), [])
    check(f"{fmt}: it still refuses the bots it is made of",
          [b for b in ("AhrefsBot", "SemrushBot", "MJ12bot") if b not in found], [])
    check(f"{fmt}: and says what it left out",
          (ROOT / fmt / FILES[fmt]).read_text().count("# Left out") > 5, True)

print("HAProxy: one entry is one word")
check("a space ends a word, so it is protected", badbots.haproxy_word("Ask Jeeves"), r"Ask\ Jeeves")
check("and a tab", badbots.haproxy_word("a\tb"), "a\\\tb")
check("a space a backslash already protects is not protected twice", badbots.haproxy_word(r"A\ B"), r"A\ B")
check("an entry that starts with a space keeps it", badbots.haproxy_word(" YLT"), r"\ YLT")
check("nothing else changes", badbots.haproxy_word(r"008\/"), r"008\/")
acl_lines = [l for l in (REPO_ROOT / "waf_patterns" / "haproxy" / "bots.acl").read_text().splitlines()
             if l.startswith("acl bad_bot")]
check("the committed file is one acl line per entry", len(acl_lines) > 1000, True)
check("and in none of them an entry is more than one word",
      [l for l in acl_lines
       if re.search(r"(?<!\\)[ \t]", l[len("acl bad_bot hdr_sub(User-Agent) -i "):])], [])

print("the check real servers are held to")


def verdict(refuses):
    """How many checks `report_bots` fails for a server that behaves as `refuses` says."""
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        checker = conformance.Checker("a list")
        conformance.report_bots(checker, refuses)
    return checker.failures


LIBRARIES = {e["user_agent"] for e in corpus.BENIGN if e["category"] == "libraries"}
BAD = set(conformance.BAD_BOTS)
check("a list that refuses the bots and the libraries passes",
      verdict(lambda a: a in BAD or a in LIBRARIES), 0)
check("one that refuses Googlebot too does not",
      verdict(lambda a: a in BAD or a in LIBRARIES or "Googlebot" in a), 1)
check("one that refuses everything does not", verdict(lambda a: True), 1)
check("one that refuses nothing does not (it is gone, not narrowed)", verdict(lambda a: False), 2)
check("one that lets curl through does not (that is a change to say out loud)",
      verdict(lambda a: a in BAD), 1)

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
