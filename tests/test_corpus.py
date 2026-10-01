#!/usr/bin/env python3
"""
The corpus of ordinary traffic is what stands between an automatic rule update and
users being refused, so it is held to what it says it is.

`BENIGN` is the traffic the nginx backend checks every candidate rule against: a
rule that matches one of these is not emitted. The more honestly it looks like a
site's traffic, the fewer false positives reach a server, and the more careful it
has to be about what goes in. This checks the properties that can be checked:

  * every entry says what it is and why it is there, in one line, and belongs to
    one category of what a false positive looks like;
  * every category has entries, enough to mean something;
  * an entry is in the form it goes on the wire, and the parts agree;
  * nothing is in it twice, and nothing that is an attack is in it: the corpus of
    attacks and this one do not overlap, and a few unmistakable payloads are not
    in either by mistake;
  * nothing real: hosts are `example.*`, addresses are in the documentation ranges,
    people are `@example.com`.

What cannot be checked is whether a request is ordinary. That is a judgement, made
when an entry is added and written down in its `why`.

Usage:
    python3 tests/test_corpus.py
"""

import ipaddress
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from patterns import corpus  # noqa: E402

failures = 0
checks = 0


def check(description, actual, expected=True):
    global failures, checks
    checks += 1
    if actual != expected:
        failures += 1
        print(f"  FAIL  {description}")
        print(f"        expected {expected!r}, got {actual!r}")


BENIGN, ATTACKS = corpus.BENIGN, corpus.ATTACKS
FIELDS = ("name", "path", "args", "request_uri", "user_agent", "host", "referer",
          "content_type", "method", "body")
MINIMUM_PER_CATEGORY = 3

print("\nwhat each entry says")
check("every entry has every field, and says what and why",
      [e["name"] for e in BENIGN if any(f not in e for f in FIELDS + ("category", "why"))], [])
check("every entry is in a category that exists",
      sorted({e["category"] for e in BENIGN} - set(corpus.CATEGORIES)), [])
check("every category has entries in it", sorted(set(corpus.CATEGORIES) - {e["category"] for e in BENIGN}), [])
counts = Counter(e["category"] for e in BENIGN)
check(f"and at least {MINIMUM_PER_CATEGORY} each",
      sorted(c for c, n in counts.items() if n < MINIMUM_PER_CATEGORY), [])
check("why is one line that says something",
      [e["name"] for e in BENIGN if not (10 <= len(e["why"]) <= 110) or "\n" in e["why"]], [])
check("a category is described", [c for c, text in corpus.CATEGORIES.items() if len(text) < 20], [])
check("a name is used once", [n for n, c in Counter(e["name"] for e in BENIGN).items() if c > 1], [])
check("an attack and an ordinary request do not share a name",
      sorted({e["name"] for e in BENIGN} & {e["name"] for e in ATTACKS}), [])

print("the form of a request")
check("the path starts with a slash", [e["name"] for e in BENIGN if not e["path"].startswith("/")], [])
check("request_uri is the path and the query",
      [e["name"] for e in BENIGN
       if e["request_uri"] != (e["path"] + ("?" + e["args"] if e["args"] else ""))], [])
check("what goes on the wire has no space, control or non-ascii character in it",
      [e["name"] for e in BENIGN if not re.fullmatch(r"[\x21-\x7e]+", e["request_uri"])], [])
check("a method is one of the ordinary ones",
      sorted({e["method"] for e in BENIGN} - {"GET", "POST", "PUT", "DELETE", "PATCH"}), [])
check("a body belongs to a request that can carry one",
      [e["name"] for e in BENIGN if e["body"] and e["method"] == "GET"], [])
check("and says what it is", [e["name"] for e in BENIGN if e["body"] and not e["content_type"]], [])
check("nothing is in it twice",
      [k for k, c in Counter(
          tuple(e[f] for f in ("request_uri", "user_agent", "host", "referer", "content_type",
                               "method", "body")) for e in BENIGN).items() if c > 1], [])

print("nothing that is an attack")
WHOLE = ("request_uri", "user_agent", "host", "referer", "content_type", "method", "body")
check("no request is in both",
      sorted({tuple(e[f] for f in WHOLE) for e in BENIGN} & {tuple(e[f] for f in WHOLE) for e in ATTACKS}),
      [])
# A few payloads nobody would call ordinary. A tripwire against a paste into the
# wrong list, not a detector: the real test is the judgement in `why`.
HOSTILE = re.compile(
    r"<script|javascript:|union(?:\+|%20|\s)+select|\.\./|%2e%2e|jndi:|/etc/passwd|"
    r"\bor\b(?:\+|%20|\s)+1(?:\+|%20|\s)*=(?:\+|%20|\s)*1|sleep\(|/\.env|\.git/", re.I)
check("none of the unmistakable ones",
      [e["name"] for e in BENIGN
       if HOSTILE.search(e["request_uri"] + " " + e["body"] + " " + e["user_agent"])], [])

print("nothing real")
check("hosts are example.*",
      [e["name"] for e in BENIGN
       if not re.fullmatch(r"(?:[a-z0-9-]+\.)*example\.(?:com|org|net)(?::\d+)?", e["host"])], [])
everything = [" ".join(str(e[f]) for f in FIELDS) for e in BENIGN]
emails = [m for text in everything for m in re.findall(r"[\w.+-]+(?:@|%40)([a-z][\w-]*(?:\.[\w-]+)+)", text)]
check("people are @example.com", sorted({d for d in emails if not d.startswith("example.")}), [])
# Everything a request says about where it is going must be reserved: example
# domains, the .invalid and .test top levels, or a documentation address. The
# crawlers' own pages are the exception, because they are what the crawler sends.
EXEMPT = ("google.com", "bing.com", "slack.com", "facebook.com", "ycombinator.com", "gmail",
          "github", "jwt.io", "example.", "duckduckgo.com", "baidu.com", "yandex.com", "apple.com",
          "discordapp.com", "linkedin.com", "pingdom.com", "uptimerobot.com")
urls = [u for text in everything for u in re.findall(r"https?(?:://|%3A%2F%2F)([\w.-]+)", text)]
check("urls point at example domains, or at a crawler's own page",
      sorted({u for u in urls if not any(x in u for x in EXEMPT)}), [])
documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                   "127.0.0.0/8", "2001:db8::/32")]
addresses = [a for text in everything for a in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
             if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", a) or all(int(p) <= 255 for p in a.split("."))]
check("an address is in a documentation range",
      sorted({a for a in addresses if not any(ipaddress.ip_address(a) in n for n in documentation)
              and not re.search(r"(?:Chrome|Safari|Firefox|Gecko|AppleWebKit|Edg|Version|rv|OS|Go-http-client|"
                                r"python-requests|curl|Prometheus|orders-service|bingbot|Googlebot)[/ :]"
                                + re.escape(a), " ".join(everything))}), [])

print("the Content-Types a client sends")
types = [e["content_type"] for e in BENIGN if e["content_type"]]
check("some carry a charset, with a space and without: a rule that reads `charset=` as a sign of something "
      "refused every one of them in all four targets, and nothing in the corpus said so",
      sum("charset=" in t for t in types) >= 4 and any(";charset=" in t for t in types)
      and any("; charset=" in t for t in types), True)
check("one is a multipart form with a boundary", any(t.startswith("multipart/form-data; boundary=") for t in types), True)
check("one is a vendor media type with a suffix and a parameter", any("+json" in t and ";" in t for t in types), True)

print("what the README says")
readme = (REPO_ROOT / "README.md").read_text()
check("the README counts the ordinary requests it is measured against",
      sorted({int(n) for n in re.findall(r"(\d+)\s+ordinary requests in", readme)
              + re.findall(r"refused \| \*\*0 of (\d+)\*\*", readme)}), [len(BENIGN)])

print(f"\n{checks - failures}/{checks} checks passed")
print(f"{len(BENIGN)} ordinary requests in {len(counts)} categories: "
      + ", ".join(f"{c} {n}" for c, n in sorted(counts.items())))
if failures:
    print(f"{failures} failing")
    sys.exit(1)
