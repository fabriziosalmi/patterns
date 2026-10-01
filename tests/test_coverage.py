#!/usr/bin/env python3
"""
The coverage matrix, and whether it tells the truth about the files.

A matrix that says "nginx writes 174 rules" is only worth something if nginx's
output has 174 rules in it. The backends decide what to drop where they drop it
and record that there; what a written rule loses is worked out here from what
each backend declares it can express. Both could drift from the output, so this
holds them to it:

  * verdicts on rules made for the purpose, one for each status, each loss and
    each way of being dropped;
  * the number of rules a backend says it wrote is the number in its files, for
    all four;
  * what a backend declares (the `~*` prefix for a lowercase transformation, the
    `t:none` Apache writes, the `-i` HAProxy writes) is what its output does;
  * the locations the matrix relates to a rule's variables agree with the
    location the IR folds them to;
  * the dialect check: `build` refuses to write a regular expression the
    target's engine does not compile;
  * the table in README.md and docs/coverage.md is what the data says, and the
    README states no count of rules that the table could disagree with (the
    nightly build regenerates the table, and prose is not regenerated).

The committed files are built with Python 3.11 or later, and the dialect check
needs it: below that the checks that depend on it are skipped, and say so.

Usage:
    python3 tests/test_coverage.py
"""

import json
import logging
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from patterns import backends, cli, coverage, dialects, ir  # noqa: E402
from patterns.backends import Backend, Capabilities, Compiled, Decision, Target  # noqa: E402

logging.disable(logging.CRITICAL)

failures = 0
checks = 0
MODERN = sys.version_info >= (3, 11)


def check(description, actual, expected=True):
    global failures, checks
    checks += 1
    if actual != expected:
        failures += 1
        print(f"  FAIL  {description}")
        print(f"        expected {expected!r}, got {actual!r}")


if not MODERN:
    print(f"\nPython {sys.version_info[0]}.{sys.version_info[1]}: the dialect check and the committed "
          "output need 3.11 or later, so the checks that use them are skipped")


def var(name, selector=None, count=False, excluded=False):
    return {"name": name, "selector": selector, "count": count, "excluded": excluded}


def rule(rule_id="1", variables=None, operator=None, transformations=(), chain=None,
         directive="SecRule", **extra):
    """An IR record with the fields the matrix reads."""
    record = {
        "id": rule_id, "directive": directive, "category": "TEST", "phase": 2,
        "variables": variables if variables is not None else [var("QUERY_STRING")],
        "operator": operator if operator is not None else
        {"name": "rx", "negated": False, "argument": "zqxjk"},
        "transformations": list(transformations), "action": "block", "severity": "high",
        "crs_severity": "CRITICAL", "score": None, "chain": chain, "target_rule_id": None,
        "pattern": "@rx zqxjk", "location": "Query-String",
    }
    if directive != "SecRule":
        record.update(operator=None, target_rule_id="2", id="no_id")
    record.update(extra)
    return record


class Probe(Backend):
    """A backend that writes exactly what it is told to, to test the verdicts."""

    name = "probe"
    title = "Probe"
    capabilities = Capabilities(
        dialect="pcre",
        operators=frozenset({"rx"}),
        transformations=frozenset({"lowercase"}),
        case_insensitive=False,
        locations={
            "query-string": Target("$args", "the query string only", frozenset({"ARGS"})),
            "user-agent": Target("$ua"),
        },
        faithful=lambda argument: argument.replace("(?i)", ""),
    )

    def compile(self, ir_):
        return Compiled({}, [])


PROBE = Probe()


def verdict(record, location="query-string", pattern="zqxjk", links=None):
    """The verdict for one written record."""
    decision = Decision(0, True, location=location, pattern=pattern)
    losses = coverage._assess_written(PROBE, record, decision, links or {})
    status = ("unsound" if any(l.unsound for l in losses)
              else "approximate" if losses else "full")
    return status, sorted({l.kind for l in losses})


print("\nthe verdicts")
check("a rule that keeps everything is full", verdict(rule()), ("full", []))
check("a variable the target sees only part of is approximate",
      verdict(rule(variables=[var("ARGS")])), ("approximate", ["variables"]))
check("one it sees whole is full",
      verdict(rule(variables=[var("QUERY_STRING")])), ("full", []))
check("a transformation the target does not apply is approximate",
      verdict(rule(transformations=["urlDecodeUni", "urlDecodeUni", "htmlEntityDecode"])),
      ("approximate", ["transformations"]))
check("one it reproduces is not a loss",
      verdict(rule(transformations=["lowercase"])), ("full", []))
check("a variable the target does not match is approximate",
      verdict(rule(variables=[var("QUERY_STRING"), var("REQUEST_COOKIES")])),
      ("approximate", ["variables"]))
check("an exclusion that is not applied is approximate",
      verdict(rule(variables=[var("QUERY_STRING"), var("ARGS", "id", excluded=True)])),
      ("approximate", ["variables"]))
check("a location that is none of the rule's variables is unsound",
      verdict(rule(variables=[var("REQUEST_COOKIES")]), location="query-string"),
      ("unsound", ["variables"]))
check("a counted variable is unsound",
      verdict(rule(variables=[var("QUERY_STRING", count=True)])), ("unsound", ["variables"]))
check("an operator the target is not given is unsound",
      verdict(rule(operator={"name": "lt", "negated": False, "argument": "1"})),
      ("unsound", ["operator"]))
check("a negated one is too",
      verdict(rule(operator={"name": "rx", "negated": True, "argument": "zqxjk"})),
      ("unsound", ["operator"]))
check("an expression written differently is unsound",
      verdict(rule(), pattern="a\\.b"), ("unsound", ["regex"]))
check("the difference the backend says it makes on purpose is not",
      verdict(rule(operator={"name": "rx", "negated": False, "argument": "(?i)zqxjk"}),
              pattern="zqxjk"), ("approximate", ["flags"]))
check("the head of a chain is approximate",
      verdict(rule("7", chain={"role": "head", "head": "7", "position": 0}), links={"7": 2}),
      ("approximate", ["chain"]))
check("and says how many conditions must all match",
      [l.detail for l in coverage._assess_written(
          PROBE, rule("7", chain={"role": "head", "head": "7", "position": 0}),
          Decision(0, True, location="query-string", pattern="zqxjk"), {"7": 2})
       if l.kind == "chain"], ["the first of 3 conditions that must all match"])
check("a link of a chain written alone is unsound",
      verdict(rule("no_id", chain={"role": "link", "head": "7", "position": 1})),
      ("unsound", ["chain"]))
check("something that is not a rule, written, is unsound",
      verdict(rule(directive="SecRuleUpdateTargetById")), ("unsound", ["not-a-rule"]))


def dropped(record, reason="operator-unsupported", detail="@lt"):
    ir_ = ir.IR(rules=[record])
    [v] = coverage.assess(PROBE, ir_, Compiled({}, [Decision(0, False, reason, detail)]))
    return v.status, v.reason, v.detail


check("a dropped rule keeps the backend's reason",
      dropped(rule()), ("dropped", "operator-unsupported", "@lt"))
check("but a directive that is not a rule is dropped for being one, whatever the backend said",
      dropped(rule(directive="SecRuleUpdateTargetById"), "location-unsupported", "unknown"),
      ("dropped", "not-a-rule", "SecRuleUpdateTargetById 2"))

print("the real IR, every backend")
R = ir.load(REPO_ROOT / "owasp_rules.json")
compiled = {n: backends.get(n).compile(R) for n in backends.names()}
for name, c in compiled.items():
    check(f"{name}: one decision per rule, in order",
          [d.index for d in c.decisions], list(range(len(R.rules))))
    check(f"{name}: every dropped rule has a reason the matrix knows",
          sorted({d.reason for d in c.decisions if not d.emitted} - set(coverage.REASONS)), [])
    check(f"{name}: nothing is both emitted and given a reason",
          [d.index for d in c.decisions if d.emitted and d.reason], [])
    verdicts = coverage.assess(backends.get(name), R, c)
    check(f"{name}: the four statuses account for every rule",
          sum(1 for v in verdicts if v.status in coverage.STATUSES), len(R.rules))
    check(f"{name}: written is what is not dropped",
          sum(1 for v in verdicts if v.status != "dropped"), sum(d.emitted for d in c.decisions))

print("the matrix counts what the files hold")


def written(name):
    return sum(d.emitted for d in compiled[name].decisions)


nginx = compiled["nginx"].files["waf_maps.conf"]
check("nginx: map keys in waf_maps.conf: a rule is one, or a few for a list of phrases",
      len(re.findall(r'^  "~', nginx, re.M)), sum(d.keys for d in compiled["nginx"].decisions if d.emitted))
check("apache: SecRule lines in the category files",
      sum(len(re.findall(r"^SecRule ", text, re.M)) for text in compiled["apache"].files.values()),
      written("apache"))
check("haproxy: patterns in the pattern files, and an acl for each phrase list a rule reads",
      sum(len([l for l in text.splitlines() if l and not l.startswith("#")])
          for name, text in compiled["haproxy"].files.items() if name.endswith(".acl"))
      + len(re.findall(r" -m sub -i -f ", compiled["haproxy"].files["waf.cfg"])),
      written("haproxy"))
check("traefik: expressions in middleware.toml",
      len(re.findall(r"^      ['\"]", compiled["traefik"].files["middleware.toml"], re.M)),
      written("traefik"))

print("what a backend declares is what it writes")


def built(name, record):
    """The files a backend writes for one rule."""
    return backends.get(name).compile(ir.IR(rules=[record])).files


lowered = rule(transformations=["lowercase"], location="Query-String")
check("nginx declares lowercase: a rule that declares it is matched with ~*",
      '"~*zqxjk"' in built("nginx", lowered)["waf_maps.conf"], True)
check("nginx: and one that does not is matched with ~",
      '"~zqxjk"' in built("nginx", rule())["waf_maps.conf"], True)
check("apache declares lowercase: a rule that declares it is written with t:lowercase",
      "t:none,t:lowercase," in built("apache", lowered)["test.conf"], True)
check("apache: and one that does not is written with t:none only",
      "t:none," in built("apache", rule())["test.conf"] and "t:lowercase" not in built("apache", rule())["test.conf"],
      True)
check("haproxy declares lowercase: a rule that declares it is matched on the lowered value",
      "query,lower -m reg" in built("haproxy", lowered)["waf.cfg"], True)
check("haproxy: and one that does not is matched as it is",
      "acl waf_query_string query -m reg" in built("haproxy", rule())["waf.cfg"], True)
insensitive = rule(operator={"name": "rx", "negated": False, "argument": "(?i)zqxjk"},
                   pattern="@rx (?i)zqxjk", location="User-Agent")
check("traefik declares it is: (?i) is kept, which Go honours",
      "'(?i)zqxjk'" in built("traefik", insensitive)["middleware.toml"], True)
# What the backend writes is a decision at each step, and each step is shown to refuse:
# a User-Agent plugin writes only what refuses and only what is a regular expression its
# engine compiles, and nothing an ordinary request matches.
check("traefik writes only rules that refuse: severity high",
      sorted({R.rules[d.index]["severity"] for d in compiled["traefik"].decisions if d.emitted}), ["high"])
check("and only @rx, not negated",
      sorted({(R.rules[d.index]["operator"]["name"], R.rules[d.index]["operator"]["negated"])
              for d in compiled["traefik"].decisions if d.emitted}), [("rx", False)])
UA = {"location": "User-Agent"}


def traefik_decision(argument, **extra):
    """What the Traefik backend does with one rule made for the purpose."""
    record = rule(operator={"name": "rx", "negated": False, "argument": argument},
                  pattern="@rx " + argument, **UA, **extra)
    [d] = backends.get("traefik").compile(ir.IR(rules=[record])).decisions
    return (d.emitted, d.reason)


check("a rule below `high` is not written, because a plugin that refuses cannot only record",
      traefik_decision("zqxjk", severity="medium"), (False, "severity-below-blocking"))
check("an expression Go's RE2 does not have is not written: it would stop the middleware",
      traefik_decision("zq(?!xjk)"), (False, "invalid-regex"))
check("one an ordinary client matches is not written",
      traefik_decision("Googlebot"), (False, "matches-benign-traffic"))
check("one that is fine is", traefik_decision("zqxjk"), (True, None))
check("a negated operator is not written as the expression it negates",
      backends.get("traefik").compile(ir.IR(rules=[rule(
          operator={"name": "rx", "negated": True, "argument": "zqxjk"}, pattern="!@rx zqxjk", **UA)])
      ).decisions[0].reason, "operator-unsupported")
print("a chain is not written, in any target")
for name in backends.names():
    check(f"{name}: no record of a chain is written",
          [R.rules[d.index]["id"] for d in compiled[name].decisions
           if d.emitted and R.rules[d.index]["chain"]], [])
    check(f"{name}: and every one is dropped for it, so the matrix says why",
          sorted({d.reason for d in compiled[name].decisions if R.rules[d.index]["chain"]}), ["chain-unsupported"])
HEAD = {"role": "head", "head": "7", "position": 0}
LINK = {"role": "link", "head": "7", "position": 1}
for name, location in (("nginx", "Content-Type"), ("apache", "CONTENT-TYPE"), ("haproxy", "CONTENT-TYPE"),
                       ("traefik", "User-Agent")):
    for role, chain in (("the head", HEAD), ("a link", LINK)):
        one = backends.get(name).compile(ir.IR(rules=[rule(
            "7" if chain is HEAD else "no_id", chain=chain, location=location,
            operator={"name": "rx", "negated": False, "argument": "zqxjk"}, pattern="@rx zqxjk",
            **({} if chain is HEAD else {"action": None, "severity": "medium"}))])).decisions[0]
        check(f"{name}: {role} of a chain is not written, whatever it matches",
              (one.emitted, one.reason, one.detail), (False, "chain-unsupported", f"{chain['role']} of 7"))
    alone = backends.get(name).compile(ir.IR(rules=[rule(
        location=location, operator={"name": "rx", "negated": False, "argument": "zqxjk"},
        pattern="@rx zqxjk")])).decisions[0]
    check(f"{name}: and the same rule outside a chain is", alone.emitted, True)

print("the order of the keys of a map")
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
real_maps = compiled["nginx"].files["waf_maps.conf"]
by_map = {}
current = None
for line in real_maps.splitlines():
    start = re.match(r"map (\S+) (\S+) \{", line)
    if start:
        current = start.group(2)
        by_map[current] = []
    elif current and re.match(r'  "~', line):
        by_map[current].append(SEVERITY_RANK[re.search(r'"(high|medium|low):[a-z_]+";$', line).group(1)])
check("in every map the high keys come before the medium ones and those before the low ones: nginx takes the "
      "first key that matches, and only a high one refuses",
      [m for m, ranks in by_map.items() if ranks != sorted(ranks)], [])
ordered = backends.get("nginx").compile(ir.IR(rules=[
    rule("1", severity="medium", pattern="@rx zqxjk", operator={"name": "rx", "negated": False, "argument": "zqxjk"}),
    rule("2", severity="high", pattern="@rx zqxjk.*attack",
         operator={"name": "rx", "negated": False, "argument": "zqxjk.*attack"})])).files["waf_maps.conf"]
check("a medium rule that comes first in CRS is written after the high one that comes second",
      ordered.index("high:test") < ordered.index("medium:test"), True)
check("and two of the same severity keep the order CRS has them in",
      (lambda text: text.index("zqxjkb") < text.index("zqxjka"))(backends.get("nginx").compile(ir.IR(rules=[
          rule("1", pattern="@rx zqxjkb", operator={"name": "rx", "negated": False, "argument": "zqxjkb"}),
          rule("2", pattern="@rx zqxjka", operator={"name": "rx", "negated": False, "argument": "zqxjka"})])
      ).files["waf_maps.conf"]), True)

print("what the nginx backend writes for a list of phrases")
from patterns.backends import nginx as nginx_backend  # noqa: E402
from patterns.corpus import nginx_uri  # noqa: E402

DATA = {"words.data": ["zqxjk-one", "zq.two", "ZQ three", "zq$four"]}


def nginx_decision(argument="zqxjk", name="rx", data=None, **extra):
    """What the nginx backend does with one rule made for the purpose. As in the IR, `pattern` is the operator again."""
    record = rule(operator={"name": name, "negated": False, "argument": argument},
                  pattern=f"@{name} {argument}", **extra)
    one = backends.get("nginx").compile(ir.IR(rules=[record], data_files=data or {}))
    return one.decisions[0], one.files["waf_maps.conf"]


pm_inline, maps = nginx_decision("zqxjk-one zq.two", "pm")
check("@pm is written, a phrase list with each phrase escaped, case ignored: `~*`",
      (pm_inline.emitted, '"~*(?:zqxjk\\\\-one|zq\\\\.two)"' in maps), (True, True))
pm_file, maps = nginx_decision("words.data", "pmFromFile", DATA)
check("so is @pmFromFile, from the list the IR carries",
      (pm_file.emitted, pm_file.keys, '"~*(?:zqxjk\\\\-one|zq\\\\.two|ZQ\\\\ three|zq\\\\$four)"' in maps), (True, 1, True))
check("a phrase list the IR does not have is not guessed at",
      (nginx_decision("gone.data", "pmFromFile", DATA)[0].emitted,
       nginx_decision("gone.data", "pmFromFile", DATA)[0].reason,
       nginx_decision("gone.data", "pmFromFile", DATA)[0].detail),
      (False, "operator-unsupported", "@pmFromFile (the IR has no such phrase list)"))
check("the name of the list is read with its blank space trimmed",
      nginx_decision("words.data ", "pmFromFile", DATA)[0].emitted, True)
check("an empty one is not written", nginx_decision("e.data", "pmFromFile", {"e.data": []})[0].reason, "empty-pattern")
negated = backends.get("nginx").compile(ir.IR(rules=[rule(
    operator={"name": "pm", "negated": True, "argument": "zqxjk"}, pattern="!@pm zqxjk")])).decisions[0]
check("a negated one is not: a map key says what matches", (negated.emitted, negated.reason), (False, "operator-unsupported"))
check("a phrase list is checked against ordinary traffic, and the rule is written whole or not at all",
      nginx_decision("zqxjk googlebot", "pm", location="User-Agent")[0].reason, "matches-benign-traffic")
late = [f"zq-filler-{i:04d}-" + "y" * 30 for i in range(400)] + ["googlebot"]
check("the check covers every key: a phrase that matches ordinary traffic in the last one keeps the rule out",
      (len(nginx_backend.phrase_alternations(late)) > 1,
       nginx_decision(" ".join(late), "pm", location="User-Agent")[0].reason), (True, "matches-benign-traffic"))
check("the severity and the category are the rule's, as for a regular expression",
      '"high:test"' in nginx_decision("zqxjk", "pm")[1], True)

many = [f"phrase-{i:05d}-" + "x" * 40 for i in range(2000)]
chunks = nginx_backend.phrase_alternations(many)
check("a long list is packed into as few keys as fit: more than one, and fewer than a key each",
      1 < len(chunks) < 100, True)
check("each key is within what nginx takes as one parameter, quotes and ~* included",
      max(len(nginx_backend._escape_for_config('"~*' + c + '"').encode()) for c in chunks) <= nginx_backend.NGINX_MAX_PARAMETER,
      True)
check("and none of the phrases is lost, or repeated",
      sorted(p for c in chunks for p in re.split(r"(?<!\\)\|", c[3:-1])), sorted(re.escape(p) for p in many))
check("a phrase that is there twice is there once", nginx_backend.phrase_alternations(["a", "b", "a"]), ["(?:a|b)"])
check("no phrases, no keys", nginx_backend.phrase_alternations([]), [])
try:
    nginx_backend.phrase_alternations(["x" * 5000])
    too_long = False
except ValueError:
    too_long = True
check("a phrase that cannot fit in a key alone is refused, not cut", too_long, True)
check("a rule whose list does not fit is not written, and says so",
      nginx_decision("big.data", "pmFromFile", {"big.data": ["x" * 5000]})[0].reason, "parameter-too-long")

print("what nginx puts in $uri")
check("it is the path decoded: `%2e` is a dot, `%2F` a slash",
      [nginx_uri(p) for p in ("/%2egit/config", "/uploads/c99%2Ephp", "/etc%2Fpasswd")],
      ["/.git/config", "/uploads/c99.php", "/etc/passwd"])
check("and normalised: `.`, `..` and `//`", [nginx_uri(p) for p in ("/a/./b/../c", "//a//b/", "/../x")],
      ["/a/c", "/a/b/", "/x"])
check("a rule on the request path is written on $uri",
      "map $uri $waf_uri" in nginx_decision("^/zq", location="Request-Filename")[1], True)
check("and checked against the path as nginx holds it: `%20` and `%28` are a space and a bracket there",
      nginx_decision(r"Report \(2026\)", location="Request-Filename")[0].reason, "matches-benign-traffic")
check("a rule on the method is written on $request_method, and checked against it",
      (nginx_decision("^ZQXJK$", location="Request-Method")[0].emitted,
       nginx_decision("^GET$", location="Request-Method")[0].reason), (True, "matches-benign-traffic"))

print("what the Apache backend writes")
ID_OFFSET = 9_000_000
apache_records = [(d, R.rules[d.index]) for d in compiled["apache"].decisions if d.emitted]
every_file = "".join(text for name, text in compiled["apache"].files.items() if name.endswith(".conf"))
check("apache writes only @rx, @pm and @pmFromFile, not negated",
      sorted({(r["operator"]["name"], r["operator"]["negated"]) for _, r in apache_records}),
      [("pm", False), ("pmFromFile", False), ("rx", False)])
check("and nothing that is not a rule",
      sorted({r["directive"] for _, r in apache_records}), ["SecRule"])
check("every rule has an id of its own, ModSecurity refuses a file with two the same (#80)",
      [i for i, n in __import__("collections").Counter(re.findall(r"[ ,\"]id:(\d+)", every_file)).items() if n > 1], [])
check("and it is the CRS id, 9000000 and more, which no installed CRS has",
      sorted(int(i) - ID_OFFSET for i in re.findall(r"[ ,\"]id:(\d+)", every_file)),
      sorted(int(r["id"]) for _, r in apache_records))
check("every argument is written as CRS wrote it, between the quotes, under the operator CRS named",
      [r["id"] for _, r in apache_records
       if f'"@{r["operator"]["name"]} {r["operator"]["argument"]}"' not in every_file], [])
check("a rule that refuses is `high`, and the rest record",
      sorted({(r["severity"] == "high") == ("deny,status:403" in line)
              for _, r in apache_records for line in every_file.splitlines()
              if f'id:{ID_OFFSET + int(r["id"])},' in line}),
      [True])
check("and both kinds are written, so the check above says something",
      sorted({r["severity"] == "high" for _, r in apache_records}), [False, True])
check("nothing sets the engine: that is the deployment's",
      re.findall(r"^\s*SecRuleEngine", every_file, re.M), [])
check("no variable is one that is not ModSecurity's",
      sorted(set(re.findall(r"^SecRule (\S+) ", every_file, re.M))),
      sorted(["ARGS", "REQUEST_FILENAME", "REQUEST_HEADERS:Content-Type", "REQUEST_HEADERS:Host",
              "REQUEST_HEADERS:Referer", "REQUEST_HEADERS:User-Agent", "REQUEST_URI"]))


def apache_decision(argument="zqxjk", name="rx", negated=False, **extra):
    """What the Apache backend does with one rule made for the purpose."""
    record = rule(operator={"name": name, "negated": negated, "argument": argument}, **extra)
    compiled_one = backends.get("apache").compile(ir.IR(rules=[record]))
    return (compiled_one.decisions[0].emitted, compiled_one.decisions[0].reason), compiled_one.files


check("apache: a rule that is fine is written", apache_decision()[0], (True, None))
check("a negated operator is not", apache_decision(negated=True)[0], (False, "operator-unsupported"))
check("nor one that is not a regular expression", apache_decision("1", "lt")[0], (False, "operator-unsupported"))
check("nor a record that is not a rule", apache_decision(directive="SecRuleUpdateTargetById")[0],
      (False, "not-a-rule"))
check("and it says what the record is, not that it has no id",
      backends.get("apache").compile(ir.IR(rules=[rule(directive="SecRuleUpdateTargetById")])).decisions[0].detail,
      "SecRuleUpdateTargetById 2")
check("nor an expression PCRE does not compile", apache_decision("zq(xjk")[0], (False, "invalid-regex"))
check("nor one on a variable it cannot check against ordinary traffic",
      apache_decision(location="Cookie")[0], (False, "location-unsupported"))
check("nor one that does not refuse", apache_decision(action="pass")[0], (False, "not-blocking"))
check("nor one an ordinary request matches", apache_decision("Googlebot", location="User-Agent")[0],
      (False, "matches-benign-traffic"))
check("ARGS is decoded before a rule is checked against ordinary traffic: `gr%C3%BC%C3%9Fe` is `grüße` to ModSecurity",
      apache_decision("grüße", location="Query-String")[0], (False, "matches-benign-traffic"))
check("an argument is read the way Apache reads it, `\\\\(` being `\\(`, before it is checked",
      apache_decision(r"\\(KHTML", location="User-Agent")[0], (False, "matches-benign-traffic"))
check("a rule that declares t:lowercase is checked on lower-case input, as ModSecurity will run it",
      apache_decision("googlebot", location="User-Agent", transformations=["lowercase"])[0],
      (False, "matches-benign-traffic"))
check("and one that does not is not: `googlebot` does not match `Googlebot` without it",
      apache_decision("googlebot", location="User-Agent")[0], (True, None))
check("but a lookbehind is PCRE, and is written", apache_decision("(?<!no)zqxjk")[0], (True, None))
check("an id from the CRS id", 'id:9000007,' in apache_decision(rule_id="7")[1]["test.conf"], True)
check("and phase and severity from the rule",
      "phase:1," in apache_decision(phase=1)[1]["test.conf"]
      and "severity:'CRITICAL'" in apache_decision()[1]["test.conf"], True)
check("a rule below high records and does not refuse",
      "pass,log" in apache_decision(severity="medium")[1]["test.conf"]
      and "deny" not in apache_decision(severity="medium")[1]["test.conf"], True)
check("an argument with quotes and backslashes is written as it was read",
      '"@rx ^say \\"hi\\" \\\\ \\d$"' in apache_decision(r'^say \"hi\" \\ \d$')[1]["test.conf"], True)
check("ARGS is checked as ModSecurity holds it, decoded: `%3Cb%3E` is `<b>` there",
      __import__("patterns.corpus", fromlist=["x"]).arguments(
          {"args": "q=%3Cb%3E+x&z=", "body": "", "content_type": ""}), ["<b> x", ""])
check("and a form body is part of it, and a JSON one is not",
      __import__("patterns.corpus", fromlist=["x"]).arguments(
          {"args": "", "body": "a=1&b=%26", "content_type": "application/x-www-form-urlencoded"}), ["1", "&"])
check("a JSON body is checked as if the deployment parses it: a value for each leaf",
      __import__("patterns.corpus", fromlist=["x"]).arguments(
          {"args": "", "body": '{"a":"x","b":[1,{"c":null}]}', "content_type": "application/json"}), ["x", "1"])
check("and one that is not JSON is not an error",
      __import__("patterns.corpus", fromlist=["x"]).arguments(
          {"args": "", "body": "{not json", "content_type": "application/json"}), [])
from patterns.backends._common import modsecurity_quote, modsecurity_unquote  # noqa: E402
check("quoting and reading a quoted argument are inverses",
      [v for v in (r"a\b", 'say "hi"', r"\d+\.\d", r'\"', "", "\\\\\"") if modsecurity_unquote(modsecurity_quote(v)) != v], [])
check("and what is written for a backslash is two, as Apache reads two as one",
      modsecurity_quote("a\\b"), "a\\\\b")

print("what the Apache backend writes for a list of phrases")


def apache_phrases(argument, name="pmFromFile", data=None, negated=False, **extra):
    """What the Apache backend does with one phrase rule made for the purpose, and the files it writes."""
    record = rule(operator={"name": name, "negated": negated, "argument": argument}, **extra)
    one = backends.get("apache").compile(ir.IR(rules=[record], data_files=data or {}))
    d = one.decisions[0]
    return (d.emitted, d.reason, d.detail), one.files


WORDS = {"words.data": ["zqxjk-one", "zq.two", "ZQ three"]}
inline, files_ = apache_phrases("zqxjk-one zq.two", "pm")
check("apache: @pm is written as CRS wrote it, with its phrases, and needs no file",
      (inline[0], '"@pm zqxjk-one zq.two"' in files_["test.conf"], sorted(files_)), (True, True, ["test.conf"]))
listed, files_ = apache_phrases("words.data", data=WORDS)
check("@pmFromFile is written as it was, and names a file that is shipped next to the rules",
      (listed[0], '"@pmFromFile words.data"' in files_["test.conf"], sorted(files_)), (True, True, ["test.conf", "words.data"]))
check("the file is a phrase to a line after a comment, which ModSecurity skips, in the order CRS has them",
      [l for l in files_["words.data"].splitlines() if l and not l.startswith("#")], WORDS["words.data"])
check("a phrase list the IR does not have is not guessed at",
      apache_phrases("gone.data", data=WORDS)[0], (False, "operator-unsupported", "@pmFromFile (the IR has no such phrase list)"))
check("an empty one is not written", apache_phrases("e.data", data={"e.data": []})[0][:2], (False, "empty-pattern"))
check("a negated one is not: it is not what a rule that refuses can say",
      apache_phrases("zqxjk", "pm", negated=True)[0][:2], (False, "operator-unsupported"))
check("one an ordinary request holds is not written, whatever the case: `Googlebot` in a User-Agent",
      apache_phrases("GOOGLEBOT zqxjk", "pm", location="User-Agent")[0][:2], (False, "matches-benign-traffic"))
late = [f"zq-filler-{i:04d}" for i in range(400)] + ["googlebot"]
check("and a phrase that is last in a long list keeps the whole rule out: it is written whole or not at all",
      apache_phrases("big.data", data={"big.data": late}, location="User-Agent")[0][:2], (False, "matches-benign-traffic"))
check("a phrase is looked for in ARGS as ModSecurity holds it, decoded: `gr%C3%BC%C3%9Fe` is `grüße`",
      apache_phrases("grüße zqxjk", "pm", location="Query-String")[0][:2], (False, "matches-benign-traffic"))
check("and in the path as ModSecurity holds it, raw (measured): `%20` is seen as `%20`, not as a space",
      apache_phrases("w.data", data={"w.data": ["my%20report"]}, location="Request-Filename")[0][:2],
      (False, "matches-benign-traffic"))
check("so a phrase only the decoded path would hold, `my report`, is written: it is not what ModSecurity sees",
      apache_phrases("w.data", data={"w.data": ["my report"]}, location="Request-Filename")[0][:2], (True, None))
check("only the phrase files of rules that are written are shipped",
      sorted(backends.get("apache").compile(ir.IR(rules=[
          rule("1", operator={"name": "pmFromFile", "negated": False, "argument": "words.data"}),
          rule("2", action="pass", operator={"name": "pmFromFile", "negated": False, "argument": "other.data"})],
          data_files={"words.data": ["zqxjk"], "other.data": ["zqxjl"]})).files), ["test.conf", "words.data"])
named = re.findall(r'@pmFromFile (\S+)"', every_file)
shipped = sorted(n for n in compiled["apache"].files if n.endswith(".data"))
check("every phrase file a written rule names is shipped, and every one shipped is named",
      (sorted(set(named) - set(shipped)), sorted(set(shipped) - set(named))), ([], []))
check("and holds the phrases CRS has in it, nothing more and nothing less",
      [n for n in shipped
       if [l for l in compiled["apache"].files[n].splitlines() if l and not l.startswith("#")] != R.data_files[n]], [])
check("no phrase file is read as configuration: the include is of *.conf",
      [n for n in compiled["apache"].files if not (n.endswith(".conf") or n.endswith(".data") or n == "README.md")], [])

print("what the Envoy backend writes")
import yaml  # noqa: E402
from patterns.backends import envoy as envoy_backend  # noqa: E402
from patterns.backends._common import yaml_string  # noqa: E402

envoy_files = compiled["envoy"].files
rbac = yaml.safe_load(envoy_files["waf-rbac.yaml"])
envoy_permissions = [m.get("header", m.get("url_path"))
                     for p in rbac[0]["typed_config"]["rules"]["policies"].values()
                     for m in p["permissions"][0]["or_rules"]["rules"]]
envoy_regexes = [m for m in envoy_permissions if "safe_regex" in (m.get("string_match") or m.get("path") or {})]
envoy_phrase_permissions = [m for m in envoy_permissions if m not in envoy_regexes]
check("the filter is YAML, one item of http_filters, a deny, of the type Envoy has",
      (len(rbac), rbac[0]["name"], rbac[0]["typed_config"]["rules"]["action"], rbac[0]["typed_config"]["@type"]),
      (1, "waf", "DENY", "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC"))
check("it holds what the matrix says was written: an expression is a permission, a phrase list is a comment and a "
      "permission for each phrase",
      len(envoy_regexes) + len(re.findall(r"^\s+# CRS \S+ \(\S+\): .*, \d+ phrases?$", envoy_files["waf-rbac.yaml"], re.M)),
      written("envoy"))
envoy_expected_phrases = sorted(
    p for d in compiled["envoy"].decisions if d.emitted and not d.pattern
    for p in backends._common.phrases_of(backends._common.operator_of(R.rules[d.index]), R.data_files))
check("every phrase of every list that is written is one `contains` that ignores case, and nothing else is",
      (sorted((m.get("string_match") or m["path"])["contains"] for m in envoy_phrase_permissions),
       {(m.get("string_match") or m["path"])["ignore_case"] for m in envoy_phrase_permissions}),
      (envoy_expected_phrases, {True}))
envoy_whole = [(m.get("string_match") or m["path"])["safe_regex"]["regex"] for m in envoy_regexes]
check("every expression is between two `.*` that are dot-all and nothing else is: Envoy matches the whole value",
      [r for r in envoy_whole if not (r.startswith("(?s:.*)") and r.endswith("(?s:.*)"))], [])
check("and each is an expression the rule has, with the case flag the rule asks for and no other change",
      sorted(set(r for r in envoy_whole
                 if not any(r in (envoy_backend.whole(d.pattern, False), envoy_backend.whole(d.pattern, True))
                            for d in compiled["envoy"].decisions if d.emitted))), [])
check("runtime.yaml raises the limit on the size of a compiled expression, which Envoy applies at 100",
      yaml.safe_load(envoy_files["runtime.yaml"]),
      {"layered_runtime": {"layers": [{"name": "waf", "static_layer": {"re2": {"max_program_size": {
          "error_level": envoy_backend.MAX_PROGRAM_SIZE, "warn_level": envoy_backend.MAX_PROGRAM_SIZE}}}}]}})

import re as _re  # noqa: E402
check("and not lower than what the largest expression of CRS needs, measured in Envoy (it needs 100 by default)",
      envoy_backend.MAX_PROGRAM_SIZE >= 10 * envoy_backend.MEASURED_PROGRAM_SIZE > 100, True)
check("the wrapper finds an expression anywhere in a value: `(?s:.*)` is how a match of the whole value is a search",
      (bool(_re.fullmatch(envoy_backend.whole("union"), "/a?q=union+select")),
       bool(_re.fullmatch("union", "/a?q=union+select"))), (True, False))
check("and keeps the meaning of the `.` of the rule: it does not match a line break, as in PCRE",
      (bool(_re.fullmatch(envoy_backend.whole("a.b"), "x a\nb y")), bool(_re.fullmatch(envoy_backend.whole("a.b"), "x a-b y"))),
      (False, True))
check("a rule that lowercases is matched with case ignored, as nginx writes `~*`",
      bool(_re.fullmatch(envoy_backend.whole("union", True), "/a?q=UNION+select")), True)
check("an anchor stays an anchor: `^a` finds a value that starts with it, not one that has it later",
      (bool(_re.fullmatch(envoy_backend.whole("^a"), "ab")), bool(_re.fullmatch(envoy_backend.whole("^a"), "ba"))),
      (True, False))


def envoy_decision(argument="zqxjk", name="rx", negated=False, **extra):
    """What the Envoy backend does with one rule made for the purpose."""
    record = rule(operator={"name": name, "negated": negated, "argument": argument},
                  pattern=("!" if negated else "") + f"@{name} {argument}", **extra)
    one = backends.get("envoy").compile(ir.IR(rules=[record]))
    return (one.decisions[0].emitted, one.decisions[0].reason), one.files["waf-rbac.yaml"]


check("envoy: a rule that is fine is written", envoy_decision()[0], (True, None))
check("a negated operator is not", envoy_decision(negated=True)[0], (False, "operator-unsupported"))
check("nor one that is not a regular expression", envoy_decision("1", "lt")[0], (False, "operator-unsupported"))
check("nor a record that is not a rule", envoy_decision(directive="SecRuleUpdateTargetById")[0], (False, "not-a-rule"))
check("nor an empty pattern", envoy_decision("")[0], (False, "empty-pattern"))
check("nor an expression RE2 does not have: a lookahead", envoy_decision("zq(?=xjk)")[0], (False, "invalid-regex"))
check("nor a line break in one", envoy_decision("zq\nxjk")[0], (False, "invalid-regex"))
check("nor one on a component Envoy has no matcher for", envoy_decision(location="Cookie")[0],
      (False, "location-unsupported"))
check("nor one that does not refuse", envoy_decision(action="pass")[0], (False, "not-blocking"))
check("nor one below `high`: a deny cannot only record", envoy_decision(severity="medium")[0],
      (False, "severity-below-blocking"))
check("nor one an ordinary request matches", envoy_decision("Googlebot", location="User-Agent")[0],
      (False, "matches-benign-traffic"))
check("nor one that is part of a chain, the head or a link",
      (envoy_decision(chain={"role": "head", "head": "1", "position": 0})[0],
       envoy_decision(chain={"role": "link", "head": "1", "position": 1})[0]),
      ((False, "chain-unsupported"), (False, "chain-unsupported")))
check("a rule on the path alone is a url_path permission, and one on the query string is on :path",
      ("url_path:" in envoy_decision(location="Request-Filename")[1], "name: ':path'" in envoy_decision()[1]), (True, True))
check("a User-Agent rule is on that header and a Host rule on :authority",
      ("name: 'user-agent'" in envoy_decision(location="User-Agent")[1],
       "name: ':authority'" in envoy_decision(location="Host")[1]), (True, True))
check("an expression with quotes and backslashes is read back as it was written, by a YAML parser",
      yaml.safe_load(envoy_decision(r"say '\"hi\"' \\ \d")[1])[0]["typed_config"]["rules"]["policies"]["waf_path"]
      ["permissions"][0]["or_rules"]["rules"][0]["header"]["string_match"]["safe_regex"]["regex"],
      envoy_backend.whole(modsecurity_unquote(r"say '\"hi\"' \\ \d")))
awkward = [r"\d+\.\w", "it's", 'say "hi"', "back\\slash'quote", "#hash", ": colon", "- dash", " lead",
           "trail ", "tab\there", "line\nbreak", "\x00nul", "\x7fdel", "é日本語😀", "\u2028sep", "", "'", "yes", "null"]
check("YAML: every awkward string is read back as it was written",
      [v for v in awkward if yaml.safe_load("k: " + yaml_string(v))["k"] != v], [])
check("and one that can be single-quoted is, so a backslash is a backslash", yaml_string(r"\d+"), r"'\d+'")
check("an empty filter is still a filter that refuses nothing",
      yaml.safe_load(backends.get("envoy").compile(ir.IR(rules=[])).files["waf-rbac.yaml"])[0]
      ["typed_config"]["rules"]["policies"], {})

print("what the Envoy backend writes for a list of phrases")


def envoy_phrases(argument, name="pmFromFile", data=None, negated=False, **extra):
    """What the Envoy backend does with one phrase rule made for the purpose, and the permissions it writes."""
    record = rule(operator={"name": name, "negated": negated, "argument": argument}, **extra)
    one = backends.get("envoy").compile(ir.IR(rules=[record], data_files=data or {}))
    d = one.decisions[0]
    text = one.files["waf-rbac.yaml"]
    policies = yaml.safe_load(text)[0]["typed_config"]["rules"]["policies"]
    perms = [m for pol in policies.values() for m in pol["permissions"][0]["or_rules"]["rules"]]
    return (d.emitted, d.reason, d.detail), perms, text


def contains(name, phrase):
    return {"header": {"name": name, "string_match": {"contains": phrase, "ignore_case": True}}}


inline, perms, _ = envoy_phrases("zqxjk-one zq.two", "pm")
check("envoy: @pm is written as a permission for each phrase: the value contains it, case ignored",
      (inline[0], perms), (True, [contains(":path", "zqxjk-one"), contains(":path", "zq.two")]))
listed, perms, text = envoy_phrases("words.data", data=WORDS)
check("@pmFromFile is written the same way, from the list the IR carries, in the order CRS has them",
      (listed[0], perms), (True, [contains(":path", p) for p in WORDS["words.data"]]))
check("and the comment says which CRS rule and which list, and how many phrases",
      "# CRS 1 (test): words.data, 3 phrases\n" in text, True)
check("one phrase is `1 phrase`", "# CRS 1 (test): @pm, 1 phrase\n" in envoy_phrases("zqxjk", "pm")[2], True)
check("the path alone is matched with `url_path`, and a header by its name",
      (envoy_phrases("words.data", data=WORDS, location="Request-Filename")[1][0],
       envoy_phrases("words.data", data=WORDS, location="User-Agent")[1][0]),
      ({"url_path": {"path": {"contains": "zqxjk-one", "ignore_case": True}}}, contains("user-agent", "zqxjk-one")))
check("a phrase list the IR does not have is not guessed at",
      envoy_phrases("gone.data", data=WORDS)[0], (False, "operator-unsupported", "@pmFromFile (the IR has no such phrase list)"))
check("an empty one is not written", envoy_phrases("e.data", data={"e.data": []})[0][:2], (False, "empty-pattern"))
check("a negated one is not: it is not what a rule that refuses can say",
      envoy_phrases("zqxjk", "pm", negated=True)[0][:2], (False, "operator-unsupported"))
check("one an ordinary request holds is not written, whatever the case: `Googlebot` in a User-Agent",
      envoy_phrases("GOOGLEBOT zqxjk", "pm", location="User-Agent")[0][:2], (False, "matches-benign-traffic"))
check("and a phrase that is last in a long list keeps the whole rule out: it is written whole or not at all",
      envoy_phrases("big.data", data={"big.data": late}, location="User-Agent")[0][:2], (False, "matches-benign-traffic"))
check("Envoy decodes nothing, so a phrase is looked for in the request as it was sent: `grüße` is not in "
      "`gr%C3%BC%C3%9Fe`, and `%c3%bc` is",
      (envoy_phrases("w.data", data={"w.data": ["grüße"]}, location="Query-String")[0][:2],
       envoy_phrases("w.data", data={"w.data": ["%c3%bc"]}, location="Query-String")[0][:2]),
      ((True, None), (False, "matches-benign-traffic")))
check("a phrase is one `contains` however awkward: a quote, a backslash, a colon, a control character, a space at "
      "either end are read back as written (in a User-Agent, where no ordinary request holds one)",
      [m["header"]["string_match"]["contains"]
       for m in envoy_phrases("w.data", data={"w.data": [v for v in awkward if v]}, location="User-Agent")[1]],
      [v for v in awkward if v])
check("only the phrase lists of rules that are written are in the filter",
      sorted(m["header"]["string_match"]["contains"] for m in
             yaml.safe_load(backends.get("envoy").compile(ir.IR(rules=[
                 rule("1", operator={"name": "pmFromFile", "negated": False, "argument": "words.data"}),
                 rule("2", action="pass", operator={"name": "pmFromFile", "negated": False, "argument": "other.data"})],
                 data_files={"words.data": ["zqxjk"], "other.data": ["zqxjl"]})).files["waf-rbac.yaml"])[0]
             ["typed_config"]["rules"]["policies"]["waf_path"]["permissions"][0]["or_rules"]["rules"]), ["zqxjk"])

print("what the HAProxy backend writes")
haproxy_records = [(d, R.rules[d.index]) for d in compiled["haproxy"].decisions if d.emitted]
check("haproxy writes only @rx, @pm and @pmFromFile, not negated, that refuse and are `high`",
      sorted({(r["operator"]["name"], r["operator"]["negated"], r["severity"]) for _, r in haproxy_records}),
      [("pm", False, "high"), ("pmFromFile", False, "high"), ("rx", False, "high")])
cfg = compiled["haproxy"].files["waf.cfg"]
pattern_files = {n: t for n, t in compiled["haproxy"].files.items() if n.endswith(".acl")}
phrase_files = {n: t for n, t in compiled["haproxy"].files.items() if n.endswith(".data")}
check("every acl of waf.cfg loads a pattern file or a phrase file that exists, and every file is loaded",
      sorted(set(re.findall(r"-f /etc/haproxy/waf/(\S+)$", cfg, re.M))), sorted({*pattern_files, *phrase_files}))
check("an expression is matched with `-m reg` and a phrase list with `-m sub -i`, never the other way",
      sorted({(m, f.endswith(".acl")) for m, f in re.findall(r"-m (\w+)(?: -i)? -f /etc/haproxy/waf/(\S+)$", cfg, re.M)}),
      [("reg", True), ("sub", False)])
check("and the one deny names them all, in a line HAProxy takes (64 words at most)",
      (sorted(re.findall(r"^acl (\S+) ", cfg, re.M)) ==
       sorted(re.search(r"^http-request deny deny_status 403 if (.*)$", cfg, re.M).group(1).split(" or "))
       and len(re.search(r"^http-request deny .*$", cfg, re.M).group(0).split()) < 64), True)
check("a pattern file is one expression to a line, after a comment that names the CRS rule",
      sorted({len([l for l in t.splitlines() if l and not l.startswith("#")]) == t.count("# CRS ")
              for t in pattern_files.values()}), [True])
from patterns.backends._common import haproxy_pattern, modsecurity_unquote  # noqa: E402
check("haproxy: every expression is written as the engine reads it: unquoted as Apache unquotes, (?i) kept",
      [r["id"] for _, r in haproxy_records if r["operator"]["name"] == "rx"
       and haproxy_pattern(modsecurity_unquote(r["operator"]["argument"])) not in
       "".join(pattern_files.values()).splitlines()], [])


def haproxy_decision(argument="zqxjk", name="rx", negated=False, **extra):
    """What the HAProxy backend does with one rule made for the purpose."""
    record = rule(operator={"name": name, "negated": negated, "argument": argument}, **extra)
    one = backends.get("haproxy").compile(ir.IR(rules=[record]))
    return (one.decisions[0].emitted, one.decisions[0].reason), one.files


check("haproxy: a rule that is fine is written", haproxy_decision()[0], (True, None))
check("a negated operator is not", haproxy_decision(negated=True)[0], (False, "operator-unsupported"))
check("nor one that is not a regular expression", haproxy_decision("1", "lt")[0], (False, "operator-unsupported"))
check("nor a record that is not a rule", haproxy_decision(directive="SecRuleUpdateTargetById")[0], (False, "not-a-rule"))
check("nor an empty pattern", haproxy_decision("")[0], (False, "empty-pattern"))
check("nor one PCRE does not compile", haproxy_decision("zq(xjk")[0], (False, "invalid-regex"))
check("nor one with a line break: a pattern file holds a line to a pattern",
      haproxy_decision("zq\nxjk")[0], (False, "invalid-regex"))
check("nor one on a fetch it cannot check", haproxy_decision(location="Cookie")[0], (False, "location-unsupported"))
check("nor one that does not refuse", haproxy_decision(action="pass")[0], (False, "not-blocking"))
check("nor one below `high`: a pattern file cannot only record",
      haproxy_decision(severity="medium")[0], (False, "severity-below-blocking"))
check("nor one an ordinary request matches", haproxy_decision("Googlebot", location="User-Agent")[0],
      (False, "matches-benign-traffic"))
check("an argument is read the way Apache reads it before the check, as HAProxy reads the file",
      haproxy_decision(r"\\(KHTML", location="User-Agent")[0], (False, "matches-benign-traffic"))
check("a (?i) is kept and not turned into -i: PCRE has it",
      "\n(?i)zqxjk\n" in haproxy_decision("(?i)zqxjk")[1]["waf-query-string.acl"]
      and " -i " not in haproxy_decision("(?i)zqxjk")[1]["waf.cfg"], True)
check("urlDecodeUni is url_dec(1), in a file of its own, named for it",
      "acl waf_query_string_urldecode query,url_dec(1) -m reg -f /etc/haproxy/waf/waf-query-string-urldecode.acl"
      in haproxy_decision(transformations=["urlDecodeUni"])[1]["waf.cfg"], True)
check("and lowercase is lower, in the order the rule has them",
      "query,lower,url_dec(1) " in haproxy_decision(transformations=["lowercase", "urlDecodeUni"])[1]["waf.cfg"]
      and "query,url_dec(1),lower " in haproxy_decision(transformations=["urlDecodeUni", "lowercase"])[1]["waf.cfg"],
      True)
check("one HAProxy has no converter for is not applied, and is named by the matrix",
      "acl waf_query_string query -m reg" in haproxy_decision(transformations=["htmlEntityDecode"])[1]["waf.cfg"],
      True)
check("the check against ordinary traffic decodes first, for a rule that decodes: `gr%C3%BC%C3%9Fe` is `grüße`",
      (haproxy_decision("grüße", transformations=["urlDecodeUni"])[0], haproxy_decision("grüße")[0]),
      ((False, "matches-benign-traffic"), (True, None)))
check("and lowers first, for a rule that lowers",
      (haproxy_decision("googlebot", location="User-Agent", transformations=["lowercase"])[0],
       haproxy_decision("googlebot", location="User-Agent")[0]),
      ((False, "matches-benign-traffic"), (True, None)))
check("every file of a build with nothing to write is just waf.cfg",
      sorted(backends.get("haproxy").compile(ir.IR(rules=[])).files), ["waf.cfg"])
check("and it has no deny line that names nothing",
      "http-request deny" in backends.get("haproxy").compile(ir.IR(rules=[])).files["waf.cfg"], False)
check("a pattern file line: a leading or trailing space, tab or leading # is written escaped",
      [haproxy_pattern(v) for v in (" a", "a ", "\ta", "a\t", "#a", "a#b", "a b")],
      ["\\ a", "a\\ ", "\\\ta", "a\\\t", "\\#a", "a#b", "a b"])
check("one that is escaped already is not escaped twice, and one that is not, with a backslash before it, is",
      [haproxy_pattern(v) for v in ("a\\ ", "a\\\\ ")], ["a\\ ", "a\\\\\\ "])

print("what the HAProxy backend writes for a list of phrases")


def haproxy_phrases(argument, name="pmFromFile", data=None, negated=False, **extra):
    """What the HAProxy backend does with one phrase rule made for the purpose, and the files it writes."""
    record = rule(operator={"name": name, "negated": negated, "argument": argument}, **extra)
    one = backends.get("haproxy").compile(ir.IR(rules=[record], data_files=data or {}))
    d = one.decisions[0]
    return (d.emitted, d.reason, d.detail), one.files


def phrase_lines(text):
    return [l for l in text.splitlines() if l and not l.startswith("#")]


inline, files_ = haproxy_phrases("zqxjk-one zq.two", "pm")
check("haproxy: @pm is written as a phrase file of its own, which an acl loads with a substring match, case ignored",
      (inline[0], sorted(files_), "acl waf_query_string_pm_1 query -m sub -i -f /etc/haproxy/waf/pm-1.data\n"
       in files_["waf.cfg"], phrase_lines(files_["pm-1.data"])), (True, ["pm-1.data", "waf.cfg"], True, ["zqxjk-one", "zq.two"]))
listed, files_ = haproxy_phrases("words.data", data=WORDS)
check("@pmFromFile is written with the file CRS names, shipped with the rules",
      (listed[0], sorted(files_), "-m sub -i -f /etc/haproxy/waf/words.data\n" in files_["waf.cfg"]),
      (True, ["waf.cfg", "words.data"], True))
check("the file is a phrase to a line after a comment, which HAProxy skips, in the order CRS has them",
      phrase_lines(files_["words.data"]), WORDS["words.data"])
check("and the one deny names the acl",
      "http-request deny deny_status 403 if waf_query_string_words\n" in files_["waf.cfg"], True)
check("a phrase list the IR does not have is not guessed at",
      haproxy_phrases("gone.data", data=WORDS)[0], (False, "operator-unsupported", "@pmFromFile (the IR has no such phrase list)"))
check("an empty one is not written", haproxy_phrases("e.data", data={"e.data": []})[0][:2], (False, "empty-pattern"))
check("a negated one is not: it is not what a rule that refuses can say",
      haproxy_phrases("zqxjk", "pm", negated=True)[0][:2], (False, "operator-unsupported"))
check("one an ordinary request holds is not written, whatever the case: `Googlebot` in a User-Agent",
      haproxy_phrases("GOOGLEBOT zqxjk", "pm", location="User-Agent")[0][:2], (False, "matches-benign-traffic"))
check("and a phrase that is last in a long list keeps the whole rule out: it is written whole or not at all",
      haproxy_phrases("big.data", data={"big.data": late}, location="User-Agent")[0][:2], (False, "matches-benign-traffic"))
check("a phrase list is looked for in the query string as HAProxy holds it: raw, `gr%C3%BC%C3%9Fe` is not `grüße`",
      (haproxy_phrases("w.data", data={"w.data": ["grüße"]}, location="Query-String")[0][:2],
       haproxy_phrases("w.data", data={"w.data": ["grüße"]}, location="Query-String",
                       transformations=["urlDecodeUni"])[0][:2]),
      ((True, None), (False, "matches-benign-traffic")))
check("a rule that declares `urlDecodeUni` has the converter on the fetch of its acl, and `lowercase` has nothing to add",
      ("query,url_dec(1) -m sub -i" in haproxy_phrases("words.data", data=WORDS, transformations=["urlDecodeUni", "lowercase"])[1]["waf.cfg"],
       ",lower" in haproxy_phrases("words.data", data=WORDS, transformations=["lowercase"])[1]["waf.cfg"]),
      (True, False))
check("a phrase a pattern file cannot hold as it is keeps the rule out: one that starts with `#`, or with blank space",
      [haproxy_phrases("w.data", data={"w.data": ["zqxjk", odd]})[0][:2] for odd in ("#zq", " zq", "zq ", "\tzq")],
      [(False, "invalid-regex")] * 4)
check("and one with the same characters inside is fine: `a#b`, `a b`",
      [haproxy_phrases("w.data", data={"w.data": ["zq" + inside]})[0][:2] for inside in ("a#b", "a b", "a\\b")],
      [(True, None)] * 3)
check("one list read by two rules, on two fetches, is shipped once and loaded by two acls",
      (lambda out: (sorted(out.files), len(re.findall(r"-f /etc/haproxy/waf/words.data$", out.files["waf.cfg"], re.M))))(
          backends.get("haproxy").compile(ir.IR(rules=[
              rule("1", operator={"name": "pmFromFile", "negated": False, "argument": "words.data"}),
              rule("2", operator={"name": "pmFromFile", "negated": False, "argument": "words.data"},
                   location="User-Agent")], data_files=WORDS))),
      (["waf.cfg", "words.data"], 2))
check("only the phrase files of rules that are written are shipped",
      sorted(backends.get("haproxy").compile(ir.IR(rules=[
          rule("1", operator={"name": "pmFromFile", "negated": False, "argument": "words.data"}),
          rule("2", action="pass", operator={"name": "pmFromFile", "negated": False, "argument": "other.data"})],
          data_files={"words.data": ["zqxjk"], "other.data": ["zqxjl"]})).files), ["waf.cfg", "words.data"])

try:
    import tomllib
except ImportError:  # before 3.11
    tomllib = None
if tomllib:
    awkward = [r"^\$", r"a\.b", "it's", r'say "hi"', r"(?i)\bfoo\b", "back\\slash'quote"]
    for expression in awkward:
        text = built("traefik", rule(operator={"name": "rx", "negated": False, "argument": expression},
                                     pattern="@rx " + expression, location="User-Agent"))["middleware.toml"]
        try:
            read = tomllib.loads(text)["http"]["middlewares"]["waf_test_user_agent"]["plugin"]["blockuseragent"]["regex"]
        except Exception as e:  # noqa: BLE001
            read = f"not TOML: {e}"
        check(f"traefik: {expression!r} is read back as written", read, [expression])
    check("and so is the whole committed file",
          bool(tomllib.loads((REPO_ROOT / "waf_patterns" / "traefik" / "middleware.toml").read_text())), True)
    check("and the bad-bot list, which badbots.py writes",
          len(tomllib.loads((REPO_ROOT / "waf_patterns" / "traefik" / "bots.toml").read_text())
              ["http"]["middlewares"]["bad_bot_block"]["plugin"]["blockuseragent"]["regex"]) > 1000, True)
check("what each backend declares it can express is what is shown above and nothing more: "
      "a claim added here has to be shown in the output first",
      {n: (c.capabilities.dialect, sorted(c.capabilities.operators),
           sorted(c.capabilities.transformations), c.capabilities.case_insensitive)
       for n, c in ((n, backends.get(n)) for n in backends.names())},
      {"nginx": ("pcre", ["pm", "pmFromFile", "rx"], ["lowercase"], True),
       "apache": ("pcre", ["pm", "pmFromFile", "rx"], ["lowercase"], True),
       "traefik": ("re2", ["rx"], [], True),
       "haproxy": ("pcre", ["pm", "pmFromFile", "rx"], ["lowercase"], True),
       "envoy": ("re2", ["pm", "pmFromFile", "rx"], ["lowercase"], True)})
check("every location a backend wrote a regular expression on is one it declares",
      {n: sorted({d.location for d in compiled[n].decisions if d.emitted and d.pattern}
                 - set(backends.get(n).capabilities.locations)) for n in compiled},
      {n: [] for n in compiled})

print("variables and locations")
mismatched = []
for record in R.rules:
    if record["directive"] != "SecRule" or record["location"] == "UNKNOWN":
        continue
    locations = {coverage.location_of(v) for v in record["variables"]} - {None}
    if record["location"].lower() not in locations:
        mismatched.append(record["id"])
check("the location the IR folds a rule to is the location of one of its variables",
      sorted(set(mismatched)), [])
check("a variable the folding does not map has no location",
      coverage.location_of(var("TX", "anomaly_score")), None)
check("a header with a selector is that header",
      coverage.location_of(var("REQUEST_HEADERS", "User-Agent")), "user-agent")
check("XML has none", coverage.location_of(var("XML", "/*")), None)

print("dialects")
check("pcre takes what Python can parse", dialects.check("pcre", r"a(?=b)(?<!c)\x{263a}"), None)
check("a global flag that is not at the start is fine, in every Python",
      dialects.check("pcre", "!(?i)abc"), None)
check("the stand-in compiler moves a global flag to the start, which Python 3.11 would refuse",
      bool(dialects.python_compile("a(?i)b").search("AB")), True)
check("so a rule with one is still checked against ordinary traffic, and not skipped",
      __import__("patterns.corpus", fromlist=["x"]).first_ordinary_match("zqxjk|(?i)googlebot", "user_agent"),
      "googlebot")
check("and what Python cannot compile either way is None, as it was",
      (dialects.python_compile("a(b"), dialects.python_compile("(?<=a+)b")), (None, None))
check("re2 has no lookahead", "lookaround" in (dialects.check("re2", "a(?=b)") or ""), True)
check("nor lookbehind", "lookaround" in (dialects.check("re2", "(?<!no)bad") or ""), True)
check("nor backreference", "backreference" in (dialects.check("re2", r"(a)\1") or ""), True)
check("it takes a lazy quantifier and a flag", dialects.check("re2", "(?i)a+?b"), None)
check("a pattern that does not parse says so", "does not parse" in (dialects.check("pcre", "a(") or ""), True)
if MODERN:
    check("re2 has no possessive quantifier",
          "possessive quantifier" in (dialects.check("re2", "a*+b") or ""), True)
    check("nor atomic group", "atomic group" in (dialects.check("re2", "(?>a)b") or ""), True)
    check("pcre has both", dialects.check("pcre", "a*+(?>b)"), None)
check("no backend writes an expression its engine refuses",
      {n: coverage.dialect_problems(backends.get(n), R, c) for n, c in compiled.items()}
      if MODERN else {n: [] for n in compiled}, {n: [] for n in compiled})


class Refuses(Backend):
    """Writes an expression RE2 does not have."""

    name = "refuses"
    title = "Refuses"
    capabilities = Capabilities(dialect="re2", operators=frozenset({"rx"}),
                                transformations=frozenset(), case_insensitive=True, locations={})

    def compile(self, ir_):
        return Compiled({"out.txt": "x\n"}, [Decision(0, True, location="query-string", pattern="a(?=b)")])


if MODERN:
    backends.register(Refuses)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            code = cli.main(["build", "--target", "refuses", "--out", tmp])
            check("build refuses to write an expression the target's engine does not have",
                  (code, list(Path(tmp).rglob("*"))), (1, []))
    except SystemExit as e:
        check("build refuses to write ... (argparse accepted the target)", e.code, 1)
    finally:
        del backends._REGISTRY["refuses"]

print("the report")
report = coverage.report(R, {n: (backends.get(n), compiled[n]) for n in compiled})
for name, entry in report["backends"].items():
    check(f"{name}: the totals add up to the rules",
          sum(entry["totals"].values()), len(R.rules))
    check(f"{name}: a loss is counted once per rule",
          max(entry["losses"].values(), default=0) <= sum(
              v for k, v in entry["totals"].items() if k != "dropped"), True)
    check(f"{name}: the reasons add up to the dropped",
          sum(entry["reasons"].values()), entry["totals"]["dropped"])
text = coverage.to_json(report)
check("the JSON parses, and keeps every rule", len(json.loads(text)["rules"]), len(R.rules))
check("one rule to a line", text.count('\n    {"index":'), len(R.rules))
check("and is the same the second time",
      text == coverage.to_json(coverage.report(
          R, {n: (backends.get(n), backends.get(n).compile(R)) for n in compiled})), True)
check("the table names every target",
      all(b["title"] in coverage.to_markdown(report) for b in report["backends"].values()), True)

print("what the documents say")
readme = (REPO_ROOT / "README.md").read_text()
check("the README states no count of rules that the table could disagree with",
      re.search(r"\d+ (?:emitted|written) rules", readme), None)
if MODERN:
    result = subprocess.run([sys.executable, "-W", "ignore", "-m", "patterns", "coverage", "--check"],
                            cwd=REPO_ROOT, capture_output=True, text=True)
    check("README.md and docs/coverage.md show the table the data gives",
          (result.returncode, result.stderr.strip()), (0, ""))
    check("coverage.json is the matrix the IR gives",
          (REPO_ROOT / "waf_patterns" / "coverage.json").read_text(), text)

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
