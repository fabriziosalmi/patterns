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
check("nginx: map keys in waf_maps.conf",
      len(re.findall(r'^  "~', nginx, re.M)), written("nginx"))
check("apache: SecRule lines in the category files",
      sum(len(re.findall(r"^SecRule ", text, re.M)) for text in compiled["apache"].files.values()),
      written("apache"))
acl = compiled["haproxy"].files["waf.acl"]
check("haproxy: ACLs and comparisons in waf.acl",
      len(re.findall(r"^acl ", acl, re.M))
      + len(re.findall(r"^http-request (?:deny|log|tarpit) if \{", acl, re.M)),
      written("haproxy"))
check("traefik: patterns in middleware.toml",
      len(re.findall(r'^      "', compiled["traefik"].files["middleware.toml"], re.M)),
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
check("apache declares no transformations: the rule is written with t:none only",
      "t:none," in built("apache", lowered)["test.conf"]
      and "t:lowercase" not in built("apache", lowered)["test.conf"], True)
check("haproxy declares case-insensitive: every ACL is written with -i",
      " -i " in built("haproxy", lowered)["waf.acl"], True)
insensitive = rule(operator={"name": "rx", "negated": False, "argument": "(?i)zqxjk"},
                   pattern="@rx (?i)zqxjk", location="User-Agent")
check("traefik declares it is not: (?i) is removed and nothing replaces it",
      '"zqxjk"' in built("traefik", insensitive)["middleware.toml"]
      and "(?i)" not in built("traefik", insensitive)["middleware.toml"], True)
check("what each backend declares it can express is what is shown above and nothing more: "
      "a claim added here has to be shown in the output first",
      {n: (c.capabilities.dialect, sorted(c.capabilities.operators),
           sorted(c.capabilities.transformations), c.capabilities.case_insensitive)
       for n, c in ((n, backends.get(n)) for n in backends.names())},
      {"nginx": ("pcre", ["rx"], ["lowercase"], True),
       "apache": ("pcre", ["rx"], [], True),
       "traefik": ("re2", ["rx"], [], False),
       "haproxy": ("pcre", ["contains", "endsWith", "rx", "streq"], ["lowercase"], True)})
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
