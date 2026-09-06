#!/usr/bin/env python3
"""
What a SecRule declares, and what the extractor used to read instead.

Every converter in this repository reads the JSON this extractor produces, so a
field that is silently wrong here is wrong in all four outputs at once. Three
were:

- the directive was matched with `SecRule\\s+.*?"((?:[^"\\\\]|\\\\.)+?)"`, which
  stops at the closing quote of the *operator*. The action list, where the id,
  the severity and the transformations live, was never read at all.
- `severity:(\\w+)` cannot match `severity:'CRITICAL'`, so all 695 rules came
  out "medium" and the nginx converter, which blocks on "high", blocked nothing.
- the transformation chain and the disruptive action were not recorded, so a
  converter had no way to tell a signature from a rule that only counts.

The fixtures below are real CRS directives, copied verbatim (#45).

Usage:
    python3 tests/test_extraction.py
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import owasp2json  # noqa: E402

failures = 0
checks = 0


def check(description, actual, expected):
    global failures, checks
    checks += 1
    if actual != expected:
        failures += 1
        print(f"  FAIL  {description}")
        print(f"        expected {expected!r}, got {actual!r}")


def only_rule(text):
    """Extracts the single rule in a fixture."""
    rules = owasp2json.extract_sec_rules(text)
    assert len(rules) == 1, f"fixture holds {len(rules)} rules, not 1"
    return rules[0]


# CRS 941110, verbatim. A signature: it blocks, and its pattern is written to
# match a value that six transformations have already been applied to.
XSS_SCRIPT_TAG = r'''
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|!REQUEST_HEADERS:Cookie|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)<script[^>]*>[\s\S]*?" \
    "id:941110,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
    msg:'XSS Filter - Category 1: Script Tag Vector',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'attack-xss',\
    severity:'CRITICAL',\
    setvar:'tx.xss_score=+%{tx.critical_anomaly_score}'"
'''

# CRS 921170. Not a signature: `@rx .` matches any character at all, the rule
# declares `pass`, and it exists to count how often a parameter name repeats.
PARAMETER_COUNTER = r'''
SecRule ARGS_NAMES "@rx ." \
    "id:921170,\
    phase:2,\
    pass,\
    nolog,\
    tag:'attack-protocol',\
    ver:'OWASP_CRS/4.29.0',\
    setvar:'tx.paramcounter_%{MATCHED_VAR_NAME}=+1'"
'''

# CRS 942100. libinjection, not a regular expression.
SQLI_LIBINJECTION = r'''
SecRule REQUEST_COOKIES|ARGS_NAMES|ARGS|XML:/*|XML://@* "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
    msg:'SQL Injection Attack Detected via libinjection',\
    severity:'CRITICAL'"
'''

# A method enforcement rule: no transformations, and a target that is a request
# component nginx can name.
METHOD_ENFORCEMENT = r'''
SecRule REQUEST_METHOD "@rx ^(?:CONNECT|TRACE)$" \
    "id:911100,\
    phase:1,\
    deny,\
    msg:'Method is not allowed by policy, e.g. GET, POST',\
    severity:'CRITICAL'"
'''


print("\nreading the whole directive")
check("the action list is read, not just the operator",
      only_rule(XSS_SCRIPT_TAG)["id"], "941110")
check("the pattern is the operator string",
      only_rule(XSS_SCRIPT_TAG)["pattern"], r"@rx (?i)<script[^>]*>[\s\S]*?")
check("a directive with no action list still yields its pattern",
      only_rule('SecRule ARGS "@rx foo"')["pattern"], "@rx foo")
check("a comment is not a directive",
      owasp2json.extract_sec_rules("# SecRule ARGS \"@rx x\" \"id:1\"\n"), [])

print("severity")
check("the quoted form CRS writes",
      only_rule(XSS_SCRIPT_TAG)["severity"], "high")
check("the unquoted form SecLang also allows",
      owasp2json._extract_rule_severity("id:1,severity:CRITICAL"), "high")
check("ERROR is medium", owasp2json._extract_rule_severity("severity:'ERROR'"), "medium")
check("WARNING is medium", owasp2json._extract_rule_severity("severity:'WARNING'"), "medium")
check("NOTICE is low", owasp2json._extract_rule_severity("severity:'NOTICE'"), "low")
check("a rule that declares none is medium",
      owasp2json._extract_rule_severity("id:1,phase:2,pass"), "medium")
check("an unknown severity is medium rather than dropped",
      owasp2json._extract_rule_severity("severity:'MADEUP'"), "medium")

print("transformations")
check("the chain is recorded in order",
      only_rule(XSS_SCRIPT_TAG)["transformations"],
      ["utf8toUnicode", "urlDecodeUni", "htmlEntityDecode", "jsDecode",
       "cssDecode", "removeNulls"])
check("t:none is not a transformation",
      owasp2json._extract_transformations("t:none"), [])
check("a rule with no chain has an empty one",
      only_rule(METHOD_ENFORCEMENT)["transformations"], [])

print("disruptive action")
check("a signature blocks", only_rule(XSS_SCRIPT_TAG)["action"], "block")
check("a counter passes", only_rule(PARAMETER_COUNTER)["action"], "pass")
check("deny is read too", only_rule(METHOD_ENFORCEMENT)["action"], "deny")
check("a rule that declares none says so",
      owasp2json._extract_disruptive_action("id:1,phase:2,t:none"), None)
check("an action name inside a message is not an action",
      owasp2json._extract_disruptive_action("id:1,msg:'we block, then log',pass"),
      "pass")
check("a comma inside a quoted value does not split it",
      owasp2json._split_actions("id:1,msg:'a, b, c',pass"),
      ["id:1", "msg:'a, b, c'", "pass"])

print("location")
check("REQUEST_METHOD is a request component nginx can name",
      only_rule(METHOD_ENFORCEMENT)["location"], "Request-Method")
check("ARGS is the query string",
      only_rule(PARAMETER_COUNTER)["location"], "Query-String")

print("operators other than @rx")
check("libinjection is recorded as the operator it is",
      only_rule(SQLI_LIBINJECTION)["pattern"], "@detectSQLi")
check("and it still carries its severity",
      only_rule(SQLI_LIBINJECTION)["severity"], "high")

print("directive assembly")
check("continuations are joined into one directive",
      len(owasp2json._iter_directives(XSS_SCRIPT_TAG)), 1)
check("two directives stay two",
      len(owasp2json._iter_directives(
          'SecRule ARGS "@rx a" "id:1"\nSecRule ARGS "@rx b" "id:2"')), 2)
check("an escaped quote does not end a string",
      owasp2json._quoted_strings(r'SecRule ARGS "@rx say\"hi" "id:1"'),
      [r'@rx say\"hi', "id:1"])

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
