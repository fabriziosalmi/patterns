#!/usr/bin/env python3
"""
What the intermediate representation says about a rule.

The converters read four things from a rule: a pattern string with its operator
stuck to the front, one folded location, a severity and an action. The rest of
what a CRS rule declares was thrown away, and three facts that decide whether a
rule can be enforced at all went with it:

- which variables it is matched against, and which are excluded. The folded
  location is "UNKNOWN" for 412 of 749 rules;
- what the operator is, apart from its argument. `@lt 1`, `@pmFromFile x.data`
  and a regular expression were all just `pattern`;
- that a rule is one link of a chain. The head and each link were emitted as
  rules in their own right, so `SecRule REQUEST_BODY "@rx \\x25"` stood for
  something that only means anything together with the two rules after it.

Fixtures marked verbatim are CRS v4.29.0 directives, copied as they are written.
The rest are synthetic, because CRS has no instance of the form under test: a
`|` inside a regular-expression selector, `phase:request`.

Usage:
    python3 tests/test_ir_extraction.py
"""

import json
import sys
import tempfile
import time
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


def extract(text):
    return owasp2json.extract_sec_rules(text)


def only_rule(text):
    rules = extract(text)
    assert len(rules) == 1, f"fixture holds {len(rules)} rules, not 1"
    return rules[0]


def var(name, selector=None, count=False, excluded=False):
    return {"name": name, "selector": selector, "count": count, "excluded": excluded}


# CRS 941110, verbatim. Nine variables, one of them excluded, two of them XPath.
XSS_SCRIPT_TAG = r'''
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|!REQUEST_HEADERS:Cookie|ARGS_NAMES|ARGS|XML:/*|XML://@* "@rx (?i)<script[^>]*>[\s\S]*?" \
    "id:941110,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
    msg:'XSS Filter - Category 1: Script Tag Vector',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-xss',\
    tag:'xss-perf-disable',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-XSS',\
    tag:'capec/1000/152/242',\
    ver:'OWASP_CRS/4.29.0',\
    severity:'CRITICAL',\
    setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
'''

# CRS 901340, verbatim. A negated operator on a rule that scores nothing.
NEGATED_OPERATOR = r'''
SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" \
    "id:901340,\
    phase:1,\
    pass,\
    nolog,\
    noauditlog,\
    msg:'Enabling body inspection',\
    tag:'OWASP_CRS',\
    ctl:forceRequestBodyVariable=On,\
    ver:'OWASP_CRS/4.29.0'"
'''

# CRS 901001, verbatim. `&TX:name` counts the variables that match.
COUNTED_VARIABLE = r'''
SecRule &TX:crs_setup_version "@eq 0" \
    "id:901001,\
    phase:1,\
    deny,\
    status:500,\
    log,\
    auditlog,\
    msg:'CRS is deployed without configuration! Please copy the crs-setup.conf.example template to crs-setup.conf, and include the crs-setup.conf file in your webserver configuration before including the CRS rules. See the INSTALL file in the CRS directory for detailed instructions',\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.29.0',\
    severity:'CRITICAL'"
'''

# CRS 901320, verbatim. A chain of three: the head carries the id and the
# phase, the links carry neither, and the last one takes no argument.
THREE_LINK_CHAIN = r'''
SecRule &TX:ENABLE_DEFAULT_COLLECTIONS "@eq 1" \
    "id:901320,\
    phase:1,\
    pass,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.29.0',\
    setvar:'tx.ua_hash=%{REQUEST_HEADERS.User-Agent}',\
    chain"
    SecRule TX:ENABLE_DEFAULT_COLLECTIONS "@eq 1" \
        "chain"
        SecRule TX:ua_hash "@unconditionalMatch" \
            "t:none,t:sha1,t:hexEncode,\
            initcol:global=global,\
            initcol:ip=%{remote_addr}_%{MATCHED_VAR}"
'''

# CRS 932207, verbatim. The score is written on the last link, and it is added
# only when all four links match.
CHAIN_WITH_SCORE_ON_LAST_LINK = r'''
SecRule REQUEST_HEADERS:Referer "@rx #.*" \
    "id:932207,\
    phase:1,\
    block,\
    capture,\
    t:none,t:lowercase,t:urlDecodeUni,\
    msg:'RCE Bypass Technique',\
    logdata:'Matched Data: %{TX.0} found within %{TX.932207_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-rce',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-RCE',\
    tag:'capec/1000/152/248/88',\
    ver:'OWASP_CRS/4.29.0',\
    severity:'CRITICAL',\
    setvar:'tx.932207_matched_var_name=%{matched_var_name}',\
    chain"
    SecRule TX:0 "@rx ['\*\?\x5c`][^\n/]+/|/[^/]+?['\*\?\x5c`]|\$[!#\$\(\*\-0-9\?-\[_a-\{]" \
        "capture,\
        t:none,\
        chain"
        SecRule MATCHED_VAR "@rx /" \
            "t:none,\
            chain"
            SecRule MATCHED_VAR "@rx \s" \
                "t:none,\
                chain"
                SecRule MATCHED_VAR "!@beginsWith #:~:text=" \
                    "t:none,\
                    setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\
                    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
'''

# CRS 932240's exclusion, verbatim. Not a rule: it adds a target to one.
TARGET_UPDATE = r'''SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:/^_ga(?:_\w+)?$/"'''

# The rules that set what a level is worth, from REQUEST-901-INITIALIZATION.conf.
SCORE_DEFAULTS = r'''
SecRule &TX:critical_anomaly_score "@eq 0" \
    "id:901140,\
    phase:1,\
    pass,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.29.0',\
    setvar:'tx.critical_anomaly_score=5'"

SecRule &TX:notice_anomaly_score "@eq 0" \
    "id:901143,\
    phase:1,\
    pass,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.29.0',\
    setvar:'tx.notice_anomaly_score=2'"
'''


print("\nvariables")
check("every variable of a long list, in order",
      [(v["name"], v["selector"]) for v in only_rule(XSS_SCRIPT_TAG)["variables"]],
      [("REQUEST_COOKIES", None), ("REQUEST_COOKIES_NAMES", None),
       ("REQUEST_FILENAME", None), ("REQUEST_HEADERS", None),
       ("REQUEST_HEADERS", "Cookie"), ("ARGS_NAMES", None), ("ARGS", None),
       ("XML", "/*"), ("XML", "//@*")])
check("!VAR:selector is excluded, not added",
      [v for v in only_rule(XSS_SCRIPT_TAG)["variables"] if v["excluded"]],
      [var("REQUEST_HEADERS", "Cookie", excluded=True)])
check("&VAR:selector counts the variables",
      only_rule(COUNTED_VARIABLE)["variables"],
      [var("TX", "crs_setup_version", count=True)])
check("a | inside a regular-expression selector does not split it (synthetic)",
      owasp2json._split_variables("ARGS:/^(a|b)$/|ARGS_NAMES"),
      ["ARGS:/^(a|b)$/", "ARGS_NAMES"])
check("an escaped slash does not end a regular-expression selector (synthetic)",
      owasp2json._split_variables(r"ARGS:/a\/b|c/|ARGS_NAMES"),
      [r"ARGS:/a\/b|c/", "ARGS_NAMES"])
check("XPath starts with a slash and is not a regular expression (synthetic)",
      owasp2json._split_variables("XML:/*|ARGS:/x/|ARGS_NAMES"),
      ["XML:/*", "ARGS:/x/", "ARGS_NAMES"])
check("the space a joined continuation leaves after a | is not part of a name",
      [v["name"] for v in owasp2json._parse_variables("REQUEST_COOKIES| ARGS_NAMES |ARGS")],
      ["REQUEST_COOKIES", "ARGS_NAMES", "ARGS"])
check("the selector is kept as written",
      owasp2json._parse_variables("REQUEST_HEADERS:User-Agent"),
      [var("REQUEST_HEADERS", "User-Agent")])

print("operator")
check("a regular expression: name and argument apart",
      only_rule(XSS_SCRIPT_TAG)["operator"],
      {"name": "rx", "negated": False, "argument": r"(?i)<script[^>]*>[\s\S]*?"})
check("a negated operator keeps its name",
      only_rule(NEGATED_OPERATOR)["operator"],
      {"name": "rx", "negated": True, "argument": "(?:URLENCODED|MULTIPART|XML|JSON)"})
check("a numeric comparison",
      only_rule(COUNTED_VARIABLE)["operator"],
      {"name": "eq", "negated": False, "argument": "0"})
check("an operator that takes no argument has an empty one",
      owasp2json._parse_operator("@unconditionalMatch"),
      {"name": "unconditionalMatch", "negated": False, "argument": ""})
check("the name keeps the case it is written in",
      owasp2json._parse_operator("@detectSQLi")["name"], "detectSQLi")
check("no operator means @rx",
      owasp2json._parse_operator("^foo$"),
      {"name": "rx", "negated": False, "argument": "^foo$"})
check("and it can be negated",
      owasp2json._parse_operator("!^foo$"),
      {"name": "rx", "negated": True, "argument": "^foo$"})
check("nothing in the argument is unescaped",
      owasp2json._parse_operator(r"@rx a\\b\"c")["argument"], r"a\\b\"c")
check("the argument of @pmFromFile is the file name",
      owasp2json._parse_operator("@pmFromFile restricted-files.data"),
      {"name": "pmFromFile", "negated": False, "argument": "restricted-files.data"})

print("phase")
check("a number", only_rule(XSS_SCRIPT_TAG)["phase"], 2)
check("the phase of a rule that runs first", only_rule(NEGATED_OPERATOR)["phase"], 1)
check("request is phase 2 (synthetic)", owasp2json._extract_phase("id:1,phase:request,pass"), 2)
check("response is phase 4 (synthetic)", owasp2json._extract_phase("id:1,phase:response"), 4)
check("a quoted number (synthetic)", owasp2json._extract_phase("phase:'3'"), 3)
check("no phase declared", owasp2json._extract_phase("id:1,pass"), None)

print("severity as written")
check("CRITICAL stays CRITICAL", only_rule(XSS_SCRIPT_TAG)["crs_severity"], "CRITICAL")
check("high is what the converters are given", only_rule(XSS_SCRIPT_TAG)["severity"], "high")
check("a rule that declares none has none",
      only_rule(NEGATED_OPERATOR)["crs_severity"], None)
check("and is medium for the converters", only_rule(NEGATED_OPERATOR)["severity"], "medium")

print("anomaly score")
check("inbound, critical, paranoia level 1",
      only_rule(XSS_SCRIPT_TAG)["score"],
      {"direction": "inbound", "level": "critical", "paranoia_level": 1})
check("a rule that only counts has none", only_rule(NEGATED_OPERATOR)["score"], None)
check("outbound and a lower level (synthetic)",
      owasp2json._extract_score("setvar:'tx.outbound_anomaly_score_pl3=+%{tx.error_anomaly_score}'"),
      {"direction": "outbound", "level": "error", "paranoia_level": 3})
check("a per-category counter is not the anomaly score",
      owasp2json._extract_score("setvar:'tx.xss_score=+%{tx.critical_anomaly_score}'"), None)
check("adding a score to a score is not a detection",
      owasp2json._extract_score(
          "setvar:'tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}'"), None)
check("what a level is worth is read from CRS",
      owasp2json.extract_score_defaults(SCORE_DEFAULTS),
      {"critical": 5, "notice": 2})
check("a file that sets none gives none",
      owasp2json.extract_score_defaults(XSS_SCRIPT_TAG), {})

print("chain")
chain3 = extract(THREE_LINK_CHAIN)
check("a chain of three is three records", len(chain3), 3)
check("the head says it is one",
      chain3[0]["chain"], {"role": "head", "head": "901320", "position": 0})
check("the links say whose they are, and where",
      [r["chain"] for r in chain3[1:]],
      [{"role": "link", "head": "901320", "position": 1},
       {"role": "link", "head": "901320", "position": 2}])
check("a link has no id of its own", [r["id"] for r in chain3], ["901320", "no_id", "no_id"])
check("a link runs in its head's phase", [r["phase"] for r in chain3], [1, 1, 1])
check("each link keeps its own condition",
      [(r["variables"][0]["name"], r["operator"]["name"]) for r in chain3],
      [("TX", "eq"), ("TX", "eq"), ("TX", "unconditionalMatch")])
check("the head declares the action, the links do not",
      [r["action"] for r in chain3], ["pass", None, None])

chain5 = extract(CHAIN_WITH_SCORE_ON_LAST_LINK)
check("a chain of five", [r["chain"]["position"] for r in chain5], [0, 1, 2, 3, 4])
check("every record names the same head",
      {r["chain"]["head"] for r in chain5}, {"932207"})
check("the score CRS wrote on the last link belongs to the head",
      [r["score"] for r in chain5],
      [{"direction": "inbound", "level": "critical", "paranoia_level": 2},
       None, None, None, None])
check("the head carries the severity",
      [r["crs_severity"] for r in chain5], ["CRITICAL", None, None, None, None])
check("a negated operator on the last link is still read",
      chain5[-1]["operator"],
      {"name": "beginsWith", "negated": True, "argument": "#:~:text="})
check("a rule outside any chain says so", only_rule(XSS_SCRIPT_TAG)["chain"], None)
check("a chain does not reach into the next rule",
      [r["chain"] for r in extract(THREE_LINK_CHAIN + XSS_SCRIPT_TAG)][-1], None)
check("another directive ends a chain that was left open (synthetic)",
      extract('SecRule ARGS "@rx a" "id:1,phase:2,chain"\n'
              'SecAction "id:2,phase:1,pass"\n'
              'SecRule ARGS "@rx b" "id:3,phase:2,pass"')[-1]["chain"], None)

print("what is not a rule")
update = only_rule(TARGET_UPDATE)
check("SecRuleUpdateTargetById is recorded as what it is",
      update["directive"], "SecRuleUpdateTargetById")
check("it names the rule it changes", update["target_rule_id"], "932240")
check("it has no operator", update["operator"], None)
check("its variable is an exclusion, and its selector a regular expression",
      update["variables"], [var("REQUEST_COOKIES", r"/^_ga(?:_\w+)?$/", excluded=True)])
check("it has no phase, score or chain",
      (update["phase"], update["score"], update["chain"]), (None, None, None))
check("a record that has no id says so", update["id"], "no_id")
check("a SecRule is not one", only_rule(XSS_SCRIPT_TAG)["directive"], "SecRule")
check("and changes no other rule", only_rule(XSS_SCRIPT_TAG)["target_rule_id"], None)
check("other SecRule* directives are not read as rules (synthetic)",
      extract('SecRuleRemoveByTag "attack-sqli"\nSecRuleRemoveById 949110'), [])
check("an update cannot close a chain that was open",
      extract('SecRule ARGS "@rx a" "id:1,phase:2,chain"\n' + TARGET_UPDATE +
              '\nSecRule ARGS "@rx b" "id:3,phase:2,pass"')[-1]["chain"], None)

print("the fields the converters read are untouched")
legacy = only_rule(XSS_SCRIPT_TAG)
check("pattern still carries its operator",
      legacy["pattern"], r"@rx (?i)<script[^>]*>[\s\S]*?")
check("location is still folded: nine variables, reported as one",
      legacy["location"], "Query-String")
check("the legacy fields and the new ones are all there, nothing else",
      sorted(legacy),
      sorted(["id", "pattern", "location", "severity", "transformations", "action",
              "directive", "phase", "variables", "operator", "crs_severity", "score",
              "chain", "target_rule_id"]))
check("an update has the same fields as a rule",
      sorted(update), sorted(legacy))

print("order")


def slow_in_reverse(file, session):
    """Finishes the files in the opposite order to their names."""
    time.sleep({"A.conf": 0.3, "B.conf": 0.15, "C.conf": 0.0}[file["name"]])
    return [{"id": file["name"]}], {}


original = owasp2json.process_rule_file
owasp2json.process_rule_file = slow_in_reverse
try:
    files = [{"name": n, "sha": ""} for n in ("C.conf", "A.conf", "B.conf")]
    rules, _ = owasp2json.fetch_owasp_rules(None, files)
finally:
    owasp2json.process_rule_file = original
check("rules come out in file-name order, not in the order the downloads finish",
      [r["id"] for r in rules], ["A.conf", "B.conf", "C.conf"])

print("the phrase lists")
check("a phrase is a line: no comment, no blank line, no blank space around it",
      owasp2json.parse_data_file("# a comment\n\n  .htaccess  \n# .env\n.htpasswd\r\n\t\n"),
      [".htaccess", ".htpasswd"])
check("a `#` that is not the start of a line is part of the phrase",
      owasp2json.parse_data_file("a#b\n#c\n"), ["a#b"])
check("each phrase once, in file order", owasp2json.parse_data_file("b\na\nb\nc\na\n"), ["b", "a", "c"])
check("and not only ASCII", owasp2json.parse_data_file("http://169。254。169。254\n⑯⑨\n"),
      ["http://169。254。169。254", "⑯⑨"])
check("a file of comments has no phrases", owasp2json.parse_data_file("# nothing\n\n"), [])
PM_FILE = ('SecRule REQUEST_FILENAME "@pmFromFile restricted-files.data" "id:930130,phase:1,block,'
           't:none,t:urlDecodeUni,t:normalizePath,msg:\'x\',severity:\'CRITICAL\'"')
PM_INLINE = 'SecRule ARGS "@pm document.cookie document.domain" "id:941999,phase:2,block,t:none"'
PM_AGAIN = 'SecRule ARGS|REQUEST_HEADERS "@pmFromFile unix-shell.data" "id:932160,phase:2,block,t:none"\n' + PM_FILE.replace("930130", "930131")
referenced = owasp2json.referenced_data_files(extract(PM_FILE + "\n" + PM_INLINE + "\n" + PM_AGAIN))
check("the files the rules read: the @pmFromFile ones, each once, sorted", referenced,
      ["restricted-files.data", "unix-shell.data"])
check("a rule that has no such operator reads none", owasp2json.referenced_data_files(extract(XSS_SCRIPT_TAG)), [])
check("an inline @pm is a list of its own, and reads no file", owasp2json.referenced_data_files(extract(PM_INLINE)), [])

import base64  # noqa: E402
import hashlib  # noqa: E402


def blob_of(content: bytes):
    """What GitHub says about a file: its blob sha, and the content as it sends it."""
    sha = hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()
    return sha, base64.b64encode(content).decode()


class FakeGitHub:
    """Stands in for the two calls that fetch a data file; counts them."""

    def __init__(self, files, lie_about=None):
        self.blobs = {n: blob_of(c) for n, c in files.items()}
        self.lie_about = lie_about
        self.calls = 0

    def __enter__(self):
        self.saved = (owasp2json.fetch_data_file_index, owasp2json.fetch_github_blob)
        by_sha = {sha: b64 for sha, b64 in self.blobs.values()}

        def index(session, ref):
            self.calls += 1
            return {n: sha for n, (sha, _) in self.blobs.items()}

        def blob(session, sha):
            self.calls += 1
            b64 = by_sha.get(sha, "")
            return base64.b64encode(b"tampered").decode() if (sha, b64) and sha == self.lie_about else b64

        owasp2json.fetch_data_file_index, owasp2json.fetch_github_blob = index, blob
        return self

    def __exit__(self, *exc):
        owasp2json.fetch_data_file_index, owasp2json.fetch_github_blob = self.saved


files = {"a.data": b"# c\none\ntwo\n", "b.data": "http://169。254\n".encode("utf-8"), "unused.data": b"x\n"}
with FakeGitHub(files) as fake:
    got = owasp2json.fetch_data_files(None, "v1", ["b.data", "a.data"])
check("the files a rule reads are fetched and read", got, {"a.data": ["one", "two"], "b.data": ["http://169。254"]})
check("in name order, so the document does not depend on the order they are asked for", list(got), ["a.data", "b.data"])
with FakeGitHub(files) as fake:
    owasp2json.fetch_data_files(None, "v1", [])
check("none are fetched when none are read: no request is made", fake.calls, 0)
with FakeGitHub(files) as fake:
    check("a file a rule reads that the ref does not have is an error, not a gap",
          owasp2json.fetch_data_files(None, "v1", ["a.data", "gone.data"]), None)
with FakeGitHub(files, lie_about=blob_of(files["a.data"])[0]) as fake:
    check("one whose content is not what GitHub lists is an error: the SHA is verified",
          owasp2json.fetch_data_files(None, "v1", ["a.data"]), None)
with FakeGitHub({"bad.data": b"\xff\xfe not utf-8\n"}) as fake:
    check("one that is not UTF-8 is an error", owasp2json.fetch_data_files(None, "v1", ["bad.data"]), None)

print("the file")
with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "rules.json"
    owasp2json.save_as_json([only_rule(XSS_SCRIPT_TAG)], str(out),
                            owasp2json.build_provenance("v4.29.0"),
                            {"critical": 5}, {"a.data": ["one"]})
    document = json.loads(out.read_text())
check("it is versioned", document["schema_version"], owasp2json.SCHEMA_VERSION)
check("it carries the score defaults", document["score_defaults"], {"critical": 5})
check("and the provenance", document["_provenance"]["source_ref"], "v4.29.0")
check("and the phrase lists the rules read", document["data_files"], {"a.data": ["one"]})
check("in that order, version first", list(document),
      ["schema_version", "_provenance", "score_defaults", "data_files", "rules"])

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
