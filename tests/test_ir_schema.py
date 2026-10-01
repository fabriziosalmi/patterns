#!/usr/bin/env python3
"""
The format of owasp_rules.json, and the file that is committed in it.

Every converter reads this file, and until now nothing said what is in it. A
converter that assumed a field could not tell a missing one from one that was
never there, and the extractor could change shape without anything failing.
schema/ir.schema.json says what is in it, and this checks four things about it:

  * the committed file is valid against the schema;
  * the schema rejects what it is meant to reject. A schema that accepts
    everything passes the first check too, so each rule is shown to fail on a
    document that breaks it;
  * what JSON Schema cannot say and a converter depends on holds: a chain is
    whole, the old fields agree with the new ones, every score has a weight;
  * the schema cannot change without its version. schema/checksums.json pins the
    content of each version, so editing the schema in place fails here until
    schema_version is raised and the new content is pinned next to the old.

Usage:
    python3 tests/test_ir_schema.py [owasp_rules.json]

Requires the `jsonschema` package.
"""

import copy
import hashlib
import json
import sys
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import owasp2json  # noqa: E402

SCHEMA_FILE = REPO_ROOT / "schema" / "ir.schema.json"
CHECKSUMS_FILE = REPO_ROOT / "schema" / "checksums.json"
DOCUMENT_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "owasp_rules.json"

failures = 0
checks = 0


def check(description, actual, expected=True):
    global failures, checks
    checks += 1
    if actual != expected:
        failures += 1
        print(f"  FAIL  {description}")
        print(f"        expected {expected!r}, got {actual!r}")


def schema_digest(schema):
    """
    A digest of what the schema says, not of how it is laid out.

    Keys are sorted and whitespace dropped, so reformatting the file does not
    need a new version and changing a constraint does.
    """
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


schema = json.loads(SCHEMA_FILE.read_text())
document = json.loads(DOCUMENT_FILE.read_text())
checksums = json.loads(CHECKSUMS_FILE.read_text())

jsonschema.Draft202012Validator.check_schema(schema)
validator = jsonschema.Draft202012Validator(schema)


def errors(doc):
    return [e.message for e in validator.iter_errors(doc)]


def refuses(doc, field):
    """
    True if the schema refuses `doc` and says it is because of `field`.

    "Refused" alone is not enough: a document broken in two places is refused
    for the wrong one, and the rule meant to catch the first is never exercised.
    """
    return any(
        field in " ".join(str(part) for part in e.absolute_path) or f"'{field}'" in e.message
        for e in validator.iter_errors(doc)
    )


def one_rule(**overrides):
    """A copy of a real rule with some fields replaced."""
    rule = copy.deepcopy(next(
        r for r in document["rules"]
        if r["directive"] == "SecRule" and r["chain"] is None and r["score"]
    ))
    rule.update(overrides)
    return rule


def wrapped(*rules, **top):
    doc = copy.deepcopy(document)
    doc["rules"] = list(rules)
    doc.update(top)
    return doc


print("\nthe committed file")
found = errors(document)
check(f"{DOCUMENT_FILE.name} is valid against the schema "
      f"({len(document['rules'])} rules)", found, [])
for message in found[:5]:
    print(f"        {message[:160]}")

print("version")
version = schema["properties"]["schema_version"]["const"]
check("the document says which version it is", document["schema_version"], version)
check("the extractor writes the version the schema is", owasp2json.SCHEMA_VERSION, version)
pinned = {int(v): digest for v, digest in checksums.items()}
check("the schema's version is the newest one pinned", max(pinned), version)
check("and its content is what was pinned for it: change the schema, raise "
      "schema_version in the schema and in owasp2json.py, pin the new digest "
      "in schema/checksums.json",
      schema_digest(schema), pinned[version])

print("the schema refuses what it should")
good = one_rule()
check("the control: a real rule is accepted", errors(wrapped(good)), [])

for field in ("operator", "variables", "chain", "score", "phase", "directive", "category"):
    broken = {k: v for k, v in good.items() if k != field}
    check(f"a rule without {field!r}", refuses(wrapped(broken), field))

check("a field nobody documented", refuses(wrapped(one_rule(colour="red")), "colour"))
check("an operator with a field nobody documented",
      refuses(wrapped(one_rule(operator={**good["operator"], "flags": "i"})), "flags"))
check("a SecRule with no operator", refuses(wrapped(one_rule(operator=None)), "operator"))
check("a rule matched against nothing", refuses(wrapped(one_rule(variables=[])), "variables"))
check("a variable that does not say whether it is excluded",
      refuses(wrapped(one_rule(variables=[{"name": "ARGS", "selector": None, "count": False}])), "excluded"))
check("a phase that does not exist", refuses(wrapped(one_rule(phase=6)), "phase"))
check("a score in a level CRS does not have",
      refuses(wrapped(one_rule(score={**good["score"], "level": "fatal"})), "level"))
check("a severity outside high, medium and low", refuses(wrapped(one_rule(severity="critical")), "severity"))
check("an id that is neither a number nor no_id", refuses(wrapped(one_rule(id="abc")), "id"))
check("a chain position below zero",
      refuses(wrapped(one_rule(chain={"role": "head", "head": "1", "position": -1})), "position"))
check("a link that has an id of its own",
      refuses(wrapped(one_rule(chain={"role": "link", "head": "1", "position": 1})), "id"))
check("a link that carries a score",
      refuses(wrapped(one_rule(id="no_id", action=None,
                               chain={"role": "link", "head": "1", "position": 1})), "score"))

update = next(r for r in document["rules"] if r["directive"] == "SecRuleUpdateTargetById")
check("the control: a real SecRuleUpdateTargetById is accepted", errors(wrapped(update)), [])
check("an update that has an operator",
      refuses(wrapped({**update, "operator": good["operator"]}), "operator"))
check("an update that names no rule", refuses(wrapped({**update, "target_rule_id": None}), "target_rule_id"))
check("an update that has a phase", refuses(wrapped({**update, "phase": 2}), "phase"))

check("a document of another version", refuses(wrapped(good, schema_version=1), "schema_version"))
check("a document without provenance",
      refuses({k: v for k, v in wrapped(good).items() if k != "_provenance"}, "_provenance"))
check("a document without the score defaults",
      refuses({k: v for k, v in wrapped(good).items() if k != "score_defaults"}, "score_defaults"))

print("the phrase lists")
check("a document without data_files",
      refuses({k: v for k, v in wrapped(good).items() if k != "data_files"}, "data_files"))
check("a phrase list that is not a list of strings",
      refuses(wrapped(good, data_files={"x.data": "word"}), "data_files"))
check("an empty phrase",
      refuses(wrapped(good, data_files={"x.data": ["a", ""]}), "data_files"))
check("a phrase twice",
      refuses(wrapped(good, data_files={"x.data": ["a", "a"]}), "data_files"))
check("the control: a list of phrases is accepted", errors(wrapped(good, data_files={"x.data": ["a", "b"]})), [])
named = sorted({r["operator"]["argument"] for r in document["rules"]
                if r["operator"] and r["operator"]["name"] == "pmFromFile"})
check("every file an @pmFromFile rule reads is in data_files", [n for n in named if n not in document["data_files"]], [])
check("and every file in data_files is read by one", sorted(set(document["data_files"]) - set(named)), [])
check("a phrase is not a comment, and has no blank space at either end",
      [(n, p) for n, ps in document["data_files"].items() for p in ps if p.startswith("#") or p != p.strip()], [])
check("a list that is empty is a list nobody can use",
      sorted(n for n, ps in document["data_files"].items() if not ps), [])
check("a score default for a level that does not exist",
      refuses(wrapped(good, score_defaults={"fatal": 9}), "fatal"))

print("what the schema cannot say")
rules = document["rules"]

heads = {}
broken_chains = []
open_chain = None
for position, rule in enumerate(rules):
    chain = rule["chain"]
    if chain is None:
        open_chain = None
        continue
    if chain["role"] == "head":
        heads[chain["head"]] = position
        open_chain = {"head": chain["head"], "next": 1}
        if chain["head"] != rule["id"] or chain["position"] != 0:
            broken_chains.append(f"{rule['id']}: a head that is not itself")
        continue
    if not open_chain or open_chain["head"] != chain["head"] or chain["position"] != open_chain["next"]:
        broken_chains.append(f"link at {position}: does not continue {chain['head']}")
        continue
    open_chain["next"] += 1
check("every link follows its head, without a gap, in position order", broken_chains, [])

by_id = {r["id"]: r for r in rules if r["chain"] is None or r["chain"]["role"] == "head"}
check("a link runs in its head's phase",
      [r["id"] for r in rules
       if r["chain"] and r["chain"]["role"] == "link"
       and r["phase"] != by_id[r["chain"]["head"]]["phase"]], [])
check("every rule that is not an update has a phase",
      [r["id"] for r in rules if r["directive"] == "SecRule" and r["phase"] is None], [])

seen = {}
for rule in rules:
    if rule["id"] != "no_id":
        seen[rule["id"]] = seen.get(rule["id"], 0) + 1
check("a rule id appears once", sorted(i for i, n in seen.items() if n > 1), [])
check("an update names a rule that is in the file",
      sorted({r["target_rule_id"] for r in rules
              if r["directive"] == "SecRuleUpdateTargetById"} - set(seen)), [])
check("every anomaly level a rule adds has a weight",
      sorted({r["score"]["level"] for r in rules if r["score"]} - set(document["score_defaults"])), [])


def spelled(rule):
    """The operator string as the converters read it, from the new fields."""
    op = rule["operator"]
    negation = "!" if op["negated"] else ""
    explicit = f"{negation}@{op['name']}" + (f" {op['argument']}" if op["argument"] else "")
    bare = f"{negation}{op['argument']}" if op["name"] == "rx" else None
    # `pattern` has had its doubled backslashes folded to one; `argument` has not.
    return {s.replace("\\\\", "\\") for s in (explicit, bare) if s is not None}


check("pattern and operator say the same thing",
      [r["id"] for r in rules if r["directive"] == "SecRule" and r["pattern"] not in spelled(r)], [])
check("severity is crs_severity folded into high, medium and low",
      [r["id"] for r in rules
       if r["directive"] == "SecRule"
       and r["severity"] != owasp2json._SEVERITY_MAP.get((r["crs_severity"] or "").upper(), "medium")], [])

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
