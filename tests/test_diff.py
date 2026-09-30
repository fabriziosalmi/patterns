#!/usr/bin/env python3
"""
What changed between two versions of the rules.

The rules refresh every night and nothing said what changed, so someone running
`latest` could not tell whether the rule set moved since yesterday without
unpacking two archives and reading generated configuration, in which one CRS rule
is four different texts.

This holds the comparison to what it claims. Each check builds the second version
from the first by changing one thing, and asks what the diff says:

  * nothing changed: one line, and the same every time;
  * a rule added, a rule removed, and a change to each field of the IR, one at a
    time, each found as that field and no other;
  * a record with no id is found by what it is part of, so a chain link or an
    update is not reported as changed because something was inserted before it;
  * a target that writes a rule both times has its output changed, and a target
    that starts or stops writing it has a status change, which is the one a
    person needs to read;
  * a document older than the IR is compared on what both have, and says so;
  * the Markdown lists the most and counts the rest, and changes.json has all.

Usage:
    python3 tests/test_diff.py [owasp_rules.json]
"""

import copy
import json
import logging
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from patterns import diff, ir  # noqa: E402

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


IR_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "owasp_rules.json"
OLD = ir.load(IR_FILE)


def derive(edit=None, ref="v9.9.9"):
    """A second version made from the first: a copy, changed by `edit`."""
    rules = copy.deepcopy(OLD.rules)
    if edit:
        rules = edit(rules) or rules
    return ir.IR(rules=rules, crs_ref=ref, schema_version=OLD.schema_version,
                 score_defaults=OLD.score_defaults, provenance=OLD.provenance)


def find(rules, rule_id):
    return next(r for r in rules if r["id"] == rule_id)


# The rules this is tried on are chosen from the data, not named: CRS changes
# every few weeks and the nightly build runs this against whatever it fetched.
from patterns import backends  # noqa: E402

NGINX = backends.get("nginx").compile(OLD).decisions
rules_written = [OLD.rules[d.index]["id"] for d in NGINX
                 if d.emitted and OLD.rules[d.index]["id"] != "no_id"]
# Rules nginx writes: one to change, one to remove, and more to change together.
WRITTEN, REMOVED = rules_written[0], rules_written[1]
MORE = rules_written[2:4]
# A rule nginx drops because its operator is not a regular expression.
DROPPED = next(OLD.rules[d.index]["id"] for d in NGINX
               if not d.emitted and d.reason == "operator-unsupported"
               and OLD.rules[d.index]["directive"] == "SecRule" and OLD.rules[d.index]["id"] != "no_id")
WRITTEN_BY = [n for n in backends.names()
              if any(d.emitted and OLD.rules[d.index]["id"] == WRITTEN
                     for d in backends.get(n).compile(OLD).decisions)]
NGINX_WRITTEN = len(rules_written) + sum(
    1 for d in NGINX if d.emitted and OLD.rules[d.index]["id"] == "no_id")

print("\nnothing changed")
same = diff.compare(OLD, derive(ref=OLD.crs_ref), targets=False)
check("the summary counts nothing", (same["summary"]["added"], same["summary"]["removed"],
                                     same["summary"]["changed"]), (0, 0, 0))
check("and all of it unchanged", same["summary"]["unchanged"], len(OLD.rules))
check("it says so in one line",
      diff.to_markdown(same), f"No rule changed since the previous release (CRS {OLD.crs_ref}).\n")
check("the same two files give the same JSON",
      diff.to_json(same), diff.to_json(diff.compare(OLD, derive(ref=OLD.crs_ref), targets=False)))

print("added and removed")
NEW_ID = "8000001"
extra = copy.deepcopy(find(OLD.rules, WRITTEN))
extra["id"] = NEW_ID
after = diff.compare(OLD, derive(lambda r: [x for x in r if x["id"] != REMOVED] + [extra]))
check("a rule that is there now and was not", [a["id"] for a in after["added"]], [NEW_ID])
check("and one that was and is not", [a["id"] for a in after["removed"]], [REMOVED])
check("neither is called changed", after["summary"]["changed"], 0)
check("an added rule says which targets write it", after["added"][0]["written_by"], WRITTEN_BY)
short, long = copy.deepcopy(extra), copy.deepcopy(extra)
short["id"], long["id"] = "99999", "100000"
check("ids are in numeric order, not as text: 99999 before 100000",
      [a["id"] for a in diff.compare(OLD, derive(lambda r: r + [long, short]))["added"]],
      ["99999", "100000"])

print("one field at a time")
EDITS = {
    "category": lambda r: r.update(category="OTHER"),
    "directive": lambda r: r.update(directive="SecRuleUpdateTargetById"),
    "phase": lambda r: r.update(phase=5),
    "variables": lambda r: r["variables"].append(
        {"name": "REQUEST_COOKIES", "selector": None, "count": False, "excluded": False}),
    "operator": lambda r: r.update(operator={"name": "rx", "negated": False, "argument": "changed"}),
    "transformations": lambda r: r["transformations"].append("lowercase"),
    "action": lambda r: r.update(action="pass"),
    "severity": lambda r: r.update(severity="low" if r["severity"] != "low" else "high"),
    "crs_severity": lambda r: r.update(crs_severity="NOTICE"),
    "score": lambda r: r.update(score={"direction": "outbound", "level": "notice", "paranoia_level": 4}),
    "chain": lambda r: r.update(chain={"role": "head", "head": r["id"], "position": 0}),
    "target_rule_id": lambda r: r.update(target_rule_id="1"),
}
check("every field of the IR is one the diff knows", sorted(EDITS), sorted(diff.IR_FIELDS))
for field, change in EDITS.items():
    def edit(rules, change=change):
        change(find(rules, WRITTEN))
    result = diff.compare(OLD, derive(edit), targets=False)
    check(f"{field}: found as that field and no other",
          [(c["id"], sorted(c["fields"])) for c in result["changed"]], [(WRITTEN, [field])])
was = find(OLD.rules, WRITTEN)["severity"]
now = "low" if was != "low" else "high"
check("the old and the new value are both there",
      diff.compare(OLD, derive(lambda r: find(r, WRITTEN).update(severity=now)), targets=False
                   )["changed"][0]["fields"]["severity"], {"from": was, "to": now})
check("a field that is only derived does not count",
      diff.compare(OLD, derive(lambda r: find(r, WRITTEN).update(pattern="@rx other")),
                   targets=False)["summary"]["changed"], 0)

print("a record with no id")
links = [r for r in OLD.rules if r["chain"] and r["chain"]["role"] == "link"]
check("there are links to try it on", bool(links), True)
inserted = diff.compare(OLD, derive(lambda r: [dict(extra)] + r), targets=False)
check("a rule inserted before them moves nothing: one added, none changed",
      (inserted["summary"]["added"], inserted["summary"]["changed"], inserted["summary"]["removed"]),
      (1, 0, 0))
link = links[0]
check("a link is named by its chain and position", diff.identity(link),
      f"{link['chain']['head']}+{link['chain']['position']}")
check("and labelled so a person can read it", diff.label(link),
      f"link {link['chain']['position']} of {link['chain']['head']}")
update = next(r for r in OLD.rules if r["directive"] == "SecRuleUpdateTargetById")
check("an update is named by the rule it changes and what it adds",
      diff.identity(update).startswith(f"update:{update['target_rule_id']}:"), True)


def reexclude(rules):
    next(r for r in rules if r["directive"] == "SecRuleUpdateTargetById")["variables"][0]["selector"] = "/^other/"


moved = diff.compare(OLD, derive(reexclude), targets=False)
check("an update that adds something else is another update: one removed, one added",
      (moved["summary"]["added"], moved["summary"]["removed"]), (1, 1))

print("what it does to a target")


def to_numeric(rules):
    # The backends still read `pattern`, which the IR keeps in step with `operator`.
    find(rules, WRITTEN).update(operator={"name": "lt", "negated": False, "argument": "1"},
                                pattern="@lt 1")


stopped = diff.compare(OLD, derive(to_numeric))
nginx = stopped["targets"]["nginx"]
check("nginx stops writing a rule that became a comparison",
      [(m["id"], m["to"]) for m in nginx["status_changed"]],
      [(WRITTEN, "dropped (operator-unsupported)")])
check("and writes one fewer", nginx["written"],
      {"from": NGINX_WRITTEN, "to": NGINX_WRITTEN - 1})
check("that is not called an output change", WRITTEN in nginx["output_changed"], False)
check("the markdown names it, on the target",
      f"`{WRITTEN}` on Nginx:" in diff.to_markdown(stopped), True)


def retransform(rules):
    for rule_id in (WRITTEN, DROPPED):
        find(rules, rule_id)["transformations"] = find(rules, rule_id)["transformations"] + ["lowercase"]


reworded = diff.compare(OLD, derive(retransform))
check("a change to a rule a target writes both times is an output change there",
      WRITTEN in reworded["targets"]["nginx"]["output_changed"], True)
check("and is not a status change", reworded["targets"]["nginx"]["status_changed"], [])
check("both rules changed",
      sorted(c["id"] for c in reworded["changed"]), sorted([WRITTEN, DROPPED]))
check("one a target drops both times changes nothing there",
      DROPPED in reworded["targets"]["nginx"]["output_changed"], False)
check("without the targets there is nothing about them",
      "targets" in diff.compare(OLD, derive(retransform), targets=False), False)

print("a document older than the IR")
legacy = ir.IR(rules=[{"id": r["id"], "pattern": r["pattern"], "location": r["location"],
                       "severity": r["severity"], "transformations": r["transformations"],
                       "action": r["action"], "category": r["category"]} for r in OLD.rules],
               crs_ref="v4.28.0")
versus = diff.compare(legacy, derive(lambda r: find(r, WRITTEN).update(severity=now)))
check("it is compared on what both have", versus["compared_on"], list(diff.LEGACY_FIELDS))
check("and only what changed is found", [(c["id"], sorted(c["fields"])) for c in versus["changed"]],
      [(WRITTEN, ["severity"])])
check("nothing is said about the targets, which cannot be compared", "targets" in versus, False)
check("the markdown says why", "older format" in diff.to_markdown(versus), True)

print("the text")
def change_severity(rules):
    for rule in rules:
        if rule["id"] in [WRITTEN, REMOVED, *MORE]:
            rule["severity"] = "low" if rule["severity"] != "low" else "high"


many = derive(change_severity)
text = diff.to_markdown(diff.compare(OLD, many, targets=False), limit=2)
check("it lists the most and counts the rest", "and 2 more, in `changes.json`" in text, True)
check("there were four to list", diff.compare(OLD, many, targets=False)["summary"]["changed"], 4)
check("it says which version to which", "CRS v4.29.0 to v9.9.9" in text, True)
check("a value that is a word is shown", bool(re.search(r"severity \w+ to \w+", text)), True)

print("the file")
with tempfile.TemporaryDirectory() as tmp:
    old_file = Path(tmp) / "old.json"
    new_file = Path(tmp) / "new.json"
    out = Path(tmp) / "changes.json"
    old_file.write_text(IR_FILE.read_text())
    document = json.loads(IR_FILE.read_text())
    document["_provenance"]["source_ref"] = "v9.9.9"
    document["rules"] = [r for r in document["rules"] if r["id"] != REMOVED]
    new_file.write_text(json.dumps(document))
    run = subprocess.run([sys.executable, "-W", "ignore", "-m", "patterns", "diff", str(old_file),
                          str(new_file), "--json", str(out), "--no-targets"],
                         cwd=REPO_ROOT, capture_output=True, text=True)
    check("the command succeeds and prints the summary", (run.returncode, "1 removed" in run.stdout), (0, True))
    written = json.loads(out.read_text())
    check("changes.json has the documented keys",
          sorted(written), ["added", "changed", "compared_on", "format", "from", "removed",
                            "summary", "targets", "to"])
    check("and the version of its own format", written["format"], diff.FORMAT)
    check("--no-targets leaves the targets out", written["targets"], {})
    check("one record to a line",
          out.read_text().count('\n    {"id":'), len(written["removed"]))
    missing = subprocess.run([sys.executable, "-W", "ignore", "-m", "patterns", "diff",
                              str(old_file), str(Path(tmp) / "nope.json")],
                             cwd=REPO_ROOT, capture_output=True, text=True)
    check("a file that is not there is an error, not a traceback",
          (missing.returncode, "Traceback" in missing.stderr), (1, False))

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
