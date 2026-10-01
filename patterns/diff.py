"""
What changed between two versions of the rules.

The rules refresh every night and nothing said what changed. Someone running
`latest` could not answer "did the rule set change since yesterday, and which
rules?" without unpacking two archives and comparing generated configuration,
which is noise: one CRS rule lands in four syntaxes.

This compares the IR, by rule, and then says what the change does to each target,
because two changes to the same rule are not the same event:

    a rule changed, and a target writes it both times     its output changes
    a rule changed, and a target drops it both times      nothing changes there
    a rule is written by a target now and was not before  or the other way round
                                                          a status change, and it
                                                          is the one to read

A rule is found by its id. A record that has none is found by what it is part of:
a link of a chain by the chain and its position, a `SecRuleUpdateTargetById` by
the rule it updates and what it adds.

The comparison is deterministic: the same two files give the same text, and the
same JSON, in the same order.
"""

import json
from typing import Dict, List, Optional, Tuple

from patterns import backends, coverage
from patterns.ir import IR

FORMAT = 1

# What a change to a rule can be in. Each is a field of the IR, and `pattern` and
# `location` are not here because they are derived from these.
IR_FIELDS = ("category", "directive", "phase", "variables", "operator", "transformations",
             "action", "severity", "crs_severity", "score", "chain", "target_rule_id")

# What a document that predates the IR has. Two documents of different versions
# are compared on what both have, since every rule would otherwise differ in the
# fields one of them lacks.
LEGACY_FIELDS = ("category", "pattern", "location", "severity", "transformations", "action")


def identity(rule: Dict) -> str:
    """
    What names a rule across two versions.

    Returns:
        The CRS id; for a record with none, what it is part of. Stable when the
        rules around it move.
    """
    if rule["id"] != "no_id":
        return rule["id"]
    chain = rule.get("chain")
    if chain:
        return f"{chain['head']}+{chain['position']}"
    if rule.get("directive") == "SecRuleUpdateTargetById":
        added = json.dumps(rule.get("variables"), sort_keys=True, separators=(",", ":"))
        return f"update:{rule['target_rule_id']}:{added}"
    return f"no_id:{json.dumps(rule, sort_keys=True)[:60]}"


def label(rule: Dict) -> str:
    """How a rule is named to a person."""
    chain = rule.get("chain")
    if rule["id"] == "no_id" and chain:
        return f"link {chain['position']} of {chain['head']}"
    if rule.get("directive") == "SecRuleUpdateTargetById":
        return f"update of {rule['target_rule_id']}"
    return rule["id"]


def _index(ir: IR) -> Dict[str, Tuple[int, Dict]]:
    """The records by identity, with their position."""
    found: Dict[str, Tuple[int, Dict]] = {}
    for position, rule in enumerate(ir.rules):
        key = identity(rule)
        while key in found:  # an identity that repeats is told apart, not lost
            key += "'"
        found[key] = (position, rule)
    return found


def _order(key: str):
    """Numeric ids in numeric order, then the rest."""
    head = key.split("+")[0]
    return (0, int(head), key) if head.isdigit() else (1, 0, key)


def _operator_text(operator: Optional[Dict]) -> str:
    if not operator:
        return ""
    return f"{'!' if operator['negated'] else ''}@{operator['name']} {operator['argument']}".strip()


def _short(text: str, width: int) -> str:
    return (text[:width] + "...") if len(text) > width else text


def _summary(rule: Dict) -> str:
    """One line for a rule that was added or removed."""
    return _short(_operator_text(rule.get("operator")) or rule.get("pattern", ""), 80)


def _statuses(ir: IR) -> Dict[str, Dict[str, Tuple[str, Optional[str]]]]:
    """For each target, each rule's status and, if dropped, the reason."""
    out: Dict[str, Dict[str, Tuple[str, Optional[str]]]] = {}
    for name in backends.names():
        backend = backends.get(name)
        verdicts = coverage.assess(backend, ir, backend.compile(ir))
        out[name] = {identity(ir.rules[v.index]): (v.status, v.reason) for v in verdicts}
    return out


def _data_changes(old: IR, new: IR) -> Dict:
    """
    What changed in the phrase lists the rules read.

    A phrase list can change and no rule with it: `@pmFromFile restricted-files.data` is
    the same record the day after a path is added to the file, and what a target writes
    for it is not the same. A diff of the records alone would say nothing changed.

    Returns:
        The files added and removed, and for each one whose phrases changed how many
        were added and removed and which rules read it.
    """
    readers: Dict[str, List[str]] = {}
    for rule in new.rules:
        operator = rule.get("operator")
        if operator and operator["name"] == "pmFromFile":
            readers.setdefault(operator["argument"], []).append(rule["id"])
    changed = []
    for name in sorted(set(old.data_files) & set(new.data_files)):
        before, after = set(old.data_files[name]), set(new.data_files[name])
        if before != after:
            changed.append({"name": name, "added": len(after - before), "removed": len(before - after),
                            "rules": sorted(readers.get(name, []), key=_order)})
    return {"added": sorted(set(new.data_files) - set(old.data_files)),
            "removed": sorted(set(old.data_files) - set(new.data_files)),
            "changed": changed}


def compare(old: IR, new: IR, targets: bool = True) -> Dict:
    """
    Compares two versions of the rules.

    Args:
        old: The earlier IR.
        new: The later one.
        targets: Also say what the change does to each target. This compiles both
            versions, and needs both to have the IR's fields.

    Returns:
        The change as data: a summary, the rules added, removed and changed, and
        per target what it does. See docs/api.md for the shape.
    """
    same_schema = old.schema_version is not None and old.schema_version == new.schema_version
    fields = IR_FIELDS if same_schema else LEGACY_FIELDS
    before, after = _index(old), _index(new)

    added = sorted(set(after) - set(before), key=_order)
    removed = sorted(set(before) - set(after), key=_order)
    changed = []
    for key in sorted(set(before) & set(after), key=_order):
        a, b = before[key][1], after[key][1]
        different = {f: {"from": a.get(f), "to": b.get(f)} for f in fields if a.get(f) != b.get(f)}
        if different:
            changed.append({"id": key, "label": label(b), "category": b.get("category"),
                            "fields": different})

    result: Dict = {
        "format": FORMAT,
        "from": {"source_ref": old.crs_ref, "schema_version": old.schema_version,
                 "records": len(old.rules)},
        "to": {"source_ref": new.crs_ref, "schema_version": new.schema_version,
               "records": len(new.rules)},
        "compared_on": list(fields),
        "summary": {
            "added": len(added), "removed": len(removed), "changed": len(changed),
            "unchanged": len(set(before) & set(after)) - len(changed),
            "source_ref_changed": old.crs_ref != new.crs_ref,
        },
    }

    if same_schema and (new.schema_version or 0) >= 2:
        data = _data_changes(old, new)
        result["data_files"] = data
        result["summary"]["data_files_changed"] = len(data["added"]) + len(data["removed"]) + len(data["changed"])

    statuses_old = _statuses(old) if targets and same_schema else None
    statuses_new = _statuses(new) if targets and same_schema else None

    def written_by(statuses, key):
        return [t for t in statuses if statuses[t].get(key, ("dropped",))[0] != "dropped"]

    result["added"] = [{
        "id": k, "label": label(after[k][1]), "category": after[k][1].get("category"),
        "rule": _summary(after[k][1]),
        **({"written_by": written_by(statuses_new, k)} if statuses_new else {}),
    } for k in added]
    result["removed"] = [{
        "id": k, "label": label(before[k][1]), "category": before[k][1].get("category"),
        "rule": _summary(before[k][1]),
        **({"written_by": written_by(statuses_old, k)} if statuses_old else {}),
    } for k in removed]
    result["changed"] = changed

    if statuses_old is not None:
        changed_keys = {c["id"] for c in changed}
        per_target: Dict[str, Dict] = {}
        for target in statuses_old:
            moved = []
            for key in sorted(set(before) & set(after), key=_order):
                was, now = statuses_old[target][key], statuses_new[target][key]
                if was != now:
                    moved.append({"id": key, "label": label(after[key][1]),
                                  "from": was[0] if was[1] is None else f"{was[0]} ({was[1]})",
                                  "to": now[0] if now[1] is None else f"{now[0]} ({now[1]})"})
            output_changed = [k for k in sorted(changed_keys, key=_order)
                              if statuses_old[target][k][0] != "dropped"
                              and statuses_new[target][k][0] != "dropped"]
            totals = lambda s: sum(1 for st, _ in s[target].values() if st != "dropped")  # noqa: E731
            per_target[target] = {
                "written": {"from": totals(statuses_old), "to": totals(statuses_new)},
                "output_changed": output_changed,
                "status_changed": moved,
            }
        result["targets"] = per_target
    return result


def to_json(change: Dict) -> str:
    """The change as JSON, one record to a line in each list."""
    head = {k: v for k, v in change.items() if k not in ("added", "removed", "changed", "targets")}
    lines = [f"  {json.dumps(k)}: {json.dumps(v, separators=(',', ':'))}," for k, v in head.items()]
    for key in ("added", "removed", "changed"):
        body = ",\n".join("    " + json.dumps(r, separators=(",", ":")) for r in change[key])
        lines.append(f'  "{key}": [' + (f"\n{body}\n  ]," if body else "],"))
    targets = change.get("targets", {})
    lines.append('  "targets": {' + (
        "\n" + ",\n".join(f'    {json.dumps(n)}: {json.dumps(t, separators=(",", ":"))}'
                          for n, t in targets.items()) + "\n  }" if targets else "}"))
    return "{\n" + "\n".join(lines) + "\n}\n"


def _fields_text(fields: Dict) -> str:
    """The fields that changed, with the values for the ones that are a word or a number."""
    parts = []
    for name, change in fields.items():
        a, b = change["from"], change["to"]
        if name == "operator":
            parts.append(f"operator {_short(_operator_text(a), 30)} to {_short(_operator_text(b), 30)}")
        elif isinstance(a, (str, int, type(None))) and isinstance(b, (str, int, type(None))):
            parts.append(f"{name} {a} to {b}")
        else:
            parts.append(name)
    return ", ".join(parts)


def to_markdown(change: Dict, limit: int = 25) -> str:
    """
    The change for a person: one line when nothing changed, else counts, what it
    does to each target, then the rules.

    Args:
        change: What `compare` returned.
        limit: How many rules to list under each heading. The rest are counted;
            changes.json has them all.
    """
    s = change["summary"]
    frm, to = change["from"]["source_ref"], change["to"]["source_ref"]
    moved = "" if not s["source_ref_changed"] else f": CRS {frm} to {to}"
    if not (s["added"] or s["removed"] or s["changed"] or s.get("data_files_changed")):
        return f"No rule changed since the previous release (CRS {to}).\n"

    out: List[str] = [f"**Rules{moved}.** {s['added']} added, {s['removed']} removed, "
                      f"{s['changed']} changed, {s['unchanged']} unchanged.\n"]
    if change["compared_on"] == list(LEGACY_FIELDS):
        out.append("The previous release was written in an older format, so rules were compared "
                   "on what both have, and what each target does with them is not compared.\n")

    targets = change.get("targets")
    if targets:
        out.append("| Target | Written | Output changed | Status changed |")
        out.append("|---|---:|---:|---:|")
        for name, t in targets.items():
            w = t["written"]
            written = f"{w['from']} to {w['to']}" if w["from"] != w["to"] else str(w["to"])
            out.append(f"| {backends.get(name).title} | {written} | {len(t['output_changed'])} "
                       f"| {len(t['status_changed'])} |")
        out.append("")

    def section(title: str, items: List[Dict], line) -> None:
        if not items:
            return
        out.append(f"**{title}** ({len(items)})\n")
        for item in items[:limit]:
            out.append(f"- {line(item)}")
        if len(items) > limit:
            out.append(f"- and {len(items) - limit} more, in `changes.json`")
        out.append("")

    data = change.get("data_files")
    if data and s.get("data_files_changed"):
        lines = ([f"`{n}` is new" for n in data["added"]] + [f"`{n}` is gone" for n in data["removed"]]
                 + [f"`{c['name']}`: {c['added']} added, {c['removed']} removed"
                    + (f" (read by {', '.join(c['rules'])})" if c["rules"] else "")
                    for c in data["changed"]])
        section("Phrase lists the rules read", lines, lambda text: text)

    if targets:
        rows = [(n, m) for n, t in targets.items() for m in t["status_changed"]]
        section("Written differently by a target", [dict(m, target=n) for n, m in rows],
                lambda m: f"`{m['label']}` on {backends.get(m['target']).title}: {m['from']} to {m['to']}")
    def code(text: str) -> str:
        return f"`{text.replace(chr(96), chr(39))}`"

    section("Added", change["added"], lambda r: f"`{r['label']}` ({r['category']}) {code(r['rule'])}")
    section("Removed", change["removed"], lambda r: f"`{r['label']}` ({r['category']}) {code(r['rule'])}")
    section("Changed", change["changed"],
            lambda r: f"`{r['label']}` ({r['category']}): {_fields_text(r['fields'])}")
    return "\n".join(out).rstrip("\n") + "\n"
