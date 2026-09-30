"""
The coverage matrix: what each target does with each rule of the IR.

A backend used to drop what it could not express and say so in a log line, and
what it kept, it kept as it could. Nothing said how many of the 749 rules a
target enforces, how many it enforces differently, and why the rest are gone.

Every rule gets one verdict per target:

    full         written, and it means what CRS wrote on the components the
                 target matches: the operator, the expression, the variables, the
                 transformations and the chain are all preserved
    approximate  written, with a named loss: a transformation not applied, a
                 variable not matched, a chain reduced to its first link
    unsound      written, and it cannot mean what the rule said: an operator the
                 backend cannot express written out as a pattern, an expression
                 rewritten, a link of a chain without the others
    dropped      not written, with a reason

Where a rule is dropped is decided by the backend, in the code that drops it, and
recorded there (`Decision`). Whether what was written is faithful is decided here
from what the backend declares it can express (`Capabilities`), and
tests/test_coverage.py holds the declarations to the output, so the matrix cannot
say something the files do not.

Not modelled: anomaly scoring (every backend enforces a rule alone, where CRS adds
points and refuses above a threshold), and what a rule does when it matches
(deny, log, tarpit). The README says the first, and neither changes a status.
"""

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from patterns import dialects
from patterns.backends import Backend, Compiled
from patterns.ir import IR

STATUSES = ("full", "approximate", "unsound", "dropped")

REASONS = {
    "not-a-rule": "not a rule: it changes another rule",
    "operator-unsupported": "an operator the backend cannot express",
    "location-unsupported": "matched on a request component the target does not have",
    "invalid-regex": "the expression does not compile",
    "empty-pattern": "nothing is left of the pattern",
    "not-blocking": "it records and does not refuse",
    "matches-benign-traffic": "it refuses ordinary traffic once converted",
    "parameter-too-long": "longer than the target accepts",
}

LOSSES = {
    "not-a-rule": "written although it is not a rule",
    "operator": "an operator written as something it is not",
    "regex": "the expression was rewritten",
    "chain": "a chain written without all of its links",
    "variables": "matched on other variables than the rule names",
    "transformations": "transformations the rule was written to run after are not applied",
    "flags": "case-insensitivity is not honoured",
}


@dataclass
class Loss:
    """
    What a written rule does not keep.

    Attributes:
        kind: A key of LOSSES.
        detail: What exactly, in a line.
        unsound: Whether the rule can no longer mean what it said, and not only
            less of it.
    """

    kind: str
    detail: str
    unsound: bool = False


@dataclass
class Verdict:
    """What one target did with one rule."""

    index: int
    status: str
    reason: Optional[str] = None
    detail: Optional[str] = None
    losses: List[Loss] = field(default_factory=list)


def location_of(variable: Dict) -> Optional[str]:
    """
    The location the IR's folded `location` field gives a single variable.

    This is `owasp2json._extract_rule_location` applied to one variable, which
    is how a rule's variables are related to the location a backend matched it
    on. tests/test_coverage.py checks that the two agree for every rule.

    Returns:
        A lower-case location such as `query-string`, None for a variable the
        folding does not map.
    """
    name = variable["name"].upper()
    selector = variable["selector"]
    if name.startswith("REQUEST_HEADERS"):
        if selector:
            return selector.upper().replace("_", "-").strip().lower()
        return "request_headers"
    if name.startswith("ARGS"):
        return "query-string"
    if name == "REQUEST_COOKIES":
        return "cookie"
    if name == "REQUEST_URI":
        return "request-uri"
    if name == "QUERY_STRING":
        return "query-string"
    if name == "REQUEST_METHOD":
        return "request-method"
    if name == "REQUEST_FILENAME":
        return "request-filename"
    if name in ("REQUEST_LINE", "REQUEST_BODY", "RESPONSE_BODY", "RESPONSE_HEADERS"):
        return name.lower()
    return None


def _named(variables: List[Dict]) -> str:
    return ", ".join(v["name"] + (f":{v['selector']}" if v["selector"] else "") for v in variables)


def _assess_written(backend: Backend, rule: Dict, decision, links: Dict[str, int]) -> List[Loss]:
    """The losses of a rule the backend wrote."""
    capabilities = backend.capabilities
    if rule["directive"] != "SecRule":
        return [Loss("not-a-rule", f"SecRuleUpdateTargetById {rule['target_rule_id']} changes "
                                   "that rule and is not one itself", unsound=True)]

    losses: List[Loss] = []
    operator = rule["operator"]

    # The operator.
    if operator["negated"] or operator["name"] not in capabilities.operators:
        negation = "!" if operator["negated"] else ""
        losses.append(Loss("operator", f"{negation}@{operator['name']} is not an operator "
                                       f"{backend.title} is given; it is written as a pattern",
                           unsound=True))
    elif (operator["name"] == "rx" and decision.pattern is not None
          and decision.pattern != capabilities.faithful(operator["argument"])):
        losses.append(Loss("regex", "the expression CRS wrote is not the one that was written",
                           unsound=True))

    # The chain.
    chain = rule["chain"]
    if chain and chain["role"] == "link":
        losses.append(Loss("chain", f"link {chain['position']} of the chain of {chain['head']}, "
                                    "written without the rest", unsound=True))
    elif chain:
        losses.append(Loss("chain", f"the first of {links.get(rule['id'], 0) + 1} conditions "
                                    "that must all match"))

    # The variables.
    written = capabilities.locations.get(decision.location)
    wanted = [v for v in rule["variables"] if not v["excluded"]]
    covered = [v for v in wanted if location_of(v) == decision.location]
    if any(v["count"] for v in rule["variables"]):
        losses.append(Loss("variables", "counts matching variables; the output matches their values",
                           unsound=True))
    if wanted and not covered:
        losses.append(Loss("variables", f"matched on {written.name if written else decision.location}"
                                        f", which is none of {_named(wanted)}", unsound=True))
    else:
        missing = [v for v in wanted if v not in covered]
        if missing:
            losses.append(Loss("variables", f"not matched: {_named(missing)}"))
        if written and written.note and any(v["name"].upper() in written.partial for v in covered):
            losses.append(Loss("variables", f"{written.name}: {written.note}"))
    excluded = [v for v in rule["variables"] if v["excluded"]]
    if excluded:
        losses.append(Loss("variables", f"exclusions not applied: {_named(excluded)}"))

    # The transformations.
    lost = [t for t in dict.fromkeys(rule["transformations"]) if t not in capabilities.transformations]
    if lost:
        losses.append(Loss("transformations", ", ".join(lost)))

    # Case.
    if (operator["name"] == "rx" and "(?i)" in operator["argument"]
            and not capabilities.case_insensitive):
        losses.append(Loss("flags", "(?i) is removed and nothing replaces it: the match is "
                                    "case-sensitive"))
    return losses


def assess(backend: Backend, ir: IR, compiled: Compiled) -> List[Verdict]:
    """
    Gives every rule of the IR a verdict for one target.

    Args:
        backend: The target, with its declared capabilities.
        ir: The IR the target was compiled from.
        compiled: What `backend.compile(ir)` returned.

    Returns:
        One Verdict per rule, in IR order.
    """
    links: Dict[str, int] = Counter(
        r["chain"]["head"] for r in ir.rules if r["chain"] and r["chain"]["role"] == "link")
    verdicts: List[Verdict] = []
    for decision in compiled.decisions:
        rule = ir.rules[decision.index]
        if not decision.emitted:
            if rule["directive"] != "SecRule":
                verdicts.append(Verdict(decision.index, "dropped", "not-a-rule",
                                        f"SecRuleUpdateTargetById {rule['target_rule_id']}"))
            else:
                verdicts.append(Verdict(decision.index, "dropped", decision.reason, decision.detail))
            continue
        losses = _assess_written(backend, rule, decision, links)
        status = ("unsound" if any(loss.unsound for loss in losses)
                  else "approximate" if losses else "full")
        verdicts.append(Verdict(decision.index, status, losses=losses))
    return verdicts


def dialect_problems(backend: Backend, ir: IR, compiled: Compiled) -> List[str]:
    """
    The written expressions the target's regular expression engine would refuse.

    Returns:
        One line per expression, naming the target and the rule.
    """
    problems = []
    for decision in compiled.decisions:
        if not decision.emitted or decision.pattern is None:
            continue
        message = dialects.check(backend.capabilities.dialect, decision.pattern)
        if message:
            rule = ir.rules[decision.index]
            problems.append(f"{backend.name}: rule {rule['id']} (record {decision.index}) "
                            f"{message}: {decision.pattern[:80]}")
    return problems


def report(ir: IR, results: Dict[str, Tuple[Backend, Compiled]]) -> Dict:
    """
    The matrix as data: totals per target, and a verdict per rule and target.

    Args:
        ir: The IR.
        results: Each target's backend and what it compiled, by target name.
    """
    verdicts = {name: assess(backend, ir, compiled) for name, (backend, compiled) in results.items()}

    backends: Dict[str, Dict] = {}
    for name, (backend, _) in results.items():
        mine = verdicts[name]
        backends[name] = {
            "title": backend.title,
            "dialect": backend.capabilities.dialect,
            "totals": {status: sum(1 for v in mine if v.status == status) for status in STATUSES},
            "reasons": dict(sorted(Counter(v.reason for v in mine if v.status == "dropped").items())),
            # Rules that lose something of each kind, not losses: one rule can lose
            # two variables and is still one rule.
            "losses": dict(sorted(Counter(
                kind for v in mine for kind in {loss.kind for loss in v.losses}).items())),
        }

    rules = []
    for index, rule in enumerate(ir.rules):
        entry: Dict = {"index": index, "id": rule["id"]}
        if rule["chain"]:
            entry["chain"] = f"{rule['chain']['role']} of {rule['chain']['head']}"
        if rule["directive"] != "SecRule":
            entry["directive"] = rule["directive"]
        for name in results:
            verdict = verdicts[name][index]
            cell: Dict = {"status": verdict.status}
            if verdict.reason:
                cell["reason"] = verdict.reason
                if verdict.detail:
                    cell["detail"] = verdict.detail
            if verdict.losses:
                cell["losses"] = [{"kind": loss.kind, "detail": loss.detail,
                                   **({"unsound": True} if loss.unsound else {})}
                                  for loss in verdict.losses]
            entry[name] = cell
        rules.append(entry)

    return {
        "format": 1,
        "source_ref": ir.crs_ref,
        "schema_version": ir.schema_version,
        "statuses": list(STATUSES),
        "reasons": REASONS,
        "losses": LOSSES,
        "backends": backends,
        "rules": rules,
    }


def to_json(data: Dict) -> str:
    """
    Serialises a report with one rule to a line, so a diff reads rule by rule.
    """
    rules = data["rules"]
    head = {key: value for key, value in data.items() if key != "rules"}
    lines = [f"  {json.dumps(key)}: {json.dumps(value, separators=(',', ':'))}," for key, value in head.items()]
    body = ",\n".join("    " + json.dumps(rule, separators=(",", ":")) for rule in rules)
    return "{\n" + "\n".join(lines) + '\n  "rules": [\n' + body + "\n  ]\n}\n"


def to_markdown(data: Dict) -> str:
    """The matrix as Markdown: totals per target, then why rules are dropped, then what is lost."""
    names = list(data["backends"])
    total = len(data["rules"])
    out: List[str] = []

    out.append(f"Of the {total} records in the CRS {data['source_ref']} intermediate representation, "
               "what each target does:\n")
    out.append("| Target | Full | Approximate | Unsound | Dropped |")
    out.append("|---|---:|---:|---:|---:|")
    for name in names:
        b = data["backends"][name]
        t = b["totals"]
        out.append(f"| {b['title']} | {t['full']} | {t['approximate']} | {t['unsound']} | {t['dropped']} |")

    out.append("\n**Why a record is dropped**, by the first reason the backend found:\n")
    out.append("| Reason | " + " | ".join(data["backends"][n]["title"] for n in names) + " |")
    out.append("|---|" + "---:|" * len(names))
    for reason in sorted(data["reasons"], key=lambda r: -sum(data["backends"][n]["reasons"].get(r, 0) for n in names)):
        counts = [data["backends"][n]["reasons"].get(reason, 0) for n in names]
        if any(counts):
            out.append(f"| {data['reasons'][reason]} | " + " | ".join(str(c) if c else "" for c in counts) + " |")

    out.append("\n**What a written rule loses**, in how many of them:\n")
    out.append("| Loss | " + " | ".join(data["backends"][n]["title"] for n in names) + " |")
    out.append("|---|" + "---:|" * len(names))
    for kind in sorted(data["losses"], key=lambda k: -sum(data["backends"][n]["losses"].get(k, 0) for n in names)):
        counts = [data["backends"][n]["losses"].get(kind, 0) for n in names]
        if any(counts):
            out.append(f"| {data['losses'][kind]} | " + " | ".join(str(c) if c else "" for c in counts) + " |")
    return "\n".join(out) + "\n"
