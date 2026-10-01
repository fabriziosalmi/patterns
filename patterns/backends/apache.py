"""
The Apache target: ModSecurity rules.

The CRS is written in ModSecurity's own language, so this target is the one that
can keep what a rule says. It did not. It read the legacy `pattern` string, ran
`re.escape` over it and wrote the result as the regular expression: `@lt 1`
became the pattern `\\@lt\\ 1`, and ModSecurity refused the file with
`Failed to resolve operator: lt\\\\` (#55). The same line was written for the 54
records that are not rules, and for every link of a chain on its own.

A rule is now written when it is something this target can express and refuse
with, and it is written as it was read:

  * `@rx`, not negated, with the argument as CRS wrote it. The IR keeps it as it
    stands between the quotes, which is also how it is written back, so Apache
    reads it as it read CRS. `(?i)` stays, because PCRE has it.
  * `t:lowercase` when the rule declares it. The other transformations are not
    applied and the matrix says which, rule by rule: what is written is `t:none`
    and the one it can check against the corpus.
  * the variable the rule's location is, one of those the corpus can say is
    ordinary. ARGS holds decoded values, not the raw query string nginx's `$args`
    is, and is checked as such.
  * a rule that refuses, `deny,status:403`, when its severity is `high`, and
    `pass,log` otherwise: ModSecurity can record, so the rules below `high` are
    in the output and in the log, as they are in nginx's maps.
  * an id of its own. CRS rule N is written as `9000000 + N`: unique, never the
    id of a CRS someone has installed (900000 to 999999), and the log says which
    rule it was.

The generated files do not say `SecRuleEngine`. docs/apache.md tells people to run
`DetectionOnly` first, and a file that says `On` takes that away.
"""

import logging
from collections import defaultdict
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from patterns import dialects
from patterns.backends import Backend, Capabilities, Compiled, Decision, Target, register
from patterns.backends._common import ascii_lower, modsecurity_unquote, operator_of, provenance_header
from patterns.corpus import arguments, first_ordinary_match
from patterns.ir import IR

logger = logging.getLogger(__name__)

# CRS rule N is written as ID_OFFSET + N.
ID_OFFSET = 9_000_000

# The bad-bot list (badbots.py) is written as rules too, and its ids start here: the
# n-th entry is rule BOT_ID_OFFSET + n. The ids of a release are not those of the next:
# the list changes every night.
BOT_ID_OFFSET = 8_000_000

# The rules that refuse, what they refuse with, and what the others do.
BLOCK = "deny,status:403,log"
RECORD = "pass,log"

# The ModSecurity severity names, by the three levels the IR folds them to.
SEVERITY = {"high": "CRITICAL", "medium": "WARNING", "low": "NOTICE"}

BLOCKING_ACTIONS = ("block", "deny", "drop")


def _path(entry: Dict[str, str]) -> List[str]:
    """REQUEST_FILENAME: the path, decoded, without the query string."""
    import urllib.parse
    return [urllib.parse.unquote(entry["path"])]


# Where each location is matched: the variable, and what the corpus has for it. A
# location is here only if both are: a rule is not written on a variable that nothing
# says is ordinary.
LOCATIONS: Dict[str, Tuple[str, str, Optional[Callable]]] = {
    "request-uri": ("REQUEST_URI", "request_uri", None),
    "query-string": ("ARGS", "args", arguments),
    "request-filename": ("REQUEST_FILENAME", "path", _path),
    "user-agent": ("REQUEST_HEADERS:User-Agent", "user_agent", None),
    "host": ("REQUEST_HEADERS:Host", "host", None),
    "referer": ("REQUEST_HEADERS:Referer", "referer", None),
    "content-type": ("REQUEST_HEADERS:Content-Type", "content_type", None),
}


def blocks(rule: Dict) -> bool:
    """
    Whether a rule refuses the request. One with no disruptive action inherits `pass`.

    A document that predates the field has none, and its rules are kept: an absent field
    is not evidence of `pass`.
    """
    return "action" not in rule or rule["action"] in BLOCKING_ACTIONS


def _write(index: int, rule: Dict) -> Tuple[Decision, Optional[str]]:
    """
    Decides what to do with one record, and writes the directive if it is written.

    Returns:
        The decision, and the `SecRule` text (None when the rule is not written).
    """
    directive = rule.get("directive", "SecRule")
    if directive != "SecRule":
        return Decision(index, False, "not-a-rule", f"{directive} {rule.get('target_rule_id')}"), None

    operator = operator_of(rule)
    if operator["negated"] or operator["name"] != "rx":
        name = ("!" if operator["negated"] else "") + "@" + operator["name"]
        return Decision(index, False, "operator-unsupported", name), None

    argument = operator["argument"]
    expression = modsecurity_unquote(argument)
    problem = dialects.check(Apache.capabilities.dialect, expression)
    if problem:
        return Decision(index, False, "invalid-regex", problem), None

    location = rule.get("location", "request-uri").lower()
    if location not in LOCATIONS:
        return Decision(index, False, "location-unsupported", location), None

    if not blocks(rule):
        return Decision(index, False, "not-blocking", str(rule.get("action"))), None

    rule_id = str(rule.get("id", "no_id"))
    if not rule_id.isdigit():
        return Decision(index, False, "not-a-rule", "it has no id"), None

    variable, field, view = LOCATIONS[location]
    lowered = "lowercase" in (rule.get("transformations") or [])
    values = view or (lambda entry: [entry[field]])
    seen = (lambda entry: [ascii_lower(v) for v in values(entry)]) if lowered else values
    ordinary = first_ordinary_match(expression, field, False, seen)
    if ordinary is not None:
        return Decision(index, False, "matches-benign-traffic", ordinary), None

    severity = rule.get("severity", "medium")
    transformations = "t:none" + (",t:lowercase" if lowered else "")
    category = rule.get("category", "generic").upper()
    text = (f'SecRule {variable} "@rx {argument}" '
            f'"id:{ID_OFFSET + int(rule_id)},phase:{rule.get("phase") or 2},{transformations},'
            f'{BLOCK if severity == "high" else RECORD},'
            f"msg:'{category}, CRS {rule_id}',"
            f"severity:'{rule.get('crs_severity') or SEVERITY.get(severity, 'WARNING')}'\"\n")
    return Decision(index, True, location=location, pattern=argument), text


def generate_apache_waf(rules: List[Dict], crs_ref: str = "latest") -> Compiled:
    """Builds the ModSecurity configuration, one file for each category of CRS."""
    decisions: List[Decision] = []
    # Rules by category, in the order of the IR, which is the order of CRS.
    categorized: Dict[str, List[str]] = defaultdict(list)
    for index, rule in enumerate(rules):
        decision, text = _write(index, rule)
        decisions.append(decision)
        if text is not None:
            categorized[rule.get("category", "generic").lower()].append(text)

    files: Dict[str, str] = {}
    for category, written in categorized.items():
        files[f"{category}.conf"] = "".join([
            provenance_header(crs_ref, Apache.title),
            f"# ModSecurity rules for category: {category.upper()}\n",
            f"# CRS rule N is rule {ID_OFFSET} + N. `SecRuleEngine` is yours to set.\n\n",
            *written,
        ])
        logger.info(f"Generated {category}.conf ({len(written)} rules)")
    return Compiled(files, decisions)


@register
class Apache(Backend):
    name = "apache"
    title = "Apache (ModSecurity)"

    # What is written is what is declared, and tests/test_coverage.py holds one to the
    # other. ModSecurity could apply every transformation and keep every operator, and
    # this backend writes `@rx` and `t:lowercase` and nothing else yet.
    capabilities = Capabilities(
        dialect="pcre",
        operators=frozenset({"rx"}),
        transformations=frozenset({"lowercase"}),
        case_insensitive=True,
        locations={
            "request-uri": Target("REQUEST_URI"),
            "query-string": Target(
                "ARGS", "the parsed argument values: their names and the raw query string "
                        "are other variables",
                frozenset({"ARGS_NAMES", "QUERY_STRING"})),
            "request-filename": Target("REQUEST_FILENAME"),
            "user-agent": Target("REQUEST_HEADERS:User-Agent"),
            "host": Target("REQUEST_HEADERS:Host"),
            "referer": Target("REQUEST_HEADERS:Referer"),
            "content-type": Target("REQUEST_HEADERS:Content-Type"),
        },
    )

    def compile(self, ir: IR) -> Compiled:
        return generate_apache_waf(ir.rules, ir.crs_ref)
