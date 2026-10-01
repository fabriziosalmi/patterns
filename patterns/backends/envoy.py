"""
The Envoy target: an RBAC filter that denies, and the runtime setting it needs.

Envoy has no WAF in it, and no rule language. What it has that can refuse a request on
what it says is the RBAC HTTP filter: a list of policies, each a set of permissions (a
header, the path) that match a request, and with `action: DENY` a request that matches one
gets a 403 from Envoy itself. A header or a path can be matched against a regular
expression, in RE2. That is what is written here, with what that is:

  * A regular expression is matched against the **whole** value. Measured in Envoy 1.32:
    `union` does not match `/a?q=union+select`, and `(?s).*(?:union).*` does. So every
    expression is written between `(?s:.*)` and `(?s:.*)`, and not as `(?s).*(?:...)`: the
    flag is for the two `.*` and not for the `.` of the rule, which would be another
    expression.
  * `:path` is the path and the query string as they arrived, and nothing is decoded: not
    the query string, not `%2e` in a path. `url_path` is the path alone, also raw. So a
    rule here sees what nginx's maps see, and an attack percent-encoded passes.
  * RE2 has no lookahead, lookbehind or backreference, and Envoy refuses an expression whose
    compiled program is bigger than 100 by default, which a CRS rule is. The runtime layer
    `runtime.yaml` raises it, and Envoy does not start without it.
  * `action: DENY` has nothing that only records, so only a rule of severity `high` is
    written, as for Traefik and HAProxy.

A rule is written when it is `@rx`, not negated, not part of a chain, an RE2 expression, on
a location Envoy has and the corpus can check, and no ordinary request matches it.

  waf-rbac.yaml   the filter, as an item of `http_filters`, to put before the router
  runtime.yaml    `layered_runtime`, to merge into the bootstrap
"""

import logging
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from patterns import dialects
from patterns.backends import Backend, Capabilities, Compiled, Decision, Target, register
from patterns.backends._common import (
    modsecurity_unquote,
    operator_of,
    provenance_header,
    yaml_string,
)
from patterns.corpus import first_ordinary_match
from patterns.ir import IR

logger = logging.getLogger(__name__)

# What Envoy takes as the largest compiled RE2 program, in the runtime. Its default is 100, and
# an expression of CRS needs more: binary-searched against Envoy 1.32.13 with the rules of CRS
# v4.29.0, the largest needs 19,405. The limit is set well above that, so that a CRS refresh does
# not stop Envoy from starting, and tests/test_envoy_blocking.py is what shows it if one does.
MAX_PROGRAM_SIZE = 1_000_000
MEASURED_PROGRAM_SIZE = 19_405

BLOCKING_ACTIONS = ("block", "deny", "drop")

# What each location is matched with: how (a header, or the path alone), which header, and the
# field of the corpus that is that component. `:path` holds the query string too, so a rule on
# the query string is matched on it, and checked against the request as it was sent.
LOCATIONS: Dict[str, Tuple[str, Optional[str], str]] = {
    "request-uri": ("header", ":path", "request_uri"),
    "query-string": ("header", ":path", "request_uri"),
    "request-filename": ("url_path", None, "path"),
    "user-agent": ("header", "user-agent", "user_agent"),
    "host": ("header", ":authority", "host"),
    "referer": ("header", "referer", "referer"),
    "content-type": ("header", "content-type", "content_type"),
}

# One policy for each of these, named for what it matches.
POLICY = {"header": lambda header: header.lstrip(":"), "url_path": lambda header: "url-path"}


def blocks(rule: Dict) -> bool:
    """
    Whether a rule refuses the request. One with no disruptive action inherits `pass`.

    A document that predates the field has none, and its rules are kept.
    """
    return "action" not in rule or rule["action"] in BLOCKING_ACTIONS


def whole(expression: str, ignore_case: bool = False) -> str:
    """
    The expression Envoy is given for a pattern that is to be found anywhere in a value.

    Envoy matches a regular expression against the whole value, so the expression is put
    between two `.*`. The `s` flag is given to those and not to the pattern, which keeps
    the meaning of the `.` in it.
    """
    group = f"(?i:{expression})" if ignore_case else f"(?:{expression})"
    return f"(?s:.*){group}(?s:.*)"


def matcher(kind: str, header: Optional[str], regex: str, indent: str) -> str:
    """One permission of a policy, as the lines of YAML it is."""
    if kind == "url_path":
        return (f"{indent}- url_path:\n{indent}    path:\n{indent}      safe_regex:\n"
                f"{indent}        regex: {yaml_string(regex)}\n")
    return (f"{indent}- header:\n{indent}    name: {yaml_string(header or '')}\n"
            f"{indent}    string_match:\n{indent}      safe_regex:\n"
            f"{indent}        regex: {yaml_string(regex)}\n")


def rbac_filter(name: str, policies: Dict[str, List[Tuple[str, str]]]) -> str:
    """
    An RBAC HTTP filter that refuses what any policy matches, as an item of `http_filters`.

    Args:
        name: The name of the filter.
        policies: For each policy, its permissions: a comment that says where each one
            comes from, and the lines of YAML that are the permission.
    """
    out = [f"- name: {name}\n  typed_config:\n"
           '    "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC\n'
           "    rules:\n      action: DENY\n"]
    if not policies:
        out.append("      policies: {}\n")
        return "".join(out)
    out.append("      policies:\n")
    for policy in sorted(policies):
        out.append(f"        {policy}:\n          permissions:\n          - or_rules:\n              rules:\n")
        for comment, lines in policies[policy]:
            out.append(f"              # {comment}\n{lines}")
        out.append("          principals:\n          - any: true\n")
    return "".join(out)


def runtime_layer() -> str:
    """The `layered_runtime` that lets Envoy compile a CRS expression."""
    return ("layered_runtime:\n  layers:\n  - name: waf\n    static_layer:\n      re2:\n"
            f"        max_program_size:\n          error_level: {MAX_PROGRAM_SIZE}\n"
            f"          warn_level: {MAX_PROGRAM_SIZE}\n")


def _write(index: int, rule: Dict) -> Tuple[Decision, Optional[Tuple[str, str, str]]]:
    """
    Decides what to do with one record.

    Returns:
        The decision, and for a rule that is written its policy, a comment that says
        where it comes from, and the lines of YAML of its permission.
    """
    directive = rule.get("directive", "SecRule")
    if directive != "SecRule":
        return Decision(index, False, "not-a-rule", f"{directive} {rule.get('target_rule_id')}"), None

    chain = rule.get("chain")
    if chain:
        # A chain matches when every record does, and one on its own is another rule.
        return Decision(index, False, "chain-unsupported", f"{chain['role']} of {chain['head']}"), None

    operator = operator_of(rule)
    if operator["negated"] or operator["name"] != "rx":
        name = ("!" if operator["negated"] else "") + "@" + operator["name"]
        return Decision(index, False, "operator-unsupported", name), None

    expression = modsecurity_unquote(operator["argument"])
    if not expression:
        return Decision(index, False, "empty-pattern", "nothing is left of the pattern"), None
    if "\n" in expression or "\r" in expression:
        return Decision(index, False, "invalid-regex", "a line break in an expression"), None
    problem = dialects.check(Envoy.capabilities.dialect, expression)
    if problem:
        return Decision(index, False, "invalid-regex", problem), None

    location = rule.get("location", "request-uri").lower()
    if location not in LOCATIONS:
        return Decision(index, False, "location-unsupported", location), None

    if not blocks(rule):
        return Decision(index, False, "not-blocking", str(rule.get("action"))), None

    severity = rule.get("severity", "medium")
    if severity != "high":
        return Decision(index, False, "severity-below-blocking", severity), None

    kind, header, field = LOCATIONS[location]
    ignore_case = "lowercase" in (rule.get("transformations") or [])
    ordinary = first_ordinary_match(expression, field, ignore_case)
    if ordinary is not None:
        return Decision(index, False, "matches-benign-traffic", ordinary), None

    category = rule.get("category", "generic").lower()
    comment = f"CRS {rule.get('id', 'no_id')} ({category})"
    lines = matcher(kind, header, whole(expression, ignore_case), "              ")
    return (Decision(index, True, location=location, pattern=expression),
            (POLICY[kind](header or ""), comment, lines))


def generate_envoy_waf(rules: List[Dict], crs_ref: str = "latest") -> Compiled:
    """Builds the RBAC filter and the runtime setting."""
    decisions: List[Decision] = []
    policies: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for index, rule in enumerate(rules):
        decision, written = _write(index, rule)
        decisions.append(decision)
        if written is not None:
            policy, comment, lines = written
            policies["waf_" + policy.replace("-", "_")].append((comment, lines))

    header = provenance_header(crs_ref, Envoy.title)
    filter_text = (header
                   + "# One item of `http_filters`, before `envoy.filters.http.router`. It refuses what a\n"
                   "# policy matches with a 403, and needs the layered runtime of runtime.yaml: Envoy does\n"
                   "# not compile a CRS expression with its default limit.\n\n"
                   + rbac_filter("waf", policies))
    runtime_text = (header
                    + "# Merge this into the bootstrap. Envoy compiles an expression of RE2 program size 100 at\n"
                    "# most unless it is told otherwise, and a CRS expression is bigger.\n\n"
                    + runtime_layer())
    for policy in sorted(policies):
        logger.info(f"Generated {policy} ({len(policies[policy])} expressions)")
    return Compiled({"waf-rbac.yaml": filter_text, "runtime.yaml": runtime_text}, decisions)


@register
class Envoy(Backend):
    name = "envoy"
    title = "Envoy"

    # What is written is what is declared, and tests/test_coverage.py holds one to the other.
    # `lowercase` is written as a case-insensitive group, as nginx writes `~*`.
    capabilities = Capabilities(
        dialect="re2",
        operators=frozenset({"rx"}),
        transformations=frozenset({"lowercase"}),
        case_insensitive=True,
        locations={
            "request-uri": Target(":path", "the path and the query string as they arrived, nothing decoded"),
            "query-string": Target(
                ":path", "the path and the query string together, nothing decoded: a pattern written for "
                         "one value sees the path and the other values too; not the request body",
                frozenset({"ARGS", "ARGS_NAMES"})),
            "request-filename": Target(
                "url_path", "the path as it arrived, not decoded or normalised as ModSecurity's "
                            "REQUEST_FILENAME is", frozenset({"REQUEST_FILENAME"})),
            "user-agent": Target("user-agent"),
            "host": Target(":authority"),
            "referer": Target("referer"),
            "content-type": Target("content-type"),
        },
        faithful=modsecurity_unquote,
    )

    def compile(self, ir: IR) -> Compiled:
        return generate_envoy_waf(ir.rules, ir.crs_ref)
