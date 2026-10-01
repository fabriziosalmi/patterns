"""
The HAProxy target: pattern files, and the few lines that use them.

HAProxy's configuration has no room for a CRS rule. It was written as an `acl` line
for each rule, and no HAProxy would read the file (#67, #68): a regular expression
full of quotes is a configuration syntax error (`unmatched quote`, 32 times), a rule on
the query string was written with `url_param_reg`, which is not a fetch HAProxy has,
295 numeric comparisons were written against a location called `unknown`, and the one
`http-request deny if a or b or ...` line had hundreds of names where HAProxy takes 64.
And docs/haproxy.md told people to load it with `-f`, which takes a file of patterns, so
it was a configuration fragment documented as something else.

HAProxy takes a regular expression from a *pattern file*: `acl x fetch -m reg -f file`
reads one pattern per line, as it stands. No quoting, nothing about line length (a line
of 70,000 characters loads), and `#` in the middle of a line is part of the pattern.
That is what this writes, as the documentation always said:

  waf-<where>[-<what is applied>].acl   the expressions that are matched on the same
                                       fetch with the same converters, one to a line,
                                       each after a comment that names the CRS rule
  waf.cfg                              the `acl` lines that load them and the one
                                       `http-request deny`, to paste into a `frontend`

A rule is written when it is something this target can express and refuse with:

  * `@rx`, not negated, as the expression CRS wrote it, `(?i)` and all: it is PCRE, and
    HAProxy compiles it with PCRE2, so nothing is translated and there is no `-i` to
    approximate a flag with.
  * the converters the rule declares that HAProxy has: `t:lowercase` is `lower`, and
    `t:urlDecodeUni` is `url_dec(1)`, which decodes `%XX` and turns `+` into a space but,
    unlike ModSecurity's, not `%uXXXX`: it is applied, and not declared, so the matrix
    still says the rule is approximate. The others (`htmlEntityDecode`, `jsDecode`, ...)
    HAProxy has no converter for.
  * the fetch the rule's location is, one of those the corpus can say is ordinary.
  * only severity `high`: the rule refuses, and HAProxy has no way to write a pattern
    file that only records.

Where HAProxy has no include (it has none, and a second `-f` does not continue a
section), `waf.cfg` is pasted into the `frontend`.
"""

import logging
import urllib.parse
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Tuple

from patterns import dialects
from patterns.backends import Backend, Capabilities, Compiled, Decision, Target, register
from patterns.backends._common import (
    ascii_lower,
    haproxy_pattern,
    modsecurity_unquote,
    operator_of,
    provenance_header,
)
from patterns.corpus import first_ordinary_match
from patterns.ir import IR

logger = logging.getLogger(__name__)

# Where the pattern files are expected to be, in `waf.cfg`. HAProxy resolves a relative
# path from where it is started, which is not a thing a file can know.
WAF_DIR = "/etc/haproxy/waf"

BLOCKING_ACTIONS = ("block", "deny", "drop")

# What each location is fetched with, and the field of the corpus that is that request
# component. A location is here only if both exist.
LOCATIONS: Dict[str, Tuple[str, str]] = {
    "request-uri": ("url", "request_uri"),            # the path and the query string, as sent
    "query-string": ("query", "args"),                # the query string, as sent
    "request-filename": ("path", "path"),
    "user-agent": ("hdr(user-agent)", "user_agent"),
    "host": ("hdr(host)", "host"),
    "referer": ("hdr(referer)", "referer"),
    "content-type": ("hdr(content-type)", "content_type"),
}

# The transformations HAProxy has a converter for: the converter, what it is called in a
# file name, and what it does to a value, for the check against ordinary traffic.
CONVERTERS: Dict[str, Tuple[str, str, Callable[[str], str]]] = {
    "lowercase": ("lower", "lowercase", ascii_lower),
    "urlDecodeUni": ("url_dec(1)", "urldecode", lambda value: urllib.parse.unquote_plus(value)),
}


def blocks(rule: Dict) -> bool:
    """
    Whether a rule refuses the request. One with no disruptive action inherits `pass`.

    A document that predates the field has none, and its rules are kept.
    """
    return "action" not in rule or rule["action"] in BLOCKING_ACTIONS


def _converters(rule: Dict) -> List[str]:
    """The transformations of a rule that HAProxy has a converter for, in the rule's order."""
    return list(dict.fromkeys(t for t in (rule.get("transformations") or []) if t in CONVERTERS))


def _name(location: str, applied: List[str]) -> str:
    """The name of a group of rules matched the same way: `query-string-urldecode`."""
    return "-".join([location] + [CONVERTERS[t][1] for t in applied])


def _write(index: int, rule: Dict) -> Tuple[Decision, Optional[Tuple[str, str]]]:
    """
    Decides what to do with one record.

    Returns:
        The decision, and for a rule that is written the name of its group and the
        lines it adds to that group's pattern file (None when it is not written).
    """
    directive = rule.get("directive", "SecRule")
    if directive != "SecRule":
        return Decision(index, False, "not-a-rule", f"{directive} {rule.get('target_rule_id')}"), None

    chain = rule.get("chain")
    if chain:
        # A chain matches when every record does, and a record on its own is a different
        # rule: the head of 920480 is any `charset=` in a Content-Type, and the link that makes
        # it a rule (the charset is not one that is allowed) is a transaction variable no target
        # has. Written alone it refused `application/json; charset=utf-8`, in all four targets.
        return Decision(index, False, "chain-unsupported", f"{chain['role']} of {chain['head']}"), None

    operator = operator_of(rule)
    if operator["negated"] or operator["name"] != "rx":
        name = ("!" if operator["negated"] else "") + "@" + operator["name"]
        return Decision(index, False, "operator-unsupported", name), None

    expression = modsecurity_unquote(operator["argument"])
    if not expression:
        return Decision(index, False, "empty-pattern", "nothing is left of the pattern"), None
    if "\n" in expression or "\r" in expression:
        return Decision(index, False, "invalid-regex", "a pattern file holds a line to a pattern"), None
    problem = dialects.check(HAProxy.capabilities.dialect, expression)
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

    fetch, field = LOCATIONS[location]
    applied = _converters(rule)

    def seen(entry: Dict[str, str]) -> List[str]:
        value = entry[field]
        for transformation in applied:
            value = CONVERTERS[transformation][2](value)
        return [value]

    ordinary = first_ordinary_match(expression, field, False, seen)
    if ordinary is not None:
        return Decision(index, False, "matches-benign-traffic", ordinary), None

    category = rule.get("category", "generic").lower()
    lines = f"# CRS {rule.get('id', 'no_id')} ({category})\n{haproxy_pattern(expression)}\n"
    return Decision(index, True, location=location, pattern=expression), (_name(location, applied), lines)


def _acl_name(group: str) -> str:
    return "waf_" + group.replace("-", "_")


def _fetch(location: str, applied: List[str]) -> str:
    """The sample expression a group is matched on: the fetch, then its converters."""
    return ",".join([LOCATIONS[location][0]] + [CONVERTERS[t][0] for t in applied])


def generate_haproxy_waf(rules: List[Dict], crs_ref: str = "latest") -> Compiled:
    """Builds the pattern files and `waf.cfg`."""
    decisions: List[Decision] = []
    groups: Dict[str, List[str]] = defaultdict(list)
    fetches: Dict[str, str] = {}

    for index, rule in enumerate(rules):
        decision, written = _write(index, rule)
        decisions.append(decision)
        if written is None:
            continue
        group, lines = written
        groups[group].append(lines)
        fetches[group] = _fetch(decision.location, _converters(rule))

    files: Dict[str, str] = {}
    header = provenance_header(crs_ref, HAProxy.title)
    for group in sorted(groups):
        files[f"waf-{group}.acl"] = "".join([
            header,
            f"# A pattern file: one regular expression to a line, matched on `{fetches[group]}`.\n",
            f"# Loaded by `acl {_acl_name(group)}` in waf.cfg.\n\n",
            *groups[group],
        ])

    cfg = [header,
           "# Paste these lines into a `frontend` (or `listen`) section, and put the pattern files in\n"
           f"# {WAF_DIR}/. HAProxy has no include, so this is not a file to load on its own.\n\n"]
    for group in sorted(groups):
        cfg.append(f"acl {_acl_name(group)} {fetches[group]} -m reg -f {WAF_DIR}/waf-{group}.acl\n")
    if groups:
        cfg.append("http-request deny deny_status 403 if "
                   + " or ".join(_acl_name(g) for g in sorted(groups)) + "\n")
    files["waf.cfg"] = "".join(cfg)
    for group in sorted(groups):
        logger.info(f"Generated waf-{group}.acl ({len(groups[group])} patterns)")
    return Compiled(files, decisions)


@register
class HAProxy(Backend):
    name = "haproxy"
    title = "HAProxy"

    # What is written is what is declared, and tests/test_coverage.py holds one to the
    # other. `url_dec(1)` is applied for `urlDecodeUni` and is not declared: it does not
    # decode `%uXXXX`, which ModSecurity's does, so the matrix keeps the loss.
    capabilities = Capabilities(
        dialect="pcre",
        operators=frozenset({"rx"}),
        transformations=frozenset({"lowercase"}),
        case_insensitive=True,
        locations={
            "request-uri": Target("url", "the request URI as sent, with its query string"),
            "query-string": Target(
                "query", "the whole query string, not each parameter's value: a pattern written "
                         "for one value sees the others too; not the request body",
                frozenset({"ARGS", "ARGS_NAMES"})),
            "request-filename": Target(
                "path", "the path as sent, before the normalisation ModSecurity's "
                        "REQUEST_FILENAME has", frozenset({"REQUEST_FILENAME"})),
            "user-agent": Target("hdr(user-agent)"),
            "host": Target("hdr(host)"),
            "referer": Target("hdr(referer)"),
            "content-type": Target("hdr(content-type)"),
        },
        faithful=modsecurity_unquote,
    )

    def compile(self, ir: IR) -> Compiled:
        return generate_haproxy_waf(ir.rules, ir.crs_ref)
