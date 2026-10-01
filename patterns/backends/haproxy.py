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
  * `@pm` and `@pmFromFile`, as `acl x fetch -m sub -i -f file`: a substring, case ignored,
    for each line of a phrase file, which is what ModSecurity does with them (measured in
    HAProxy 3.4: ASCII is folded, other bytes are matched as they are). The files are the
    ones CRS ships, `restricted-files.data` among them, and are written next to the
    expressions; an inline `@pm` gets one of its own, `pm-<id>.data`. It is a scan of the
    list for each request, not an index: about a millisecond for the five largest lists
    on three fetches each. A phrase a pattern file cannot hold as written (one that starts
    with `#`, or with blank space, which HAProxy drops) keeps the whole rule out.
  * the fetch the rule's location is, one of those the corpus can say is ordinary.
  * only severity `high`: the rule refuses, and HAProxy has no way to write a pattern
    file that only records.

Where HAProxy has no include (it has none, and a second `-f` does not continue a
section), `waf.cfg` is pasted into the `frontend`.
"""

import logging
import re
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
    phrases_of,
    provenance_header,
)
from patterns.corpus import first_ordinary_match, first_ordinary_phrase
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


def _converters(rule: Dict, phrases: bool = False) -> List[str]:
    """
    The transformations of a rule that HAProxy has a converter for, in the rule's order.

    A phrase list is matched with `-i`, which is the case-insensitive match `@pm` always is,
    so `lowercase` has nothing to add there.
    """
    return list(dict.fromkeys(t for t in (rule.get("transformations") or [])
                              if t in CONVERTERS and not (phrases and t == "lowercase")))


def _unwritable(phrases: List[str]) -> Optional[str]:
    """
    The first phrase a pattern file cannot hold as it is, or None.

    HAProxy skips a line that starts with `#` and drops the blank space at the start of
    one, and `-m sub` has no way to escape either, so such a phrase would be another phrase.
    """
    for phrase in phrases:
        if phrase[:1] == "#" or phrase != phrase.strip() or "\n" in phrase or "\r" in phrase:
            return phrase
    return None


def _stem(name: str) -> str:
    """A phrase file's name as part of an ACL name: `restricted-files.data` -> `restricted_files`."""
    return re.sub(r"[^A-Za-z0-9]+", "_", name[:-5] if name.endswith(".data") else name)


def _name(location: str, applied: List[str]) -> str:
    """The name of a group of rules matched the same way: `query-string-urldecode`."""
    return "-".join([location] + [CONVERTERS[t][1] for t in applied])


# What a rule that is written adds: a line of a pattern file, in the group of rules matched
# the same way, or a phrase list and the ACL that loads it.
Pattern = Tuple[str, str]               # the group, and the lines it adds
Phrases = Tuple[str, str, str, List[str]]  # the group, the ACL's name, the file's name, the phrases


def _write(index: int, rule: Dict, data_files: Dict[str, List[str]]
           ) -> Tuple[Decision, Optional[Pattern], Optional[Phrases]]:
    """
    Decides what to do with one record.

    Returns:
        The decision; for an expression the name of its group and the lines it adds to that
        group's pattern file; for a phrase list the group, the name of the ACL, the name of
        the phrase file and its phrases. A rule that is not written has none of them.
    """
    directive = rule.get("directive", "SecRule")
    if directive != "SecRule":
        return Decision(index, False, "not-a-rule", f"{directive} {rule.get('target_rule_id')}"), None, None

    chain = rule.get("chain")
    if chain:
        # A chain matches when every record does, and a record on its own is a different
        # rule: the head of 920480 is any `charset=` in a Content-Type, and the link that makes
        # it a rule (the charset is not one that is allowed) is a transaction variable no target
        # has. Written alone it refused `application/json; charset=utf-8`, in all four targets.
        return Decision(index, False, "chain-unsupported", f"{chain['role']} of {chain['head']}"), None, None

    operator = operator_of(rule)
    phrases = phrases_of(operator, data_files)
    expression = None
    if phrases is not None:
        if not phrases:
            return Decision(index, False, "empty-pattern", "the phrase list has no phrases"), None, None
        odd = _unwritable(phrases)
        if odd is not None:
            return (Decision(index, False, "invalid-regex",
                             f"a pattern file cannot hold the phrase {odd[:40]!r} as it is"), None, None)
    elif operator["negated"] or operator["name"] != "rx":
        name = ("!" if operator["negated"] else "") + "@" + operator["name"]
        detail = (f"{name} (the IR has no such phrase list)"
                  if operator["name"] == "pmFromFile" and not operator["negated"] else name)
        return Decision(index, False, "operator-unsupported", detail), None, None
    else:
        expression = modsecurity_unquote(operator["argument"])
        if not expression:
            return Decision(index, False, "empty-pattern", "nothing is left of the pattern"), None, None
        if "\n" in expression or "\r" in expression:
            return Decision(index, False, "invalid-regex", "a pattern file holds a line to a pattern"), None, None
        problem = dialects.check(HAProxy.capabilities.dialect, expression)
        if problem:
            return Decision(index, False, "invalid-regex", problem), None, None

    location = rule.get("location", "request-uri").lower()
    if location not in LOCATIONS:
        return Decision(index, False, "location-unsupported", location), None, None

    if not blocks(rule):
        return Decision(index, False, "not-blocking", str(rule.get("action"))), None, None

    severity = rule.get("severity", "medium")
    if severity != "high":
        return Decision(index, False, "severity-below-blocking", severity), None, None

    fetch, field = LOCATIONS[location]
    applied = _converters(rule, phrases is not None)

    def seen(entry: Dict[str, str]) -> List[str]:
        value = entry[field]
        for transformation in applied:
            value = CONVERTERS[transformation][2](value)
        return [value]

    if phrases is not None:
        ordinary = first_ordinary_phrase(phrases, field, seen)
    else:
        ordinary = first_ordinary_match(expression, field, False, seen)
    if ordinary is not None:
        return Decision(index, False, "matches-benign-traffic", ordinary), None, None

    group = _name(location, applied)
    if phrases is not None:
        rule_id = str(rule.get("id", "no_id"))
        name = (operator["argument"].strip() if operator["name"] == "pmFromFile"
                else f"pm-{rule_id if rule_id.isdigit() else 'i' + str(index)}.data")
        return (Decision(index, True, location=location), None,
                (group, f"{_acl_name(group)}_{_stem(name)}", name, phrases))

    category = rule.get("category", "generic").lower()
    lines = f"# CRS {rule.get('id', 'no_id')} ({category})\n{haproxy_pattern(expression)}\n"
    return Decision(index, True, location=location, pattern=expression), (group, lines), None


def _acl_name(group: str) -> str:
    return "waf_" + group.replace("-", "_")


def _fetch(location: str, applied: List[str]) -> str:
    """The sample expression a group is matched on: the fetch, then its converters."""
    return ",".join([LOCATIONS[location][0]] + [CONVERTERS[t][0] for t in applied])


def generate_haproxy_waf(rules: List[Dict], crs_ref: str = "latest",
                         data_files: Optional[Dict[str, List[str]]] = None) -> Compiled:
    """Builds the pattern files, the phrase files and `waf.cfg`."""
    data_files = data_files or {}
    decisions: List[Decision] = []
    groups: Dict[str, List[str]] = defaultdict(list)
    fetches: Dict[str, str] = {}
    # The ACLs that load a phrase file: name -> (the sample expression, the file).
    lists: Dict[str, Tuple[str, str]] = {}
    shipped: Dict[str, List[str]] = {}

    for index, rule in enumerate(rules):
        decision, written, phrase_list = _write(index, rule, data_files)
        decisions.append(decision)
        if written is not None:
            group, lines = written
            groups[group].append(lines)
            fetches[group] = _fetch(decision.location, _converters(rule))
        if phrase_list is not None:
            group, acl, name, phrases = phrase_list
            lists[acl] = (_fetch(decision.location, _converters(rule, True)), name)
            shipped[name] = phrases

    files: Dict[str, str] = {}
    header = provenance_header(crs_ref, HAProxy.title)
    for group in sorted(groups):
        files[f"waf-{group}.acl"] = "".join([
            header,
            f"# A pattern file: one regular expression to a line, matched on `{fetches[group]}`.\n",
            f"# Loaded by `acl {_acl_name(group)}` in waf.cfg.\n\n",
            *groups[group],
        ])
    # The phrase files, as CRS ships them: one phrase to a line. HAProxy skips the comment lines.
    for name in sorted(shipped):
        files[name] = "".join([
            header,
            "# A phrase list: one phrase to a line, each looked for in the value with case ignored\n"
            "# (`-m sub -i`), as ModSecurity's `@pm` does. Loaded by an `acl` in waf.cfg.\n\n",
            *[phrase + "\n" for phrase in shipped[name]],
        ])

    cfg = [header,
           "# Paste these lines into a `frontend` (or `listen`) section, and put the pattern files and\n"
           f"# the phrase lists in {WAF_DIR}/. HAProxy has no include, so this is not a file to load on\n"
           "# its own.\n\n"]
    for group in sorted(groups):
        cfg.append(f"acl {_acl_name(group)} {fetches[group]} -m reg -f {WAF_DIR}/waf-{group}.acl\n")
    for acl in sorted(lists):
        sample, name = lists[acl]
        cfg.append(f"acl {acl} {sample} -m sub -i -f {WAF_DIR}/{name}\n")
    names = [_acl_name(g) for g in sorted(groups)] + sorted(lists)
    if names:
        cfg.append("http-request deny deny_status 403 if " + " or ".join(names) + "\n")
    files["waf.cfg"] = "".join(cfg)
    for group in sorted(groups):
        logger.info(f"Generated waf-{group}.acl ({len(groups[group])} patterns)")
    for name in sorted(shipped):
        logger.info(f"Generated {name} ({len(shipped[name])} phrases)")
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
        operators=frozenset({"rx", "pm", "pmFromFile"}),
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
        return generate_haproxy_waf(ir.rules, ir.crs_ref, ir.data_files)
