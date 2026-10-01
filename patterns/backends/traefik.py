"""
The Traefik target: User-Agent expressions for a middleware plugin.

Traefik has no built-in middleware that matches a header against a regular
expression, so what this writes needs a plugin. The one it is written for is
`agence-gaya/traefik-plugin-blockuseragent` (Apache-2.0, in Traefik's plugin
catalog), registered under the name `blockuseragent` in the static configuration:

    experimental:
      plugins:
        blockuseragent:
          moduleName: github.com/agence-gaya/traefik-plugin-blockuseragent
          version: v0.1.8

It takes `regex`, a list of Go regular expressions, and answers 403 when the
User-Agent matches any of them (the expression is not anchored). Go's `regexp` is
RE2, which is what the dialect check here is made for.

`@pm` and `@pmFromFile` are written as one case-insensitive alternation of the
escaped phrases, `(?i)(?:a|b|...)`, an entry for each list. Measured in the real plugin
(Traefik 3.7) with the 790 phrases that CRS has for a User-Agent: an entry for each
phrase is a loop of 790 interpreted iterations and took about 1.7 ms a request more than
one entry with the same alternation, which cost nothing that could be told from the noise.

This used to write `plugin.badbot` with a `userAgent` list. No plugin by that name
takes that configuration, and the expressions were written into TOML basic strings
where a backslash starts an escape, so Traefik refused the file before it got that
far (#69). tests/test_traefik_blocking.py runs the real plugin.
"""

import logging
from typing import Dict, List, Optional, Tuple

from patterns import dialects
from patterns.backends import Backend, Capabilities, Compiled, Decision, Target, register
from patterns.backends._common import go_quote_meta, operator_of, phrases_of, provenance_header, toml_string
from patterns.corpus import first_ordinary_match, first_ordinary_phrase
from patterns.ir import IR

logger = logging.getLogger(__name__)

# The name the plugin is registered under, and what it is.
PLUGIN = "blockuseragent"
PLUGIN_MODULE = "github.com/agence-gaya/traefik-plugin-blockuseragent"
PLUGIN_VERSION = "v0.1.8"


def explain_pattern(rule: Dict) -> Tuple[Optional[str], Optional[Tuple[str, str]]]:
    """
    The regular expression a rule matches with, or why it has none.

    Only `@rx` is a regular expression. A phrase list, a comparison or a negated
    operator written as one would be an expression that means something else.

    Returns:
        (the expression, None) or (None, (reason code, detail)).
    """
    operator = operator_of(rule)
    if operator["negated"] or operator["name"] != "rx":
        name = ("!" if operator["negated"] else "") + "@" + operator["name"]
        logger.warning(f"Skipping rule {rule.get('id')}: {name} is not a regular expression")
        return None, ("operator-unsupported", name)
    if not operator["argument"]:
        return None, ("empty-pattern", "nothing is left once the operator is removed")
    return operator["argument"], None


def generate_traefik_conf(rules: List[Dict], crs_ref: str = "latest",
                          data_files: Optional[Dict[str, List[str]]] = None) -> Compiled:
    """Builds the Traefik middleware configuration (middleware.toml)."""
    data_files = data_files or {}
    decisions: List[Decision] = []
    out: List[str] = [
        provenance_header(crs_ref, Traefik.title),
        "# Needs the plugin registered as `%s` in the static configuration:\n"
        "#   experimental.plugins.%s: moduleName = \"%s\", version = \"%s\"\n"
        "# See docs/traefik.md.\n#\n" % (PLUGIN, PLUGIN, PLUGIN_MODULE, PLUGIN_VERSION),
        "[http.middlewares]\n\n",
    ]

    # Rules by category and location. The expressions of a group are a dict, not a
    # set: it drops duplicates and keeps the order they came in, where a set wrote
    # them in hash-seed order. An expression that comes from a phrase list has a comment that says
    # which; the others have None.
    categorized_rules: Dict[str, Dict[str, Dict[str, Optional[str]]]] = {}

    for index, rule in enumerate(rules):
        rule_id = rule.get("id", "no_id")
        category = rule.get("category", "generic").lower()
        location = rule.get("location", "user-agent").lower()

        # A chain matches when every record does, and one on its own is another rule.
        if rule.get("chain"):
            decisions.append(Decision(index, False, "chain-unsupported",
                                      f"{rule['chain']['role']} of {rule['chain']['head']}"))
            continue

        # The plugin sees the User-Agent header and nothing else.
        if location != "user-agent":
            decisions.append(Decision(index, False, "location-unsupported", location))
            continue

        # The plugin refuses and cannot record. nginx writes every severity and
        # refuses only on `high`, so the rules that merely note something (CRS 920330
        # is an empty User-Agent, a notice) are in its variables and not in its 403s.
        # Here a rule that is written refuses, so only `high` is written.
        severity = rule.get("severity", "medium")
        if severity != "high":
            decisions.append(Decision(index, False, "severity-below-blocking", severity))
            continue

        operator = operator_of(rule)
        phrases = phrases_of(operator, data_files)
        if phrases is None and operator["name"] == "pmFromFile" and not operator["negated"]:
            decisions.append(Decision(index, False, "operator-unsupported",
                                      "@pmFromFile (the IR has no such phrase list)"))
            continue
        if phrases is not None:
            if not phrases:
                decisions.append(Decision(index, False, "empty-pattern", "the phrase list has no phrases"))
                continue
            expression = "(?i)(?:" + "|".join(go_quote_meta(p) for p in phrases) + ")"
            problem = dialects.check(Traefik.capabilities.dialect, expression)
            if problem:
                decisions.append(Decision(index, False, "invalid-regex", problem))
                continue
            ordinary = first_ordinary_phrase(phrases, "user_agent")
            if ordinary is not None:
                logger.warning(f"Excluding rule {rule_id}: it matches an ordinary request ({ordinary})")
                decisions.append(Decision(index, False, "matches-benign-traffic", ordinary))
                continue
            what = operator["argument"].strip() if operator["name"] == "pmFromFile" else "@pm"
            note = f"CRS {rule_id}: {what}, {len(phrases)} phrase{'' if len(phrases) == 1 else 's'}"
            categorized_rules.setdefault(category, {}).setdefault(location, {}).setdefault(expression, note)
            decisions.append(Decision(index, True, location=location))
            continue

        expression, why = explain_pattern(rule)
        if not expression:
            decisions.append(Decision(index, False, *why))
            continue

        # What the plugin's engine refuses is a middleware that fails to start,
        # and with it every request through the router.
        problem = dialects.check(Traefik.capabilities.dialect, expression)
        if problem:
            logger.warning(f"Skipping rule {rule_id}: the expression {problem}")
            decisions.append(Decision(index, False, "invalid-regex", problem))
            continue

        # Measured, not assumed: a rule that refuses ordinary traffic is not written.
        ordinary = first_ordinary_match(expression, "user_agent")
        if ordinary is not None:
            logger.warning(f"Excluding rule {rule_id}: it matches an ordinary request ({ordinary})")
            decisions.append(Decision(index, False, "matches-benign-traffic", ordinary))
            continue

        categorized_rules.setdefault(category, {}).setdefault(location, {}).setdefault(expression, None)
        decisions.append(Decision(index, True, location=location, pattern=expression))

    for category, location_rules in categorized_rules.items():
        for location, expressions in location_rules.items():
            name = f"waf_{category}_{location}".replace("-", "_")
            out.append(f"[http.middlewares.{name}]\n")
            out.append(f"  [http.middlewares.{name}.plugin.{PLUGIN}]\n")
            out.append("    regex = [\n")
            for expression, note in expressions.items():
                if note:
                    out.append(f"      # {note}\n")
                out.append(f"      {toml_string(expression)},\n")
            out.append("    ]\n\n")

    return Compiled({"middleware.toml": "".join(out)}, decisions)


@register
class Traefik(Backend):
    name = "traefik"
    title = "Traefik"

    # The plugin takes a list of Go regular expressions for the User-Agent header,
    # and nothing else. `(?i)` is kept: Go honours it.
    capabilities = Capabilities(
        dialect="re2",
        operators=frozenset({"rx", "pm", "pmFromFile"}),
        transformations=frozenset(),
        case_insensitive=True,
        locations={"user-agent": Target("User-Agent header")},
    )

    def compile(self, ir: IR) -> Compiled:
        return generate_traefik_conf(ir.rules, ir.crs_ref, ir.data_files)
