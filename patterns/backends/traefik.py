import logging
import re
from typing import Dict, List, Optional, Tuple

from patterns.backends import Backend, Capabilities, Compiled, Decision, Target, register
from patterns.backends._common import (
    UNSUPPORTED_FILE_OPERATORS,
    provenance_header,
    validate_regex,
    without_handled_syntax,
)
from patterns.ir import IR

logger = logging.getLogger(__name__)

def _sanitize_pattern(pattern: str) -> str:
    """Internal helper for pattern sanitization."""
    pattern = pattern.replace("@rx ", "").strip()
    pattern = re.sub(r"\(\?i\)", "", pattern)  # Remove case-insensitive flag

    # Convert $ to \$
    pattern = pattern.replace("$", r"\$")

    # Convert { or { to {
    pattern = re.sub(r"&l(?:brace|cub);?", r"{", pattern)
    pattern = re.sub(r"&r(?:brace|cub);?", r"}", pattern)

    # Remove unnecessary \.*
    pattern = re.sub(r"\\\.\*", r"\.*", pattern)
    pattern = re.sub(r"(?<!\\)\.(?![\w])", r"\.", pattern)  # Escape dots

    # Replace non-capturing groups (?:...) with capturing groups (...)
    pattern = re.sub(r"\(\?:", "(", pattern)

    return pattern


# Operators this backend recognises as not being a regular expression. Any other
# operator that is not `@rx` is written as if it were one.
_STRING_OPERATORS = ["@streq", "@contains", "!@eq", "!@within", "@lt", "@ge", "@gt", "@eq", "@ipMatch", "@endsWith"]


def explain_pattern(pattern: str) -> Tuple[Optional[str], Optional[Tuple[str, str]]]:
    """
    Sanitizes a pattern for use with Traefik's badbot plugin, or says why not.

    Returns:
        (the expression, None) or (None, (reason code, detail)).
    """
    for unsupported in UNSUPPORTED_FILE_OPERATORS:
        if unsupported in pattern:
            logger.warning(f"Skipping unsupported pattern: {pattern}")
            return None, ("operator-unsupported", unsupported)

    # if it is not a string comparison we use regex
    for operator in _STRING_OPERATORS:
        if operator in pattern:
            return None, ("operator-unsupported", operator)
    sanitized = _sanitize_pattern(pattern) # return the regex
    if not sanitized:
        return None, ("empty-pattern", "nothing is left once the operator is removed")
    return sanitized, None


def sanitize_pattern(pattern: str) -> Optional[str]:
    """Sanitizes a pattern for use with Traefik's badbot plugin."""
    return explain_pattern(pattern)[0]


def generate_traefik_conf(rules: List[Dict], crs_ref: str = "latest") -> Compiled:
    """Builds the Traefik middleware configuration (middleware.toml)."""
    decisions: List[Decision] = []
    out: List[str] = [provenance_header(crs_ref, Traefik.title), "[http.middlewares]\n\n"]

    # Group rules by category AND location.  This is important!
    # The patterns of a group are a dict, not a set: it drops duplicates and
    # keeps the order they came in, where a set wrote them in hash-seed order.
    categorized_rules: Dict[str, Dict[str, Dict[str, None]]] = {}

    for index, rule in enumerate(rules):
        rule_id = rule.get("id", "no_id")
        category = rule.get("category", "generic").lower()
        location = rule.get("location", "user-agent").lower() # default value!
        pattern = rule["pattern"]
        severity = rule.get("severity", "medium").lower() # default

        # Sanitize, but *only* if the location is User-Agent.
        # We *don't* want to apply regexes to other locations here.
        if location == "user-agent":
            sanitized_pattern, why = explain_pattern(pattern)
            if not sanitized_pattern:
                decisions.append(Decision(index, False, *why))
                continue # skip
            if not validate_regex(sanitized_pattern):
                decisions.append(Decision(index, False, "invalid-regex", "Python's re does not compile it"))
                continue # skip
        else:
            logger.warning(f"Skipping rule with unsupported location '{location}' for Traefik: {rule_id}")
            decisions.append(Decision(index, False, "location-unsupported", location))
            continue

        # Initialize category/location if needed
        if category not in categorized_rules:
            categorized_rules[category] = {}
        if location not in categorized_rules[category]:
            categorized_rules[category][location] = {}

        # Add the *escaped* pattern to the group.
        categorized_rules[category][location][sanitized_pattern] = None
        decisions.append(Decision(index, True, location=location, pattern=sanitized_pattern))

    # Write the configuration
    for category, location_rules in categorized_rules.items():
      for location, patterns in location_rules.items():
        # Create a unique middleware name
        middleware_name = f"waf_{category}_{location}".replace("-", "_")
        out.append(f"[http.middlewares.{middleware_name}]\n")
        out.append(f"  [http.middlewares.{middleware_name}.plugin.badbot]\n")
        out.append("    userAgent = [\n")
        # Properly escape for TOML (and for regex within the string)
        for pattern in patterns:
            # No extra escape for TOML, because we write the full regex
            out.append(f'      "{pattern}",\n')
        out.append("    ]\n\n")

    return Compiled({"middleware.toml": "".join(out)}, decisions)


@register
class Traefik(Backend):
    name = "traefik"
    title = "Traefik"

    # The badbot plugin takes a list of regular expressions for the User-Agent
    # header, and nothing else. The backend removes `(?i)` and does not replace it
    # with anything, so the match is case-sensitive.
    capabilities = Capabilities(
        dialect="re2",
        operators=frozenset({"rx"}),
        transformations=frozenset(),
        case_insensitive=False,
        locations={"user-agent": Target("userAgent")},
        faithful=without_handled_syntax,
    )

    def compile(self, ir: IR) -> Compiled:
        return generate_traefik_conf(ir.rules, ir.crs_ref)
