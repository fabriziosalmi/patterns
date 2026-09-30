import logging
import re
from typing import Dict, List, Optional

from patterns.backends import Backend, register
from patterns.backends._common import (
    UNSUPPORTED_FILE_OPERATORS,
    provenance_header,
    validate_regex,
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


def sanitize_pattern(pattern: str) -> Optional[str]:
    """Sanitizes a pattern for use with Traefik's badbot plugin."""
    for unsupported in UNSUPPORTED_FILE_OPERATORS:
        if unsupported in pattern:
            logger.warning(f"Skipping unsupported pattern: {pattern}")
            return None

    # if it is not a string comparison we use regex
    if not any(op in pattern for op in ["@streq", "@contains", "!@eq", "!@within", "@lt", "@ge", "@gt", "@eq", "@ipMatch", "@endsWith"]):
      return _sanitize_pattern(pattern) # return the regex
    else: # if it is not a regex
       return None


def generate_traefik_conf(rules: List[Dict], crs_ref: str = "latest") -> Dict[str, str]:
    """Builds the Traefik middleware configuration (middleware.toml)."""
    out: List[str] = [provenance_header(crs_ref, Traefik.title), "[http.middlewares]\n\n"]

    # Group rules by category AND location.  This is important!
    # The patterns of a group are a dict, not a set: it drops duplicates and
    # keeps the order they came in, where a set wrote them in hash-seed order.
    categorized_rules: Dict[str, Dict[str, Dict[str, None]]] = {}

    for rule in rules:
        rule_id = rule.get("id", "no_id")
        category = rule.get("category", "generic").lower()
        location = rule.get("location", "user-agent").lower() # default value!
        pattern = rule["pattern"]
        severity = rule.get("severity", "medium").lower() # default

        # Sanitize, but *only* if the location is User-Agent.
        # We *don't* want to apply regexes to other locations here.
        if location == "user-agent":
            sanitized_pattern = sanitize_pattern(pattern)
            if not sanitized_pattern or not validate_regex(sanitized_pattern):
                continue # skip
        else:
            logger.warning(f"Skipping rule with unsupported location '{location}' for Traefik: {rule_id}")
            continue

        # Initialize category/location if needed
        if category not in categorized_rules:
            categorized_rules[category] = {}
        if location not in categorized_rules[category]:
            categorized_rules[category][location] = {}

        # Add the *escaped* pattern to the group.
        categorized_rules[category][location][sanitized_pattern] = None

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

    return {"middleware.toml": "".join(out)}


@register
class Traefik(Backend):
    name = "traefik"
    title = "Traefik"

    def render(self, ir: IR) -> Dict[str, str]:
        return generate_traefik_conf(ir.rules, ir.crs_ref)
