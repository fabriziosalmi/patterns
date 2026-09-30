import logging
import re
from collections import defaultdict
from typing import Dict, List

from patterns.backends import Backend, Capabilities, Compiled, Decision, Target, register
from patterns.backends._common import (
    UNSUPPORTED_FILE_OPERATORS,
    provenance_header,
    validate_regex,
)
from patterns.ir import IR

logger = logging.getLogger(__name__)

# ModSecurity Rule Templates (more flexible)
MODSEC_RULE_TEMPLATE = (
    'SecRule {variables} "{pattern}" '
    '"id:{rule_id},phase:{phase},t:none,{actions},msg:\'{category} attack detected\',severity:{severity}"\n'
)
# Default Actions
DEFAULT_ACTIONS = "deny,status:403,log"

# Supported ModSecurity operators and their rough translations (for logging/info)
SUPPORTED_OPERATORS = {
    "@rx": "Regular Expression",
    "@streq": "String Equals",
    "@contains": "Contains String",
    "@beginsWith": "Begins With",
    "@endsWith": "Ends With",
    "@within": "Contained Within",
    "@ipMatch": "IP Address Match",
    # ... add more as needed
}


# --- Utility Functions ---
def _sanitize_pattern(pattern: str) -> str:
    """Internal helper to perform basic pattern sanitization."""
    # Remove @rx prefix, if present
    pattern = pattern.replace("@rx ", "").strip()
    # You *could* add basic escaping here if needed, but be *very* careful
    # not to break valid regexes.  It's generally better to handle this
    # in the `owasp2json.py` script.
    return pattern

# The locations _determine_variables knows. Any other is matched on REQUEST_URI.
_LOCATIONS = ("request-uri", "query-string", "user-agent", "host", "referer", "content-type")


def _determine_variables(location: str) -> str:
    """Maps the 'location' field to ModSecurity variables."""
    location = location.lower()  # Normalize to lowercase
    if location == "request-uri":
        return "REQUEST_URI"
    elif location == "query-string":
        return "ARGS"  # Or ARGS_GET, depending on your needs
    elif location == "user-agent":
        return "REQUEST_HEADERS:User-Agent"
    elif location == "host":
        return "REQUEST_HEADERS:Host"
    elif location == "referer":
        return "REQUEST_HEADERS:Referer"
    elif location == "content-type":
        return "REQUEST_HEADERS:Content-Type"
    # Add other location mappings as needed
    else:
        logger.warning(f"Unknown location '{location}', defaulting to REQUEST_URI")
        return "REQUEST_URI"  # Default variable


def generate_apache_waf(rules: List[Dict], crs_ref: str = "latest") -> Compiled:
    """Builds the Apache ModSecurity configuration files, one per category."""
    decisions: List[Decision] = []

    # Rules grouped by category. A dict keeps what was added in the order it was
    # added and still drops duplicates. A set did the second and not the first,
    # so the order of a file followed the hash seed of the run that wrote it.
    categorized_rules: Dict[str, Dict[str, None]] = defaultdict(dict)
    rule_id_counter = 9000000  # Start with a high ID range (OWASP CRS convention)


    for index, rule in enumerate(rules):
        rule_id = rule.get("id", "no_id")  # Get rule ID
        if not isinstance(rule_id, int):  # check if is an int
            # Extract ID from rule and convert to an integer
            match = re.search(r'id:(\d+)', rule_id)
            if match:
                try:
                    rule_id = int(match.group(1))
                except ValueError:
                    logger.warning(f"Invalid rule ID '{match.group(1)}' in rule: {rule}. Using generated ID.")
                    rule_id = rule_id_counter
                    rule_id_counter += 1
            else:
                rule_id = rule_id_counter
                rule_id_counter += 1

        category = rule.get("category", "generic").lower()
        pattern = rule["pattern"]
        location = rule.get("location", "REQUEST_URI")  # Set a default variable
        severity = rule.get("severity", "CRITICAL").upper()  # CRITICAL, ERROR, WARNING, NOTICE
        # --- Operator Handling ---
        operator_used = "Unknown"  # Default
        for op in SUPPORTED_OPERATORS:
            if pattern.startswith(op):
                operator_used = SUPPORTED_OPERATORS[op]
                break  # Stop after finding the *first* matching operator

        # Skip unsupported patterns.
        unsupported = [op for op in UNSUPPORTED_FILE_OPERATORS if op in pattern]
        if unsupported:
            logger.info(f"[!] Skipping unsupported pattern: {pattern}")
            decisions.append(Decision(index, False, "operator-unsupported", unsupported[0]))
            continue

        sanitized_pattern = _sanitize_pattern(pattern)
        if not sanitized_pattern:
            decisions.append(Decision(index, False, "empty-pattern",
                                      "nothing is left once the operator is removed"))
            continue
        if not validate_regex(sanitized_pattern):
            decisions.append(Decision(index, False, "invalid-regex", "Python's re does not compile it"))
            continue  # Skip invalid regexes

        # Determine ModSecurity variables based on 'location'
        variables = _determine_variables(location)

        # --- Rule Construction ---
        # Build the ModSecurity rule string
        rule_str = MODSEC_RULE_TEMPLATE.format(
            variables=variables,
            pattern=re.escape(sanitized_pattern),  # Escape for ModSecurity
            rule_id=rule_id,
            category=category.upper(),  # Use uppercase for category
            severity=severity,
            phase=2,  # Phase 2 (request body processing) is common, adjust if needed
            actions=DEFAULT_ACTIONS,
        )
        categorized_rules[category][rule_str] = None
        # A location the backend does not know is matched on REQUEST_URI.
        decisions.append(Decision(
            index, True,
            location=location.lower() if location.lower() in _LOCATIONS else "request-uri",
            pattern=re.escape(sanitized_pattern)))


    # --- Files ---
    # Rules go to per-category files.  This is good for organization.
    files: Dict[str, str] = {}
    for category, rule_set in categorized_rules.items():
        files[f"{category}.conf"] = "".join([
            provenance_header(crs_ref, Apache.title),
            f"# ModSecurity Rules for Category: {category.upper()}\n",
            "SecRuleEngine On\n\n",  # Enable the rule engine
            *rule_set,
        ])
        logger.info(f"Generated {category}.conf ({len(rule_set)} rules)")
    return Compiled(files, decisions)


@register
class Apache(Backend):
    name = "apache"
    title = "Apache (ModSecurity)"

    # ModSecurity can apply transformations and keeps the operator, and this
    # backend writes neither: `t:none`, and the pattern escaped into a literal.
    capabilities = Capabilities(
        dialect="pcre",
        operators=frozenset({"rx"}),
        transformations=frozenset(),
        case_insensitive=True,
        locations={
            "request-uri": Target("REQUEST_URI"),
            "query-string": Target(
                "ARGS", "the parsed argument values: their names and the raw query string "
                        "are other variables",
                frozenset({"ARGS_NAMES", "QUERY_STRING"})),
            "user-agent": Target("REQUEST_HEADERS:User-Agent"),
            "host": Target("REQUEST_HEADERS:Host"),
            "referer": Target("REQUEST_HEADERS:Referer"),
            "content-type": Target("REQUEST_HEADERS:Content-Type"),
        },
    )

    def compile(self, ir: IR) -> Compiled:
        return generate_apache_waf(ir.rules, ir.crs_ref)
