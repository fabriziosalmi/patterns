import json
import os
import re
import logging
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from functools import lru_cache
from collections import defaultdict  # Import defaultdict

# --- Configuration ---
LOG_LEVEL = logging.INFO  # Adjust as needed (DEBUG, INFO, WARNING, ERROR)
INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/apache"))

# ModSecurity Rule Templates (more flexible)
MODSEC_RULE_TEMPLATE = (
    'SecRule {variables} "{pattern}" '
    '"id:{rule_id},phase:{phase},t:none,{actions},msg:\'{category} attack detected\',severity:{severity}"\n'
)
# Default Actions
DEFAULT_ACTIONS = "deny,status:403,log"

# Unsupported ModSecurity directives (expand as needed)
UNSUPPORTED_PATTERNS = [
    "@pmFromFile",  # File lookups not directly supported
    # You might handle some of these with ctl:ruleRemoveTargetById later
]
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

# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Utility Functions ---
@lru_cache(maxsize=None)
def validate_regex(pattern: str) -> bool:
    """Validates a regex pattern (basic check)."""
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        logger.warning(f"Invalid regex: {pattern} - {e}")
        return False

def _sanitize_pattern(pattern: str) -> str:
    """Internal helper to perform basic pattern sanitization."""
    # Remove @rx prefix, if present
    pattern = pattern.replace("@rx ", "").strip()
    # You *could* add basic escaping here if needed, but be *very* careful
    # not to break valid regexes.  It's generally better to handle this
    # in the `owasp2json.py` script.
    return pattern

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


def generate_apache_waf(rules: List[Dict], crs_ref: str = "latest") -> None:
    """Generates Apache ModSecurity configuration files."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Use a dictionary to group rules by category.  Sets prevent duplicates.
    categorized_rules: Dict[str, Set[str]] = defaultdict(set)
    rule_id_counter = 9000000  # Start with a high ID range (OWASP CRS convention)


    for rule in rules:
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
        if any(unsupported in pattern for unsupported in UNSUPPORTED_PATTERNS):
            logger.info(f"[!] Skipping unsupported pattern: {pattern}")
            continue

        sanitized_pattern = _sanitize_pattern(pattern)
        if not sanitized_pattern or not validate_regex(sanitized_pattern):
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
        categorized_rules[category].add(rule_str)  # added into a dict


    # --- File Output ---
    # Write rules to per-category files.  This is good for organization.
    for category, rule_set in categorized_rules.items():
        output_file = OUTPUT_DIR / f"{category}.conf"
        try:
            with open(output_file, "w") as f:
                f.write(provenance_header(crs_ref))
                f.write(f"# ModSecurity Rules for Category: {category.upper()}\n")
                f.write("SecRuleEngine On\n\n")  # Enable the rule engine
                for rule in rule_set:
                    f.write(rule)
            logger.info(f"Generated {output_file} ({len(rule_set)} rules)")
        except IOError as e:
            logger.error(f"Error writing to {output_file}: {e}")
            #  Consider raising the exception here if you want the script to *stop*
            #  on any file write error.


def load_owasp_rules(file_path: Path) -> List[Dict]:
    """Loads OWASP rules from the JSON file.

    Accepts either a bare list of rule objects or the
    ``{"_provenance": ..., "rules": [...]}`` object form emitted by owasp2json.py.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, Exception) as e:
        logger.error(f"Error loading rules from {file_path}: {e}")
        raise
    if isinstance(data, dict):
        return data.get("rules", [])
    return data


def load_provenance_ref(file_path: Path) -> str:
    """Returns the CRS reference recorded in owasp_rules.json, or 'latest'."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data.get("_provenance", {}).get("source_ref", "latest")
    except Exception:
        pass
    return "latest"


def provenance_header(crs_ref: str) -> str:
    """Attribution block prepended to every generated file.

    Records that the output is a derived/converted work of the OWASP Core Rule
    Set (Apache-2.0). See THIRD_PARTY_NOTICES.md.
    """
    return (
        f"# Generated by fabriziosalmi/patterns from OWASP CoreRuleSet ({crs_ref}), "
        "Apache-2.0; converted to Apache (ModSecurity).\n"
        "# Source rules: https://github.com/coreruleset/coreruleset\n"
        "# Derived/converted work redistributed under Apache-2.0. "
        "See THIRD_PARTY_NOTICES.md.\n"
        "#\n"
    )

def main():
    """Main function."""
    try:
        rules = load_owasp_rules(INPUT_FILE)
        crs_ref = load_provenance_ref(INPUT_FILE)
        generate_apache_waf(rules, crs_ref)
        logger.info("Apache ModSecurity configuration generated successfully.")
    except Exception as e:
        logger.critical(f"Script failed: {e}")
        exit(1)

if __name__ == "__main__":
    main()
