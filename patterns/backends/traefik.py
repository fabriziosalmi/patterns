import os
import json
import re
import logging
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from functools import lru_cache

# --- Configuration ---
LOG_LEVEL = logging.INFO  # DEBUG, INFO, WARNING, ERROR
INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/traefik"))
MIDDLEWARE_FILE = OUTPUT_DIR / "middleware.toml"

# Unsupported patterns (for Traefik's badbot plugin, which uses regex)
UNSUPPORTED_PATTERNS = [
    "@pmFromFile",  # No file lookups
    # Add other unsupported operators/patterns here.
]

# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

@lru_cache(maxsize=256)
def validate_regex(pattern: str) -> bool:
    """Validates a regex pattern."""
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        logger.warning(f"Invalid regex: {pattern} - {e}")
        return False

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
    for unsupported in UNSUPPORTED_PATTERNS:
        if unsupported in pattern:
            logger.warning(f"Skipping unsupported pattern: {pattern}")
            return None

    # if it is not a string comparison we use regex
    if not any(op in pattern for op in ["@streq", "@contains", "!@eq", "!@within", "@lt", "@ge", "@gt", "@eq", "@ipMatch", "@endsWith"]):
      return _sanitize_pattern(pattern) # return the regex
    else: # if it is not a regex
       return None


def generate_traefik_conf(rules: List[Dict], crs_ref: str = "latest") -> None:
    """Generates the Traefik middleware configuration (middleware.toml)."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with open(MIDDLEWARE_FILE, "w", encoding="utf-8") as f:
            f.write(provenance_header(crs_ref))
            f.write("[http.middlewares]\n\n")

            # Group rules by category AND location.  This is important!
            categorized_rules: Dict[str, Dict[str, Set[str]]] = {}

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
                    categorized_rules[category][location] = set()  # Use a set

                # Add the *escaped* pattern to the set.
                categorized_rules[category][location].add(sanitized_pattern)

            # Write the configuration
            for category, location_rules in categorized_rules.items():
              for location, patterns in location_rules.items():
                # Create a unique middleware name
                middleware_name = f"waf_{category}_{location}".replace("-", "_")
                f.write(f"[http.middlewares.{middleware_name}]\n")
                f.write(f"  [http.middlewares.{middleware_name}.plugin.badbot]\n")
                f.write("    userAgent = [\n")
                # Properly escape for TOML (and for regex within the string)
                for pattern in patterns:
                    # No extra escape for TOML, because we write the full regex
                    f.write(f'      "{pattern}",\n')
                f.write("    ]\n\n")

        logger.info(f"Generated Traefik middleware file: {MIDDLEWARE_FILE}")

    except OSError as e:
        logger.error(f"Error writing to {MIDDLEWARE_FILE}: {e}")
        raise


def load_owasp_rules(file_path: Path) -> List[Dict]:
    """Loads OWASP rules from a JSON file.

    Accepts either a bare list of rule objects or the
    ``{"_provenance": ..., "rules": [...]}`` object form emitted by owasp2json.py.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
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
        "Apache-2.0; converted to Traefik.\n"
        "# Source rules: https://github.com/coreruleset/coreruleset\n"
        "# Derived/converted work redistributed under Apache-2.0. "
        "See THIRD_PARTY_NOTICES.md.\n"
        "#\n"
    )

def main():
    """Main function."""
    try:
        logger.info("Loading OWASP rules...")
        owasp_rules = load_owasp_rules(INPUT_FILE)
        crs_ref = load_provenance_ref(INPUT_FILE)
        logger.info(f"Loaded {len(owasp_rules)} rules.")

        logger.info("Generating Traefik WAF configuration...")
        generate_traefik_conf(owasp_rules, crs_ref)
        logger.info("Traefik WAF generation complete.")

    except Exception as e:
        logger.critical(f"Script failed: {e}")
        exit(1)

if __name__ == "__main__":
    main()
