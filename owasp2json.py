import os
import re
import time
import json
import base64
import hashlib
import logging
import argparse
from typing import List, Dict, Optional, Match
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from tqdm import tqdm

# --- Configuration ---
LOG_LEVEL = logging.INFO  # Set to DEBUG for more verbose output
GITHUB_REPO_URL = "https://api.github.com/repos/coreruleset/coreruleset"
OWASP_CRS_BASE_URL = f"{GITHUB_REPO_URL}/contents/rules"
GITHUB_REF = "v4.0"  # More specific default: Major version only
RATE_LIMIT_DELAY = 60  # Shorter delay, rely on exponential backoff
RETRY_DELAY = 2       # Shorter initial retry
MAX_RETRIES = 8        # More retries
EXPONENTIAL_BACKOFF = True
BACKOFF_MULTIPLIER = 2
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # GitHub token for authentication
CONNECTION_POOL_SIZE = 30   # More connections for faster parallel downloads


# --- Custom Exceptions ---
class GitHubRequestError(Exception):
    """Base exception for GitHub API request failures."""
    pass

class GitHubRateLimitError(GitHubRequestError):
    """Raised when the GitHub API rate limit is exceeded."""
    pass

class GitHubBlobFetchError(GitHubRequestError):
    """Raised when fetching a blob (file content) fails."""
    pass


# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# --- Utility Functions ---
def get_session() -> requests.Session:
    """Creates and returns a requests.Session with optional GitHub token."""
    session = requests.Session()
    if GITHUB_TOKEN:
        session.headers.update({"Authorization": f"token {GITHUB_TOKEN}"})
    # Increase connection pool size (important for parallel requests)
    adapter = requests.adapters.HTTPAdapter(pool_connections=CONNECTION_POOL_SIZE, pool_maxsize=CONNECTION_POOL_SIZE)
    session.mount("https://", adapter)  # Mount for all https:// requests
    return session


def fetch_with_retries(session: requests.Session, url: str) -> requests.Response:
    """
    Fetches a URL with retries, handling rate limits and transient errors.
    Raises: GitHubRequestError (or subclasses) if the request ultimately fails.
    """
    retries = 0
    while retries < MAX_RETRIES:
        try:
            response = session.get(url)

            # Check for rate limiting (403 with specific header)
            if response.status_code == 403 and "X-RateLimit-Remaining" in response.headers and response.headers["X-RateLimit-Remaining"] == '0':
                reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                wait_time = max(0, reset_time - int(time.time()))  # Ensure wait_time >= 0
                # If wait_time is very short, still wait a little bit to avoid hammering the API.
                wait_time = max(wait_time, 1)
                logger.warning(f"Rate limit exceeded. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
                continue # Retry Immediately

            # Raise exceptions for other HTTP errors (4xx, 5xx)
            response.raise_for_status()
            return response

        except requests.exceptions.RequestException as e:
            # Log the error, calculate wait time (exponential backoff)
            logger.warning(f"Request failed ({type(e).__name__}): {e} - URL: {url}")
            wait_time = (RETRY_DELAY * (BACKOFF_MULTIPLIER ** retries)
                         if EXPONENTIAL_BACKOFF else RETRY_DELAY)
            logger.warning(f"Retrying {url}... ({retries + 1}/{MAX_RETRIES}) in {wait_time} seconds.")
            time.sleep(wait_time)
            retries += 1

    # If we reach here, all retries failed.
    raise GitHubRequestError(f"Failed to fetch {url} after {MAX_RETRIES} retries.")


def fetch_latest_tag(session: requests.Session, ref_prefix: str) -> Optional[str]:
    """Fetches the latest matching Git tag, or falls back to the latest overall."""
    ref_url = f"{GITHUB_REPO_URL}/git/refs/tags"
    try:
        response = fetch_with_retries(session, ref_url)
        tags = response.json()

        if not tags:
            logger.warning("No tags found in the repository.")
            return None

        # Filter tags that start with the given prefix.
        matching_tags = [
            r["ref"] for r in tags
            if r["ref"].startswith(f"refs/tags/{ref_prefix}")
        ]
        # Sort matching tags to find the latest (lexicographically, assuming semver).
        matching_tags.sort(reverse=True)

        if matching_tags:
            latest_tag = matching_tags[0]  # The first tag is the latest
            logger.info(f"Latest matching tag: {latest_tag}")
            return latest_tag

        # Fallback:  If no matching tags, return the *very* latest tag.
        logger.warning(f"No matching refs found for prefix '{ref_prefix}'.  Using latest tag.")
        # Sort *all* tags and get the last one.
        tags.sort(key=lambda x: x["ref"], reverse=True)
        return tags[0]["ref"] if tags else None

    except GitHubRequestError as e:
        logger.error(f"Failed to fetch tags: {e}")
        return None


def fetch_rule_files(session: requests.Session, ref: str) -> List[Dict[str, str]]:
    """Fetches the list of .conf rule files from the given ref."""
    ref_name = ref.split("/")[-1] if "/" in ref else ref  # Extract ref name
    rules_url = f"{OWASP_CRS_BASE_URL}?ref={ref_name}"

    try:
        response = fetch_with_retries(session, rules_url)
        files = response.json()
        # Filter for .conf files and extract relevant data.
        return [
            {"name": f["name"], "sha": f["sha"]}
            for f in files if f["name"].endswith(".conf")
        ]
    except GitHubRequestError as e:
        logger.error(f"Failed to fetch rule files from {rules_url}: {e}")
        return []  # Return an empty list on failure


def fetch_github_blob(session: requests.Session, sha: str) -> str:
    """Fetches the base64-encoded content of a blob (file) given its SHA."""
    blob_url = f"{GITHUB_REPO_URL}/git/blobs/{sha}"
    try:
        response = fetch_with_retries(session, blob_url)
        blob_data = response.json()
        return blob_data.get("content", "")  # Return empty string if no content
    except GitHubRequestError as e:
        logger.error(f"Failed to fetch blob for SHA {sha}: {e}")
        return ""


def verify_blob_sha(file_sha: str, blob_content_b64: str) -> bool:
    """Verifies the SHA1 hash of the decoded blob content."""
    decoded_bytes = base64.b64decode(blob_content_b64)
    blob_header = f"blob {len(decoded_bytes)}\0".encode("utf-8")
    calculated_sha = hashlib.sha1(blob_header + decoded_bytes).hexdigest()

    if calculated_sha != file_sha:
        logger.warning(f"SHA mismatch!  Expected: {file_sha}, Calculated: {calculated_sha}")
        return False  # This is now an integrity failure, return False
    return True


def _extract_rule_id(secrule_text: str) -> str:
    """Extracts the rule ID from a SecRule directive."""
    match = re.search(r'id:(\d+)', secrule_text)
    return match.group(1) if match else "no_id"

def _extract_rule_severity(secrule_text: str) -> str:
    """Extract the severity."""
    match = re.search(r'severity:(\w+)', secrule_text)
    return match.group(1) if match else "medium" # Set default to medium


def _extract_rule_location(secrule_text: str) -> str:
    """
    Extracts the location (variable) from a SecRule directive.  Handles
    multiple variables and chained rules.
    """
    match = re.search(r'SecRule\s+([^"\s]+)', secrule_text)
    if not match:
        return "UNKNOWN"

    variables_str = match.group(1)
    variables = variables_str.split("|")  # Split multiple variables
    # Process variables for location extraction
    locations = []

    for var in variables:
        var = var.upper() # Set all vars to upper case
        if var.startswith("REQUEST_HEADERS"):
            if ":" in var:  # Specific header
                locations.append(var.split(":")[1].replace("_","-").strip()) # add support to user-agent
            else:
                locations.append("REQUEST_HEADERS") # Generic header location
        elif var.startswith("ARGS"): # add support to args
             locations.append("Query-String")
        elif var == "REQUEST_COOKIES":
            locations.append("Cookie")
        elif var == "REQUEST_URI":
            locations.append("Request-URI")
        elif var == "QUERY_STRING":
            locations.append("Query-String")
        elif var in ("REQUEST_LINE", "REQUEST_BODY", "RESPONSE_BODY", "RESPONSE_HEADERS"):
            locations.append(var) # if it has an explicit direct
        # Add more location mappings as needed

    # Prioritize specific locations, fall back to generic ones
    if "REQUEST_URI" in locations:
         return "Request-URI" # set request uri as top priority
    elif "Query-String" in locations:
         return "Query-String"
    if locations:
        return locations[0]  # Return the first extracted location
    return "UNKNOWN" # default locatioN


def extract_sec_rules(raw_text: str) -> List[Dict[str, str]]:
    """
    Extracts SecRule patterns and associated metadata from raw text.
    Now returns a *list of dictionaries*, each representing a SecRule.
    """
    rules = []
    # Find all SecRule directives (including those spanning multiple lines).
    for match in re.finditer(r'SecRule\s+.*?"((?:[^"\\]|\\.)+?)"', raw_text, re.DOTALL):
        secrule_text = match.group(0)  # Full SecRule text
        pattern = match.group(1).strip().replace("\\\\", "\\")  # Extract and clean pattern

        if not pattern: # if there are not pattern then skipp
            continue

        rule_id = _extract_rule_id(secrule_text)  # Extract rule ID
        location = _extract_rule_location(secrule_text)  # Extract location
        severity = _extract_rule_severity(secrule_text)

        rules.append({
            "id": rule_id,
            "pattern": pattern,
            "location": location,
            "severity": severity
        })
    return rules


def process_rule_file(file: Dict[str, str], session: requests.Session) -> List[Dict[str, str]]:
    """Processes a single rule file, extracting rules and metadata."""
    blob_b64 = fetch_github_blob(session, file["sha"])
    if not blob_b64:
        logger.warning(f"Skipping {file['name']} (empty blob).")
        return []

    if not verify_blob_sha(file["sha"], blob_b64):
        pass # We check before but continue, since data is present

    try:
        raw_text = base64.b64decode(blob_b64).decode("utf-8")
    except Exception as e:
         logger.error(f"Failed to decode the file: {file['name']}. Reason: {e}")
         return []

    category = file["name"].split("-")[-1].replace(".conf", "")
    extracted_rules = extract_sec_rules(raw_text)  # Get list of dicts

    # Add category to each extracted rule.
    for rule in extracted_rules:
        rule["category"] = category

    return extracted_rules


def fetch_owasp_rules(session: requests.Session, rule_files: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Fetches and processes rule files in parallel, returning all extracted rules."""
    all_rules = []
    with ThreadPoolExecutor(max_workers=CONNECTION_POOL_SIZE) as executor:
        future_to_file = {
            executor.submit(process_rule_file, file, session): file
            for file in rule_files
        }
        # Use tqdm for progress display. as_completed yields futures as they finish.
        for future in tqdm(as_completed(future_to_file), total=len(rule_files), desc="Processing rules"):
            file = future_to_file[future]
            try:
                rules = future.result()  # Get result (or raise exception)
                all_rules.extend(rules)
            except Exception as e:
                logger.error(f"Error processing {file['name']}: {e}")
                # Consider continuing even on individual file errors

    logger.info(f"Fetched a total of {len(all_rules)} rules.")
    return all_rules


def build_provenance(source_ref: str) -> Dict[str, str]:
    """Builds the attribution / provenance block embedded in owasp_rules.json.

    owasp_rules.json is a *derived work*: the patterns are extracted and
    converted from the OWASP Core Rule Set (Apache-2.0). Recording the source,
    reference and license here keeps the intermediate artifact self-describing
    and satisfies the attribution / "state changes" expectations of Apache-2.0
    (see THIRD_PARTY_NOTICES.md).
    """
    return {
        "source": "OWASP CoreRuleSet",
        "source_repo": "https://github.com/coreruleset/coreruleset",
        "source_ref": source_ref or "latest",
        "license": "Apache-2.0",
        "note": (
            "Derived work: SecRule patterns extracted and converted from the "
            "OWASP Core Rule Set, redistributed under Apache-2.0. "
            "See THIRD_PARTY_NOTICES.md."
        ),
        "generated_by": "fabriziosalmi/patterns (owasp2json.py)",
    }


def save_as_json(
    rules: List[Dict[str, str]],
    output_file: str,
    provenance: Optional[Dict[str, str]] = None,
) -> bool:
    """Saves the extracted rules to a JSON file (atomically).

    When ``provenance`` is supplied the payload is wrapped as
    ``{"_provenance": {...}, "rules": [...]}`` so the attribution travels with
    the data. The converters accept both this object form and a bare list.
    """
    try:
        output_dir = Path(output_file).parent
        if output_dir:
             output_dir.mkdir(parents=True, exist_ok=True)
        temp_file = f"{output_file}.tmp"  # Use a temporary file
        payload = {"_provenance": provenance, "rules": rules} if provenance is not None else rules
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)
        os.replace(temp_file, output_file)  # Atomic rename
        logger.info(f"Rules saved to {output_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to save rules to {output_file}: {e}")
        return False


def main():
    """Main function: Fetches, processes, and saves OWASP CRS rules."""
    parser = argparse.ArgumentParser(
        description="Fetches OWASP Core Rule Set rules and saves them as JSON."
    )
    parser.add_argument("--output", type=str, default="owasp_rules.json",
                        help="Output JSON file path.")
    parser.add_argument("--ref", type=str, default=GITHUB_REF,
                        help="Git reference (tag or branch prefix).  E.g., 'v4.0', 'v3.3', 'dev'")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate fetching and processing (no file save).")
    args = parser.parse_args()

    session = get_session()  # Create a requests session

    # 1. Fetch the latest tag (or use the provided ref directly)
    latest_ref = fetch_latest_tag(session, args.ref)
    if not latest_ref:
        logger.error("Could not determine the latest tag. Exiting.")
        return  # Exit if we can't get a ref

    # 2. Fetch the list of rule files.
    rule_files = fetch_rule_files(session, latest_ref)
    if not rule_files:
        logger.error("Could not fetch the list of rule files. Exiting.")
        return

    # 3. Fetch and process the rules (in parallel).
    rules = fetch_owasp_rules(session, rule_files)

    # 4. Save the rules to a JSON file (unless it's a dry run).
    ref_name = latest_ref.split("/")[-1] if latest_ref else args.ref
    if not args.dry_run:
        if rules:
            if save_as_json(rules, args.output, build_provenance(ref_name)):
                logger.info("Successfully saved rules to JSON.")
            else:
                logger.error("Failed to save rules to JSON.") # if the save fail
        else:
            logger.warning("No rules were extracted.")  # Warn if no rules
    else:
        logger.info("Dry-run mode:  Rules were fetched and processed, but not saved.")
        # Optionally print some of the extracted rules here for verification.
        if rules:
            logger.info(f"Example rule: {rules[0]}")


if __name__ == "__main__":
    main()
