import os
import re
import time
import json
import base64
import hashlib
import logging
import argparse
import sys
from typing import List, Dict, Optional, Match, Tuple
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from tqdm import tqdm

# --- Configuration ---
LOG_LEVEL = logging.INFO  # Set to DEBUG for more verbose output
GITHUB_REPO_URL = "https://api.github.com/repos/coreruleset/coreruleset"
OWASP_CRS_BASE_URL = f"{GITHUB_REPO_URL}/contents/rules"
GITHUB_REF = "latest"  # Newest stable Core Rule Set release
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


SEMVER_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+](.*))?$")


def _version_key(tag_name: str) -> Optional[Tuple[int, int, int, int, str]]:
    """
    Orders a semantic version tag.

    Returns None for a tag that is not a version, so it can be filtered out
    rather than compared as a string. The fourth element ranks a release above
    its own pre-releases: `v4.0.0` must sort above `v4.0.0-rc2`, which plain
    string ordering gets backwards because the longer string wins.

    Args:
        tag_name: A tag such as 'v4.29.0' or 'v4.0.0-rc2'.

    Returns:
        A sort key, or None if the tag is not a semantic version.
    """
    match = SEMVER_TAG.match(tag_name)
    if not match:
        return None
    major, minor, patch, pre = match.groups()
    return (int(major), int(minor), int(patch), 0 if pre else 1, pre or "")


def is_prerelease(tag_name: str) -> bool:
    """True when the tag carries a pre-release suffix such as -rc2 or -beta1."""
    match = SEMVER_TAG.match(tag_name)
    return bool(match and match.group(4))


def fetch_tags(session: requests.Session) -> List[str]:
    """
    Fetches every tag name in the upstream repository.

    Paginated: the single unpaginated request this used to make silently
    truncates once the repository has more tags than one page holds.
    """
    tags: List[str] = []
    page = 1
    while True:
        url = f"{GITHUB_REPO_URL}/git/refs/tags?per_page=100&page={page}"
        response = fetch_with_retries(session, url)
        batch = response.json()
        if not isinstance(batch, list) or not batch:
            break
        tags.extend(ref["ref"].split("/")[-1] for ref in batch)
        if len(batch) < 100:
            break
        page += 1
    return tags


def resolve_ref(session: requests.Session, requested: str) -> Optional[str]:
    """
    Resolves the requested reference to exactly one upstream tag.

    Three shapes are accepted, in this order:

    - `latest`, the default: the newest stable release by semantic version.
    - An exact tag that exists upstream, used as given. This is how a build is
      pinned to a known Core Rule Set version.
    - A version prefix such as `v4` or `v4.1`, resolved to the newest stable
      tag under it.

    This replaces a prefix match ordered as strings, which resolved the default
    `v4.0` to `v4.0.0-rc2`: a release candidate sorts above its own release
    because it is the longer string. The build converted that release candidate
    while the release notes advertised the current version (#43).

    Args:
        session: The HTTP session to use.
        requested: `latest`, an exact tag, or a version prefix.

    Returns:
        The resolved tag name, or None if nothing matched.
    """
    try:
        tags = fetch_tags(session)
    except GitHubRequestError as e:
        logger.error(f"Failed to fetch tags: {e}")
        return None

    if not tags:
        logger.warning("No tags found in the repository.")
        return None

    requested = (requested or "latest").strip()

    if requested != "latest" and requested in tags:
        if is_prerelease(requested):
            logger.warning(f"{requested} is a pre-release; converting it because it was asked for by name.")
        logger.info(f"Using the requested tag: {requested}")
        return requested

    # Candidates are stable versions only. A pre-release is reachable by naming
    # it exactly, which is the branch above.
    candidates = [
        tag for tag in tags
        if _version_key(tag) is not None and not is_prerelease(tag)
    ]
    if requested != "latest":
        candidates = [tag for tag in candidates if tag.startswith(requested)]

    if not candidates:
        logger.error(
            f"No stable tag matches {requested!r}. Upstream tags that are versions: "
            f"{sorted((t for t in tags if _version_key(t)), key=_version_key)[-5:]}"
        )
        return None

    resolved = max(candidates, key=_version_key)
    logger.info(f"Resolved {requested!r} to {resolved}")
    return resolved


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


_TRANSFORM_RE = re.compile(r"\bt:([A-Za-z0-9_]+)")


def _extract_transformations(actions: str) -> List[str]:
    """
    Returns the `t:` transformation chain declared by a rule.

    A CRS pattern is written to match a value *after* these have been applied.
    Matching a raw request against a pattern that expects urlDecodeUni is both
    a false-negative risk, since an attacker can encode, and a false-positive
    risk, since the raw form contains characters the decoded one would not.
    Recording the chain lets a converter decide what it can honestly emit.

    Args:
        actions: The action list of a SecRule.

    Returns:
        The transformation names, in order, without the `t:` prefix.
    """
    return [t for t in _TRANSFORM_RE.findall(actions) if t != "none"]


# SecLang allows one disruptive action per rule. `block` defers to the policy
# SecDefaultAction sets, which in CRS is what a signature uses; `deny` and
# `drop` refuse outright. `pass` explicitly does not: the rule runs for its side
# effects and lets the request through.
_DISRUPTIVE_ACTIONS = ("allow", "block", "deny", "drop", "pass", "proxy", "redirect")


def _split_actions(actions: str) -> List[str]:
    """
    Splits an action list on the commas that separate actions.

    A value may itself contain a comma: `msg:'SQL Injection, common exploits'`
    is one action, not two. Only commas outside single quotes separate.

    Args:
        actions: The action list of a SecRule.

    Returns:
        One string per action, stripped.
    """
    out: List[str] = []
    buf: List[str] = []
    quoted = False
    for ch in actions:
        if ch == "'":
            quoted = not quoted
        if ch == "," and not quoted:
            out.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    out.append("".join(buf).strip())
    return [a for a in out if a]


def _extract_disruptive_action(actions: str) -> Optional[str]:
    """
    Returns the disruptive action a rule declares, or None if it declares none.

    This is what separates a signature from bookkeeping. CRS rule 921170 is
    `@rx .`, a pattern that matches any character: it exists to count request
    parameters, declares `pass`, and blocks nothing. Converted into an nginx map
    without its action it becomes a rule that matches every request with a query
    string. A converter that does not read this cannot tell the two apart.

    Args:
        actions: The action list of a SecRule.

    Returns:
        The action name, or None when the rule inherits SecDefaultAction's.
    """
    for action in _split_actions(actions):
        if action in _DISRUPTIVE_ACTIONS:
            return action
    return None


def _extract_rule_id(actions: str) -> str:
    """
    Extracts the rule ID from the action list.

    Args:
        actions: The action list of a SecRule.

    Returns:
        The CRS rule id, or "no_id" when the rule declares none.
    """
    match = re.search(r'id:(\d+)', actions)
    return match.group(1) if match else "no_id"

# CRS writes the severity quoted: `severity:'CRITICAL'`. The unquoted form is
# also legal in SecLang, so both are accepted.
_SEVERITY_RE = re.compile(r"severity:'?(\w+)'?")

# ModSecurity severities, mapped to the three levels the converters use.
_SEVERITY_MAP = {
    "EMERGENCY": "high", "ALERT": "high", "CRITICAL": "high",
    "ERROR": "medium", "WARNING": "medium",
    "NOTICE": "low", "INFO": "low", "DEBUG": "low",
}


def _extract_rule_severity(secrule_text: str) -> str:
    """
    Extract the severity, normalised to high, medium or low.

    The previous pattern was ``severity:(\\w+)``, and ``\\w`` does not match the
    quote CRS actually writes, so it never matched and every rule fell through
    to the "medium" default. Every converter reads this value, and the nginx
    one blocks on "high", so nothing could ever block.

    Args:
        secrule_text: The full text of a SecRule directive.

    Returns:
        "high", "medium" or "low"; "medium" when no severity is declared.
    """
    match = _SEVERITY_RE.search(secrule_text)
    if not match:
        return "medium"
    return _SEVERITY_MAP.get(match.group(1).upper(), "medium")


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
        elif var == "REQUEST_METHOD":
            locations.append("Request-Method")
        elif var == "REQUEST_FILENAME":
            locations.append("Request-Filename")
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


def _iter_directives(raw_text: str) -> List[str]:
    """
    Yields complete SecLang directives, joining backslash continuations.

    A CRS rule spans many lines: the variables and operator on the first, then
    the action list continued with a trailing backslash on each subsequent one.

        SecRule ARGS "@rx pattern" \\
            "id:941100,\\
            phase:2,\\
            severity:'CRITICAL',\\
            ..."

    Args:
        raw_text: The contents of a .conf file.

    Returns:
        One string per directive, continuations joined.
    """
    directives: List[str] = []
    current: List[str] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not current and not stripped.startswith("Sec"):
            continue
        if stripped.endswith("\\"):
            current.append(stripped[:-1].rstrip())
            continue
        current.append(stripped)
        directives.append(" ".join(current))
        current = []
    if current:
        directives.append(" ".join(current))
    return directives


def _quoted_strings(text: str) -> List[str]:
    """
    Returns the double-quoted strings in a directive, in order.

    Scans rather than uses a regular expression, because the action list
    contains single-quoted values with commas and escaped double quotes.

    Args:
        text: One directive.

    Returns:
        The contents of each double-quoted string.
    """
    out: List[str] = []
    i = 0
    while i < len(text):
        if text[i] != '"':
            i += 1
            continue
        i += 1
        buf: List[str] = []
        while i < len(text):
            if text[i] == "\\" and i + 1 < len(text):
                buf.append(text[i:i + 2])
                i += 2
                continue
            if text[i] == '"':
                break
            buf.append(text[i])
            i += 1
        out.append("".join(buf))
        i += 1
    return out


def extract_sec_rules(raw_text: str) -> List[Dict[str, str]]:
    """
    Extracts SecRule patterns and their metadata.

    The previous version matched `SecRule\\s+.*?"(...)"`, which stops at the
    first quoted string: the operator. Everything after it was discarded,
    including the entire action list, so every rule came out with id "no_id"
    and severity "medium" no matter what CRS declared. Directives are now read
    whole, continuations and all, and the actions are parsed from the second
    quoted string.

    Args:
        raw_text: The contents of a .conf file.

    Returns:
        One dict per rule, with id, pattern, location, severity,
        transformations and disruptive action.
    """
    rules = []
    for directive in _iter_directives(raw_text):
        if not directive.startswith("SecRule"):
            continue
        quoted = _quoted_strings(directive)
        if not quoted:
            continue

        pattern = quoted[0].strip().replace("\\\\", "\\")
        if not pattern:
            continue

        actions = quoted[1] if len(quoted) > 1 else ""
        rules.append({
            "id": _extract_rule_id(actions),
            "pattern": pattern,
            "location": _extract_rule_location(directive),
            "severity": _extract_rule_severity(actions),
            "transformations": _extract_transformations(actions),
            "action": _extract_disruptive_action(actions),
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
                        help="'latest' for the newest stable release, an exact tag such as "
                             "'v4.29.0' to pin a build, or a version prefix such as 'v4'.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate fetching and processing (no file save).")
    args = parser.parse_args()

    session = get_session()  # Create a requests session

    # 1. Fetch the latest tag (or use the provided ref directly)
    latest_ref = resolve_ref(session, args.ref)
    if not latest_ref:
        # Returning quietly here left the previous owasp_rules.json in place and
        # let the rest of the pipeline rebuild from stale input.
        logger.error(f"Could not resolve {args.ref!r} to an upstream tag.")
        return 1

    # 2. Fetch the list of rule files.
    rule_files = fetch_rule_files(session, latest_ref)
    if not rule_files:
        logger.error(f"Could not fetch the rule files at {latest_ref}.")
        return 1

    # 3. Fetch and process the rules (in parallel).
    rules = fetch_owasp_rules(session, rule_files)

    # 4. Save the rules to a JSON file (unless it's a dry run).
    ref_name = latest_ref.split("/")[-1] if latest_ref else args.ref
    if not args.dry_run:
        if rules:
            if save_as_json(rules, args.output, build_provenance(ref_name)):
                logger.info(f"Saved {len(rules)} rules from {ref_name} to {args.output}.")
            else:
                logger.error("Failed to save rules to JSON.") # if the save fail
                return 1
        else:
            logger.error("No rules were extracted.")
            return 1
    else:
        logger.info("Dry-run mode:  Rules were fetched and processed, but not saved.")
        # Optionally print some of the extracted rules here for verification.
        if rules:
            logger.info(f"Example rule: {rules[0]}")


    return 0


if __name__ == "__main__":
    sys.exit(main())
