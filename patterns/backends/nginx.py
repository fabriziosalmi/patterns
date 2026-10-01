import logging
import re
from collections import defaultdict
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

from patterns.backends import Backend, Capabilities, Compiled, Decision, Target, register
from patterns.backends._common import operator_of, provenance_header
from patterns.corpus import VARIABLE_FIELDS, first_ordinary_match, nginx_uri
from patterns.dialects import python_equivalent
from patterns.ir import IR

logger = logging.getLogger(__name__)

# A ModSecurity rule's operator decides whether it can become an nginx regex at
# all. Only `@rx` is a regular expression; everything else is a numeric
# comparison, a file lookup, a byte-range check or a libinjection detector, and
# emitting it as a map key produces an entry that can never match a URI. Of the
# 646 patterns extracted from CRS, 330 are in that second group, 181 of them
# `@lt` paranoia-level guards, which are CRS control flow rather than attack
# signatures.
CONVERTIBLE_OPERATOR = "@rx"

@lru_cache(maxsize=256)  # Increased cache size
def validate_regex(pattern: str) -> bool:
    """Reports whether a pattern is a regular expression nginx could compile."""
    try:
        re.compile(python_equivalent(pattern))
        return True
    except re.error as e:
        logger.warning(f"Invalid regex: {pattern} - {e}")
        return False

def explain_pattern(pattern: str) -> Tuple[Optional[str], Optional[Tuple[str, str]]]:
    """
    Returns the regular expression a rule matches with, or why it has none.

    A ModSecurity operator decides whether a rule is a regular expression at
    all. Only `@rx` is; the rest are numeric comparisons, phrase lists, file
    lookups or libinjection detectors, and a map key built from one of those can
    never match. A negated operator is dropped too: a map key says what matches,
    not what fails to.

    The expression itself is returned unchanged. nginx hands the contents of a
    configuration string to PCRE, and PCRE is what CRS writes for, so there is
    nothing to translate. Verified against nginx 1.31.5, matching against
    $args: `\\d` matches a digit, `[0-9]` matches a digit, `sel.*from` matches
    across characters, `foo$` anchors, `\\x{62}` matches a b, and `(?<!no)bad`
    applies the lookbehind. What needs care is the configuration parser rather
    than the regex, and that is _escape_for_config's job.

    Returns:
        (the expression, None) or (None, (reason code, detail)).
    """
    stripped = pattern.strip()
    if stripped.startswith("!"):
        # A negated operator inverts the match, which a map key cannot express.
        logger.debug(f"Skipping negated operator: {pattern}")
        return None, ("operator-unsupported", "negated: a map key says what matches, not what does not")
    if stripped.startswith("@"):
        if not stripped.startswith(CONVERTIBLE_OPERATOR + " "):
            operator = stripped.split(None, 1)[0]
            logger.debug(f"Skipping non-regex operator {operator}: {pattern}")
            return None, ("operator-unsupported", operator)
        stripped = stripped[len(CONVERTIBLE_OPERATOR):].strip()

    # Every map key is matched case-insensitively or not by the ~ prefix
    # is_case_insensitive picks, so an inline (?i) is redundant. It is removed
    # rather than kept because nginx rejects it anywhere but the start.
    stripped = stripped.replace("(?i)", "").strip()
    if not stripped:
        return None, ("empty-pattern", "nothing is left once the operator and (?i) are removed")
    return stripped, None


def sanitize_pattern(pattern: str, location: str) -> Optional[str]:
    """The regular expression a rule matches with, or None if it has none."""
    return explain_pattern(pattern)[0]


def is_case_insensitive(pattern: str, transformations: List[str]) -> bool:
    """
    Reports whether a rule's pattern should be matched ignoring case.

    CRS patterns are not case-insensitive by default. They are written to run
    after the transformations the rule declares, and a rule that declares
    `t:lowercase` is written in lower case because its input will be. Converted
    without its transformations, such a pattern only matches lower-case attacks
    unless the match itself ignores case.

    So case-insensitivity is taken from the rule: `(?i)` in the pattern, or a
    lowercasing transformation. Applying it to every rule instead, which is what
    emitting `~*` unconditionally did, makes rules match strings their authors
    excluded on purpose.
    """
    if "(?i)" in pattern:
        return True
    return any(t in ("lowercase", "cmdline", "normalizepath") for t in transformations)


# nginx refuses a configuration parameter longer than this, in bytes.
#
# One over-long parameter is not one lost rule: nginx refuses the file, so the
# whole rule set stops loading. That failure shipped once already (#22), which
# is why the limit is measured rather than assumed.
#
# The previous value, 4096, was one above the boundary, and the comparison
# against it emitted a key nginx refuses. Binary-searched with `nginx -t`, on
# nginx 1.31.5 and on the nginx the Ubuntu runners install: 4095 bytes loads,
# 4096 does not ("too long parameter, probably missing terminating \"
# character"). The limit is on the parameter, not the line: a 4095-byte key
# loads on a line of 4508 characters.
#
# tests/test_parameter_limit.py binary-searches the local nginx for the same
# boundary and fails if this constant is above it, so a stricter build is caught
# rather than assumed away with a margin.
#
# The limit counts bytes, and a Python string counts characters. The two agree
# for every pattern CRS writes in a .conf file, which spells non-ASCII as
# `\x{...}`, but not for the .data files behind `@pmFromFile`: ssrf.data
# contains `\u2460` and `\u3002`, three bytes each. Measuring in characters
# there produces a key that passes this check and takes the file down.
NGINX_MAX_PARAMETER = 4095

# The severities a map entry can have, in the order its keys have to be written in: a map takes
# the first key that matches, and only a `high` one refuses.
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# The request component each rule location is matched against.
LOCATION_VARIABLES = {
    # `$uri` is the path percent-decoded and normalised by nginx, which is the
    # `t:urlDecodeUni`, `t:normalizePath` chain the rules on REQUEST_FILENAME declare.
    "request-filename": "$uri",
    "request-method": "$request_method",
    "request-uri": "$request_uri",
    "query-string": "$args",
    "user-agent": "$http_user_agent",
    "host": "$http_host",
    "referer": "$http_referer",
    "content-type": "$http_content_type",
}


def _escape_for_config(pattern: str) -> str:
    """
    Escapes a regular expression so nginx's parser hands PCRE what CRS wrote.

    Inside a double-quoted string nginx consumes the backslash in `\\\\`, `\\"` and
    `\\'` and leaves every other backslash alone. Verified against nginx 1.31.5:
    a key written `"a\\\\b"` matches a word boundary, `"a\\\\\\\\b"` matches a
    literal backslash, and `"say\\"hi"` matches say"hi. So a pattern that means
    to match a literal backslash has to arrive with its backslashes doubled, and
    a quote has to arrive escaped.

    Backslashes are doubled first: the backslash added in front of a quote is
    one nginx is meant to consume, not one PCRE should see.
    """
    return pattern.replace("\\", "\\\\").replace('"', '\\"')


def _sanitize_name(name: str) -> str:
    """Reduces a name to what nginx accepts in a variable name."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower()).strip("_") or "generic"


def _map_variable(source_variable: str) -> str:
    """Names the variable a map writes into, from the variable it reads."""
    return f"$waf_{_sanitize_name(source_variable.lstrip('$'))}"


# A rule that does not refuse the request is not a signature. CRS runs plenty of
# rules for their side effects: 921170 is `@rx .`, a pattern matching any
# character, and it exists to count repeated parameter names. Emitted into a map
# it matches every request that carries a query string.
BLOCKING_ACTIONS = ("block", "deny", "drop")


def blocks(rule: Dict) -> bool:
    """
    Reports whether a rule refuses the request, or only records something.

    A rule that declares no disruptive action inherits SecDefaultAction, which
    CRS sets to `pass`, so it does not block either.

    A rules file written before owasp2json.py recorded this field has no such
    key at all. Absence of the field is not evidence of `pass`, so those rules
    are kept: the alternative is that upgrading the converter ahead of the data
    silently empties the output.
    """
    if "action" not in rule:
        return True
    return rule["action"] in BLOCKING_ACTIONS


def fires_on_ordinary_traffic(pattern: str, variable: str,
                              ignore_case: bool) -> Optional[str]:
    """
    Returns the name of the first ordinary request a pattern matches, or None.

    This is the check that decides what may be emitted. A converted rule has
    lost the transformations it was written to run after, so a pattern that is
    precise against a decoded value can be indiscriminate against a raw one:
    920230 is `%[0-9a-fA-F]{2}` with `t:urlDecodeUni`, which means "still
    percent-encoded after one decode", that is, double encoding. Against a raw
    URI it means "contains a percent-encoded character", which is most ordinary
    URLs. Whether a given rule survives that loss cannot be reasoned about rule
    by rule, so it is measured against corpus.BENIGN.

    Python's re stands in for PCRE here. The two differ on syntax, which
    validate_regex already handles, not on what these patterns match.

    Args:
        pattern: The regular expression, as it will be emitted.
        variable: The nginx variable the map is keyed on.
        ignore_case: Whether the map key will carry the `~*` prefix.

    Returns:
        The `name` of the first matching benign request, or None if it matches
        none of them.
    """
    if variable == "$uri":
        return first_ordinary_match(pattern, "path", ignore_case, lambda entry: [nginx_uri(entry["path"])])
    field = VARIABLE_FIELDS.get(variable)
    if field is None:
        return None
    return first_ordinary_match(pattern, field, ignore_case)


def exclusion_report(not_blocking: int, too_long: int,
                     noisy: List[Tuple[str, str, str]]) -> str:
    """
    Describes, in the generated file, what was left out of it and why.

    A converter that drops rules silently is how this output came to load
    cleanly and block nothing. An operator reading the file should be able to
    see the size of what is missing without running the generator.
    """
    lines = ["# Rules deliberately not emitted:\n"]
    if not_blocking:
        lines.append(f"#   {not_blocking} record rather than refuse "
                     "(they declare pass, or inherit it)\n")
    if too_long:
        lines.append(f"#   {too_long} exceed nginx's 4096-character parameter limit\n")
    if noisy:
        lines.append(f"#   {len(noisy)} match ordinary traffic once converted, "
                     "so they cannot block:\n")
        for rule_id, category, ordinary in noisy:
            lines.append(f"#     {rule_id} ({category}) matches: {ordinary}\n")
    if len(lines) == 1:
        return "# No rules were excluded.\n"
    return "".join(lines)


def phrase_alternations(phrases: List[str], limit: int = NGINX_MAX_PARAMETER) -> List[str]:
    """
    Writes a list of phrases as the regular expressions of map keys that fit nginx.

    `@pm` and `@pmFromFile` are a case-insensitive substring match against a list, which is
    an alternation of the phrases with each one escaped. One key for the lot is more than
    nginx takes as a parameter (#22), and one key per phrase is thousands of keys, which
    nginx tries one after the other for every request. So the phrases are packed into as few
    keys as fit, each `(?:a|b|c)` and each at most `limit` bytes as it is written in the file.

    Args:
        phrases: The phrases, in the order they are to be tried.
        limit: The most bytes a key may take, with its quotes and `~*`.

    Returns:
        The expressions, one for each key. Empty if there are no phrases. Raises ValueError
        if one phrase alone cannot fit.
    """
    overhead = len('"~*(?:') + len(')"')
    chunks: List[List[str]] = []
    size = 0
    for phrase in dict.fromkeys(phrases):
        piece = re.escape(phrase)
        cost = len(_escape_for_config(piece).encode("utf-8"))
        if overhead + cost > limit:
            raise ValueError(f"the phrase {phrase[:40]!r} does not fit in a key of {limit} bytes")
        if not chunks or size + 1 + cost > limit:
            chunks.append([])
            size = overhead
        size += cost + (1 if chunks[-1] else 0)
        chunks[-1].append(piece)
    return ["(?:" + "|".join(chunk) + ")" for chunk in chunks]


def phrases_of(operator: Dict, data_files: Dict[str, List[str]]) -> Optional[List[str]]:
    """
    The phrases an `@pm` or `@pmFromFile` operator matches, or None if it is neither.

    `@pm` takes its phrases from its argument, split on blank space. `@pmFromFile` takes
    them from the file the argument names, which the IR carries (`data_files`).
    """
    if operator["negated"] or operator["name"] not in ("pm", "pmFromFile"):
        return None
    if operator["name"] == "pm":
        return operator["argument"].split()
    return data_files.get(operator["argument"].strip())


def generate_nginx_waf(rules: List[Dict], crs_ref: str = "latest",
                       data_files: Optional[Dict[str, List[str]]] = None) -> Compiled:
    """Builds the Nginx WAF configuration: maps, rules and a README."""
    data_files = data_files or {}

    # source variable -> "key value" map entries, each with its severity: see SEVERITY_ORDER
    entries_by_variable: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
    severities_seen: set = set()
    skipped_too_long = 0
    skipped_not_blocking = 0
    excluded_as_noisy: List[Tuple[str, str, str]] = []
    decisions: List[Decision] = []

    for index, rule in enumerate(rules):
        rule_id = rule.get("id", "no_id")  # Get rule ID
        category = rule.get("category", "generic").lower()
        location = rule.get("location", "request-uri").lower() # set a default location
        pattern = rule["pattern"]
        severity = rule.get("severity", "medium").lower() # get severity

        # A chain matches when every record does, and a record on its own is another rule:
        # the head of 920480 is any `charset=` in a Content-Type, and the link that makes it a
        # rule (the charset is not one that is allowed) is a transaction variable no target has.
        # Written alone it refused `application/json; charset=utf-8`, in all four targets.
        if rule.get("chain"):
            decisions.append(Decision(index, False, "chain-unsupported",
                                      f"{rule['chain']['role']} of {rule['chain']['head']}"))
            continue

        # What the rule matches with: a regular expression, or a list of phrases
        # written as the alternations that fit a key.
        operator = operator_of(rule)
        listed = phrases_of(operator, data_files)
        if listed is not None:
            if not listed:
                decisions.append(Decision(index, False, "empty-pattern", "the phrase list has no phrases"))
                continue
            try:
                patterns = phrase_alternations(listed)
            except ValueError as e:
                decisions.append(Decision(index, False, "parameter-too-long", str(e)))
                continue
            ignore_case = True  # @pm ignores case
        else:
            sanitized_pattern, why = explain_pattern(pattern)
            if not sanitized_pattern:
                if operator["name"] == "pmFromFile" and not operator["negated"]:
                    why = ("operator-unsupported", "@pmFromFile (the IR has no such phrase list)")
                decisions.append(Decision(index, False, *why))
                continue  # Skip unsupported patterns
            if not validate_regex(sanitized_pattern):
                decisions.append(Decision(index, False, "invalid-regex", "Python's re does not compile it"))
                continue  # Skip invalid patterns
            patterns = [sanitized_pattern]
            ignore_case = None  # decided below, from the rule

        variable = LOCATION_VARIABLES.get(location)
        if variable is None:
            logger.warning(f"Unsupported location: {location} for rule: {rule_id}")
            decisions.append(Decision(index, False, "location-unsupported", location))
            continue

        if not blocks(rule):
            skipped_not_blocking += 1
            decisions.append(Decision(index, False, "not-blocking", str(rule.get("action"))))
            continue

        # nginx reads the map key as a double-quoted string, so an unescaped
        # quote inside the pattern ends the token early: the CRS pattern
        # `charset\s*=\s*["\']?...` produced `unexpected "\'"` and the file
        # would not load.
        if ignore_case is None:
            ignore_case = is_case_insensitive(pattern, rule.get("transformations") or [])

        # Measured, not assumed: a rule that refuses ordinary traffic is not
        # emitted, whatever its severity says. Each key is checked, and a rule is
        # written whole or not at all.
        ordinary = next((found for found in (fires_on_ordinary_traffic(p, variable, ignore_case)
                                             for p in patterns) if found is not None), None)
        if ordinary is not None:
            excluded_as_noisy.append((rule_id, category, ordinary))
            decisions.append(Decision(index, False, "matches-benign-traffic", ordinary))
            continue

        prefix = "~*" if ignore_case else "~"
        keys = [f'"{prefix}{_escape_for_config(p)}"' for p in patterns]
        too_long = max(len(k.encode("utf-8")) for k in keys)
        if too_long > NGINX_MAX_PARAMETER:
            # nginx refuses a single configuration parameter longer than 4096
            # characters ("too long parameter"), and one over-long pattern makes
            # the whole file unloadable. Verified against nginx 1.31.5: the
            # quoted token including `~*` may be at most 4096 characters.
            skipped_too_long += 1
            logger.warning(
                f"Skipping rule {rule_id}: key is {too_long} "
                f"bytes, over nginx's {NGINX_MAX_PARAMETER}-byte parameter limit"
            )
            decisions.append(Decision(index, False, "parameter-too-long", f"{too_long} bytes"))
            continue

        # The value carries the severity and the category, so an operator can
        # read $waf_<variable> in a log to see what matched.
        severities_seen.add(severity)
        value = f'"{severity}:{_sanitize_name(category)}"'
        for key in keys:
            entries_by_variable[variable].append((SEVERITY_ORDER.get(severity, len(SEVERITY_ORDER)),
                                                  f"  {key} {value};"))
        decisions.append(Decision(index, True, location=location, pattern="|".join(patterns),
                                  keys=len(keys)))

    if skipped_too_long:
        logger.warning(
            f"{skipped_too_long} rule(s) skipped for exceeding nginx's parameter limit"
        )
    if skipped_not_blocking:
        logger.info(
            f"{skipped_not_blocking} rule(s) skipped: they record rather than refuse"
        )
    for rule_id, category, ordinary in excluded_as_noisy:
        logger.warning(
            f"Excluding rule {rule_id} ({category}): it matches an ordinary "
            f"request ({ordinary})"
        )

    # --- Generate Maps (waf_maps.conf) ---
    #
    # One map per source variable, keyed on the variable its patterns were
    # written for. Keying every map on `$1`, as this generator used to, meant
    # every lookup returned the default: `$1` holds a regular expression capture
    # and nothing sets it here, so the rules matched nothing at all.
    #
    # No `http { }` wrapper: this file is included *into* the http context, and
    # nginx does not allow a nested http block.
    maps: List[str] = []
    maps.append(provenance_header(crs_ref, Nginx.title))
    maps.append("# Nginx WAF Maps (Generated by `python3 -m patterns build --target nginx`)\n")
    maps.append("#\n")
    maps.append("# Include this file INSIDE your existing `http` block:\n")
    maps.append("#\n")
    maps.append("#   http {\n")
    maps.append("#       include /path/to/waf_patterns/nginx/waf_maps.conf;\n")
    maps.append("#   }\n")
    maps.append("#\n")
    maps.append("# Each map yields \"<severity>:<category>\" on a match, and \"\" otherwise.\n")
    maps.append("#\n")
    maps.append(exclusion_report(skipped_not_blocking, skipped_too_long,
                             excluded_as_noisy))
    maps.append("\n")

    for variable in sorted(entries_by_variable):
        name = _map_variable(variable)
        maps.append(f"map {variable} {name} {{\n")
        maps.append('  default "";\n')
        # nginx takes the first key that matches, and `if ($waf_x ~ "^high")` reads what that
        # key said. A `medium` key ahead of a `high` one that matches the same value turns it
        # into a request that passes: the high rule is there and never speaks. So the
        # keys are in severity order, and the order of CRS within a severity. Verified against
        # nginx: with the medium key first `zqxjk attack` is a 200, with the high one first a 403.
        maps.append("\n".join(line for _, line in sorted(entries_by_variable[variable], key=lambda e: e[0])))
        maps.append("\n}\n\n")


    # --- Generate Rules (waf_rules.conf) ---
    #
    # Only `high` blocks. The previous version also emitted `add_header` inside
    # `if`, which nginx rejects in server context ("add_header directive is not
    # allowed here"), so the file could not load.
    rules_out: List[str] = []
    rules_out.append(provenance_header(crs_ref, Nginx.title))
    rules_out.append("# Nginx WAF Rules (Generated by `python3 -m patterns build --target nginx`)\n")
    rules_out.append("#\n")
    rules_out.append("# Include this file inside a `server` or `location` block.\n")
    rules_out.append("# Requires waf_maps.conf to be included in the `http` block.\n")
    rules_out.append("#\n")
    variables = [_map_variable(v) for v in sorted(entries_by_variable)]

    if "high" in severities_seen:
        rules_out.append("# Requests matching a `high` severity pattern are refused with 403.\n")
        rules_out.append("# Lower severities are recorded in the variables but do not block:\n")
        rules_out.append("# they hold \"<severity>:<category>\" and are usable in log_format.\n\n")
        for name in variables:
            rules_out.append(f'if ({name} ~ "^high") {{\n')
            rules_out.append("  return 403;\n")
            rules_out.append("}\n")
    else:
        # Emitting `if` blocks that can never fire would suggest an
        # enforcement this rule set cannot currently provide.
        rules_out.append("# NOTHING IS BLOCKED BY THIS FILE.\n")
        rules_out.append("#\n")
        rules_out.append("# The rules extracted from the Core Rule Set carry no severity, so no\n")
        rules_out.append("# pattern reaches the `high` level that would trigger a 403, and no\n")
        rules_out.append("# blocking directive is emitted rather than one that can never fire.\n")
        rules_out.append("#\n")
        rules_out.append("# Matches are still recorded. These variables hold\n")
        rules_out.append("# \"<severity>:<category>\" when a pattern matches, and \"\" otherwise:\n")
        rules_out.append("#\n")
        for name in variables:
            rules_out.append(f"#   {name}\n")
        rules_out.append("#\n")
        rules_out.append("# Use them in log_format to see what would match your own traffic\n")
        rules_out.append("# before enforcing anything:\n")
        rules_out.append("#\n")
        rules_out.append("#   log_format waf '$remote_addr $request \"$waf_request_uri\" \"$waf_args\"';\n")
        rules_out.append("#\n")
        rules_out.append("# To block on any match, uncomment the directives below. Measured\n")
        rules_out.append("# against a running nginx, that blocks XSS, SQL injection, Log4Shell\n")
        rules_out.append("# and path traversal, and also refuses an ordinary `?url=` or\n")
        rules_out.append("# `?email=` parameter. That false-positive profile is what CRS itself\n")
        rules_out.append("# manages with anomaly scoring, which this project does not have yet.\n")
        rules_out.append("# Measure first, then decide. See\n")
        rules_out.append("# https://github.com/fabriziosalmi/patterns/issues/45\n")
        rules_out.append("#\n")
        for name in variables:
            rules_out.append(f"#   if ({name}) {{ return 403; }}\n")


    # --- Generate README ---
    readme: List[str] = []
    readme.append("# Nginx WAF Configuration\n\n")
    readme.append("This directory contains Nginx WAF configuration files generated from OWASP rules.\n\n")
    readme.append("## Usage\n\n")
    readme.append("1. **Include `waf_maps.conf` in your `http` block:**\n")
    readme.append("   ```nginx\n")
    readme.append("   http {\n")
    readme.append("       include /path/to/waf_patterns/nginx/waf_maps.conf;\n")
    readme.append("       # ... other http configurations ...\n")
    readme.append("   }\n")
    readme.append("   ```\n\n")
    readme.append("2. **Include `waf_rules.conf` in your `server` or `location` block:**\n")
    readme.append("   ```nginx\n")
    readme.append("   server {\n")
    readme.append("       # ... other server configurations ...\n")
    readme.append("       include /path/to/waf_patterns/nginx/waf_rules.conf;\n")
    readme.append("   }\n")
    readme.append("   ```\n\n")
    readme.append("3. **Reload Nginx:**\n")
    readme.append("   ```bash\n")
    readme.append("   sudo nginx -t && sudo systemctl reload nginx\n")
    readme.append("   ```\n\n")
    readme.append("## What this blocks\n\n")
    readme.append("Only a rule of severity `high` refuses a request, with a 403. The lower severities are\n")
    readme.append("recorded in the `$waf_*` variables, which hold `\"<severity>:<category>\"` on a match and\n")
    readme.append("`\"\"` otherwise, and are there for `log_format`. The header of `waf_maps.conf` lists the\n")
    readme.append("rules that were left out and why.\n\n")
    readme.append("A `map` matches one regular expression against one raw request variable, and nothing\n")
    readme.append("else: it does not decode, it does not read the request body and it does not add up a\n")
    readme.append("score. `@pm` and `@pmFromFile` are written as case-insensitive alternations of their\n")
    readme.append("phrases, and the request path is matched on `$uri`, which nginx has decoded and\n")
    readme.append("normalised. See https://fabriziosalmi.github.io/patterns/nginx for what it catches and\n")
    readme.append("what it does not.\n\n")
    readme.append("Log the variables against your own traffic before enforcing anything.\n\n")
    readme.append("## Important Notes:\n\n")
    readme.append("* **Testing is Crucial:**  Thoroughly test your WAF configuration with a variety of requests (both legitimate and malicious) to ensure it's working correctly and not causing false positives.\n")
    readme.append("* **False Positives:**  WAF rules, especially those based on regex, can sometimes block legitimate traffic.  Monitor your Nginx logs and adjust the rules as needed.\n")
    readme.append("* **Performance:** Complex regexes can impact performance.  Use the simplest regex that accurately matches the threat.\n")
    readme.append("* **Updates:**  Regularly update the OWASP rules (by re-running `owasp2json.py` and `python3 -m patterns build --target nginx`) to stay protected against new threats.\n")
    readme.append("* **This is not a complete WAF:** This script provides a basic WAF based on pattern matching.  For more comprehensive protection, consider using a dedicated WAF solution like Nginx App Protect or ModSecurity.\n")

    logger.info(f"Generated Nginx waf_maps.conf, waf_rules.conf and README.md "
                f"({sum(len(e) for e in entries_by_variable.values())} entries)")
    return Compiled({
        "waf_maps.conf": "".join(maps),
        "waf_rules.conf": "".join(rules_out),
        "README.md": "".join(readme),
    }, decisions)


@register
class Nginx(Backend):
    name = "nginx"
    title = "Nginx"

    # What nginx can express, and what the backend writes of it. A map key is one
    # regular expression matched against one request variable, after nothing:
    # the only transformation the output has is case, through the `~*` prefix.
    capabilities = Capabilities(
        dialect="pcre",
        operators=frozenset({"rx", "pm", "pmFromFile"}),
        transformations=frozenset({"lowercase"}),
        case_insensitive=True,
        locations={
            "request-uri": Target("$request_uri"),
            "request-filename": Target("$uri"),
            "request-method": Target("$request_method"),
            "query-string": Target(
                "$args", "the query string only: arguments in the request body are not seen"),
            "user-agent": Target("$http_user_agent"),
            "host": Target("$http_host"),
            "referer": Target("$http_referer"),
            "content-type": Target("$http_content_type"),
        },
        faithful=lambda argument: argument.replace("(?i)", "").strip(),
    )

    def compile(self, ir: IR) -> Compiled:
        return generate_nginx_waf(ir.rules, ir.crs_ref, ir.data_files)
