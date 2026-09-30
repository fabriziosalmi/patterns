"""
Regular expression dialects: what a target's engine compiles.

A pattern that does not compile on a target is not an approximation of the rule.
It is a configuration that fails to load, or a rule that never loads. Python's
`re` answers a related question, and answers it differently from version to
version: from 3.11 a global flag such as `(?i)` anywhere but the start of a
pattern is an error, where before it was accepted, and PCRE accepts it in both.

So a dialect here is a parse plus a list of constructs the engine does not have,
and neither depends on what `re` happens to reject:

    pcre   nginx, Apache (ModSecurity) and HAProxy built with PCRE2. Anything
           Python can parse after the PCRE-only syntax is rewritten.
    re2    Go's `regexp`, which Traefik plugins use. No lookaround, no
           backreference, no atomic group, no possessive quantifier, no
           conditional.

A dialect check is meant for Python 3.11 or later, where the parser knows atomic
groups and possessive quantifiers.
"""

import re
from typing import Dict, FrozenSet, List, Optional

try:  # 3.11 and later
    from re import _parser as sre_parse
    from re import _constants as sre_constants
except ImportError:  # pragma: no cover
    import sre_parse
    import sre_constants

# The PCRE constructs Python's re does not parse. Each entry rewrites one into
# something Python accepts, for the check only: what is written is always the
# pattern CRS wrote.
_PCRE_ONLY = (
    # \x{263a}: a hex escape wider than two digits.
    (re.compile(r"(?<!\\)\\x\{([0-9A-Fa-f]{1,6})\}"),
     lambda m: ("\\u%04x" if int(m.group(1), 16) <= 0xFFFF else "\\U%08x")
     % int(m.group(1), 16)),
    # \z: end of subject. Python spells it \Z.
    (re.compile(r"(?<!\\)\\z"), lambda m: "\\Z"),
    # (?<name>...): Python requires (?P<name>...).
    (re.compile(r"\(\?<([A-Za-z_]\w*)>"), lambda m: "(?P<%s>" % m.group(1)),
)

# A global flag group, `(?i)`. PCRE accepts it anywhere and applies it from there.
_GLOBAL_FLAGS = re.compile(r"\(\?[aiLmsux]+\)")

# What each dialect does not have, by the name of the construct.
FORBIDDEN: Dict[str, FrozenSet[str]] = {
    "pcre": frozenset(),
    "re2": frozenset({"lookaround", "backreference", "atomic group",
                      "possessive quantifier", "conditional"}),
}


def python_equivalent(pattern: str) -> str:
    """Rewrites PCRE-only syntax so Python's parser accepts the pattern."""
    for expression, replacement in _PCRE_ONLY:
        pattern = expression.sub(replacement, pattern)
    return pattern


def _parse(pattern: str):
    """
    Parses a pattern, tolerating a global flag that is not at the start.

    The flag does not change which constructs the pattern uses, which is all the
    check reads, so it is dropped on the second try.
    """
    text = python_equivalent(pattern)
    try:
        return sre_parse.parse(text)
    except re.error as e:
        if "global flags not at the start" not in str(e):
            raise
        return sre_parse.parse(_GLOBAL_FLAGS.sub("", text))


def _constructs(tree) -> List[str]:
    """The names of the constructs in a parsed pattern that dialects disagree on."""
    found: List[str] = []
    names = {
        getattr(sre_constants, "ASSERT", None): "lookaround",
        getattr(sre_constants, "ASSERT_NOT", None): "lookaround",
        getattr(sre_constants, "GROUPREF", None): "backreference",
        getattr(sre_constants, "GROUPREF_EXISTS", None): "conditional",
        getattr(sre_constants, "ATOMIC_GROUP", None): "atomic group",
        getattr(sre_constants, "POSSESSIVE_REPEAT", None): "possessive quantifier",
    }

    def walk(items) -> None:
        for op, value in items:
            if op in names:
                found.append(names[op])
            if isinstance(value, (list, tuple)):
                for part in value:
                    if isinstance(part, sre_parse.SubPattern):
                        walk(part)
                    elif isinstance(part, (list, tuple)):
                        for inner in part:
                            if isinstance(inner, sre_parse.SubPattern):
                                walk(inner)
            elif isinstance(value, sre_parse.SubPattern):
                walk(value)

    walk(tree)
    return found


def check(dialect: str, pattern: str) -> Optional[str]:
    """
    Reports why a pattern does not compile in a dialect.

    Returns:
        A message, or None when the dialect accepts the pattern.

    Raises:
        KeyError: The dialect is not known.
    """
    forbidden = FORBIDDEN[dialect]
    try:
        tree = _parse(pattern)
    except (re.error, RecursionError, OverflowError) as e:
        return f"does not parse: {e}"
    used = sorted({name for name in _constructs(tree) if name in forbidden})
    if used:
        return f"uses {', '.join(used)}, which {dialect} does not have"
    return None
