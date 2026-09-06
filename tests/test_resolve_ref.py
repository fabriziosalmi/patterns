#!/usr/bin/env python3
"""
Upstream tag resolution.

The default `v4.0` was matched as a string prefix and the candidates ordered as
strings, so it resolved to `v4.0.0-rc2`: a release candidate sorts above its own
release because it is the longer string. Every build converted that 2023 release
candidate while the release notes advertised the current version (#43).

The cases below are the ones that got it wrong. No network: the tag list is
supplied directly.

Usage:
    python3 tests/test_resolve_ref.py
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import owasp2json  # noqa: E402

# The real upstream list, trimmed to what matters here.
UPSTREAM_TAGS = [
    "nightly",
    "v3.3.0", "v3.3.5",
    "v4.0.0-rc1", "v4.0.0-rc2", "v4.0.0",
    "v4.1.0", "v4.9.0", "v4.10.0", "v4.28.0", "v4.29.0",
]

failures = 0
checks = 0


def check(description, actual, expected):
    global failures, checks
    checks += 1
    if actual != expected:
        failures += 1
        print(f"  FAIL  {description}")
        print(f"        expected {expected!r}, got {actual!r}")


def resolve(requested, tags=UPSTREAM_TAGS):
    """Calls the resolver with the tag list supplied instead of fetched."""
    original = owasp2json.fetch_tags
    owasp2json.fetch_tags = lambda session: list(tags)
    try:
        return owasp2json.resolve_ref(session=None, requested=requested)
    finally:
        owasp2json.fetch_tags = original


print("\nversion ordering")
check("a release sorts above its own release candidate",
      max(["v4.0.0", "v4.0.0-rc2"], key=owasp2json._version_key), "v4.0.0")
check("ordering is numeric, not lexicographic",
      max(["v4.9.0", "v4.29.0"], key=owasp2json._version_key), "v4.29.0")
check("a non-version tag has no key", owasp2json._version_key("nightly"), None)
check("a release candidate is a pre-release", owasp2json.is_prerelease("v4.0.0-rc2"), True)
check("a release is not", owasp2json.is_prerelease("v4.0.0"), False)

print("resolution")
check("latest is the newest stable release", resolve("latest"), "v4.29.0")
check("the prefix that used to give a release candidate", resolve("v4.0"), "v4.0.0")
check("a major prefix is resolved by version, not by string",
      resolve("v4"), "v4.29.0")
check("an exact tag is used as given", resolve("v4.1.0"), "v4.1.0")
check("an exact pre-release is honoured when named",
      resolve("v4.0.0-rc2"), "v4.0.0-rc2")
check("a pre-release is never chosen by a prefix",
      resolve("v4.0.0", ["v4.0.0-rc1", "v4.0.0-rc2"]), None)
check("an unknown ref resolves to nothing", resolve("v99"), None)
check("no tags at all resolves to nothing", resolve("latest", []), None)
check("nightly is not mistaken for a version", resolve("latest", ["nightly"]), None)

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
