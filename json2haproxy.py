"""Deprecated: use `python3 -m patterns build --target haproxy`. Kept for one release."""

import sys

from patterns.cli import run_legacy

if __name__ == "__main__":
    sys.exit(run_legacy("haproxy"))
