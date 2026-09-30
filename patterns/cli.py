"""
The command line: `python3 -m patterns <command>`.

    list                         the targets there are
    validate [--input FILE]      check an IR file against its schema
    build --target T | --all     compile the IR into a target's files
          [--input FILE] [--out DIR] [--check]

`build` writes each target under `--out` (default `waf_patterns`) in a directory
named after it. With `--check` it writes nothing and exits 1 if the files on
disk are not what the IR produces, which is how CI tells a stale commit.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from patterns import backends, ir

logger = logging.getLogger("patterns")

DEFAULT_OUT = Path("waf_patterns")

# The backends ask Python's `re` whether a pattern compiles, and `re` changed.
# From 3.11 a global flag such as `(?i)` anywhere but the start of the pattern is
# an error, where before it was accepted. Four Apache rules are in one output and
# not in the other, so the committed files are the 3.11 ones.
OUTPUT_PYTHON = (3, 11)


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _warn_if_python_is_old() -> None:
    if sys.version_info < OUTPUT_PYTHON:
        logger.warning(
            "Python %d.%d: the output is built with %d.%d or later. Older versions accept "
            "some patterns newer ones reject, so this may write rules the committed files "
            "do not have.", *sys.version_info[:2], *OUTPUT_PYTHON)


def build_target(target: str, rules: ir.IR, directory: Path, check: bool = False) -> List[str]:
    """
    Builds one target into `directory`, or compares what is there.

    Args:
        target: A registered backend name.
        rules: The IR.
        directory: Where the target's files go.
        check: Compare instead of write.

    Returns:
        With `check`, what is wrong: one line per file that is missing or
        differs. Empty otherwise, and empty when everything matches.
    """
    files: Dict[str, str] = backends.get(target).render(rules)
    problems: List[str] = []
    for relative in sorted(files):
        path = directory / relative
        content = files[relative].encode("utf-8")
        if check:
            if not path.is_file():
                problems.append(f"missing: {path}")
            elif path.read_bytes() != content:
                problems.append(f"differs: {path}")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        logger.info(f"Wrote {path}")
    return problems


def _list(args: argparse.Namespace) -> int:
    for name in backends.names():
        print(f"{name:10} {backends.get(name).title}")
    return 0


def _validate(args: argparse.Namespace) -> int:
    try:
        problems = ir.validate(args.input)
    except ImportError:
        print("validate needs the `jsonschema` package: pip install -r requirements.txt", file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f"cannot read {args.input}: {e}", file=sys.stderr)
        return 1
    for problem in problems:
        print(problem)
    if problems:
        print(f"{args.input}: {len(problems)} problem(s)", file=sys.stderr)
        return 1
    print(f"{args.input}: valid")
    return 0


def _build(args: argparse.Namespace) -> int:
    targets = backends.names() if args.all else args.target
    _warn_if_python_is_old()
    try:
        rules = ir.load(args.input)
    except (OSError, ValueError) as e:
        print(f"cannot read {args.input}: {e}", file=sys.stderr)
        return 1
    logger.info(f"Loaded {len(rules.rules)} rules ({rules.crs_ref}).")

    problems: List[str] = []
    for target in targets:
        problems += build_target(target, rules, args.out / target, check=args.check)

    if args.check:
        for problem in problems:
            print(problem)
        if problems:
            print(f"{len(problems)} file(s) are not what {args.input} produces; "
                  "run `python3 -m patterns build --all` and commit the result", file=sys.stderr)
            return 1
        print(f"{', '.join(targets)}: output matches {args.input}")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m patterns",
        description="Compile the OWASP CRS intermediate representation into web server configuration.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("list", help="list the targets").set_defaults(run=_list)

    validate = commands.add_parser("validate", help="check an IR file against its schema")
    validate.add_argument("--input", type=Path, default=ir.DEFAULT_INPUT, help="the IR file (default: owasp_rules.json)")
    validate.set_defaults(run=_validate)

    build = commands.add_parser("build", help="compile the IR into a target's files")
    which = build.add_mutually_exclusive_group(required=True)
    which.add_argument("--target", action="append", choices=backends.names(),
                       help="a target to build; repeat for several")
    which.add_argument("--all", action="store_true", help="build every target")
    build.add_argument("--input", type=Path, default=ir.DEFAULT_INPUT, help="the IR file (default: owasp_rules.json)")
    build.add_argument("--out", type=Path, default=DEFAULT_OUT,
                       help="where targets go, one directory each (default: waf_patterns)")
    build.add_argument("--check", action="store_true",
                       help="write nothing; exit 1 if the files on disk differ from what the IR produces")
    build.set_defaults(run=_build)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _configure_logging()
    args = _parser().parse_args(argv)
    return args.run(args)


def run_legacy(target: str) -> int:
    """
    What `json2<target>.py` does: one target, configured by environment.

    `INPUT_FILE` and `OUTPUT_DIR` are the variables those scripts read, and
    `OUTPUT_DIR` is the directory of the target itself, not a root.
    """
    _configure_logging()
    _warn_if_python_is_old()
    print(f"json2{target}.py is deprecated: use `python3 -m patterns build --target {target}`",
          file=sys.stderr)
    default_dir = DEFAULT_OUT / target
    try:
        rules = ir.load(os.getenv("INPUT_FILE", str(ir.DEFAULT_INPUT)))
        build_target(target, rules, Path(os.getenv("OUTPUT_DIR", str(default_dir))))
    except Exception as e:
        logger.critical(f"Script failed: {e}")
        return 1
    return 0
