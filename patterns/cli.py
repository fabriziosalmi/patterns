"""
The command line: `python3 -m patterns <command>`.

    list                         the targets there are
    validate [--input FILE]      check an IR file against its schema
    build --target T | --all     compile the IR into a target's files
          [--input FILE] [--out DIR] [--check]
    coverage [--json]            what each target does with each rule
             [--write | --check]
    diff OLD NEW                 what changed between two versions of the rules
         [--json FILE] [--no-targets]

`build` writes each target under `--out` (default `waf_patterns`) in a directory
named after it, and with `--all` the coverage matrix as `coverage.json` beside
them. It refuses to write anything if a target would write a regular expression
its engine does not compile. With `--check` it writes nothing and exits 1 if the
files on disk are not what the IR produces, which is how CI tells a stale commit.

`diff` compares two IR files by rule and, unless `--no-targets`, says what the
change does to each target. It prints the summary as Markdown and `--json` writes
the whole of it. It reports and does not judge: it exits 0 whatever it finds.

`coverage` prints the matrix as a table. `--write` puts that table in the files
that show it (README.md and docs/coverage.md, between `coverage:start` and
`coverage:end`), and `--check` exits 1 if they are out of date.
"""

import argparse
import logging
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

from patterns import backends, coverage, diff, ir
from patterns.backends import Compiled

logger = logging.getLogger("patterns")

DEFAULT_OUT = Path("waf_patterns")
COVERAGE_FILE = "coverage.json"

# Where the coverage table is shown. Each file holds one block of it, between
# these two lines, and `coverage --write` replaces what is between them.
COVERAGE_DOCS = ("README.md", "docs/coverage.md")
_BLOCK = re.compile(r"(<!-- coverage:start -->\n)(.*?)(<!-- coverage:end -->)", re.DOTALL)

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


def write_files(files: Dict[str, str], directory: Path, check: bool = False) -> List[str]:
    """
    Writes files into `directory`, or compares what is there.

    Returns:
        With `check`, what is wrong: one line per file that is missing or
        differs. Empty otherwise, and empty when everything matches.
    """
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


def build_target(target: str, rules: ir.IR, directory: Path, check: bool = False) -> List[str]:
    """
    Builds one target into `directory`, or compares what is there.

    Args:
        target: A registered backend name.
        rules: The IR.
        directory: Where the target's files go.
        check: Compare instead of write.

    Returns:
        With `check`, what is wrong. See `write_files`.
    """
    return write_files(backends.get(target).render(rules), directory, check)


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

    compiled: Dict[str, Compiled] = {t: backends.get(t).compile(rules) for t in targets}

    # A regular expression the target's engine refuses is a configuration that
    # does not load. Nothing is written if a backend would write one.
    if sys.version_info >= OUTPUT_PYTHON:
        refused = [line for t in targets
                   for line in coverage.dialect_problems(backends.get(t), rules, compiled[t])]
        if refused:
            for line in refused:
                print(line, file=sys.stderr)
            print(f"{len(refused)} expression(s) would not compile on their target; nothing written",
                  file=sys.stderr)
            return 1
    else:
        logger.warning("Python %d.%d: the regular expressions are not checked against the "
                       "targets' engines; that needs %d.%d or later.",
                       *sys.version_info[:2], *OUTPUT_PYTHON)

    problems: List[str] = []
    for target in targets:
        problems += write_files(compiled[target].files, args.out / target, check=args.check)
    if args.all:
        matrix = coverage.to_json(coverage.report(
            rules, {t: (backends.get(t), compiled[t]) for t in targets}))
        problems += write_files({COVERAGE_FILE: matrix}, args.out, check=args.check)

    if args.check:
        for problem in problems:
            print(problem)
        if problems:
            print(f"{len(problems)} file(s) are not what {args.input} produces; "
                  "run `python3 -m patterns build --all` and commit the result", file=sys.stderr)
            return 1
        print(f"{', '.join(targets)}: output matches {args.input}")
    return 0


def _matrix(path: Path) -> Dict:
    """The coverage matrix of every target, from the IR at `path`."""
    rules = ir.load(path)
    return coverage.report(rules, {n: (backends.get(n), backends.get(n).compile(rules))
                                   for n in backends.names()})


def _coverage(args: argparse.Namespace) -> int:
    # The backends log every rule they drop, which is what this command is here
    # to summarise.
    logging.getLogger().setLevel(logging.ERROR)
    try:
        data = _matrix(args.input)
    except (OSError, ValueError) as e:
        print(f"cannot read {args.input}: {e}", file=sys.stderr)
        return 1
    table = coverage.to_markdown(data)

    if not (args.write or args.check):
        print(coverage.to_json(data) if args.json else table, end="")
        return 0

    stale: List[str] = []
    for name in COVERAGE_DOCS:
        path = ir.REPO_ROOT / name
        text = path.read_text(encoding="utf-8")
        if not _BLOCK.search(text):
            print(f"{name}: no coverage:start / coverage:end block", file=sys.stderr)
            return 1
        updated = _BLOCK.sub(lambda m: m.group(1) + table + m.group(3), text)
        if updated != text:
            stale.append(name)
            if args.write:
                path.write_text(updated, encoding="utf-8")
                logger.info(f"Updated {name}")
    if args.check and stale:
        print(f"{', '.join(stale)}: the coverage table is out of date; "
              "run `python3 -m patterns coverage --write`", file=sys.stderr)
        return 1
    return 0


def _diff(args: argparse.Namespace) -> int:
    logging.getLogger().setLevel(logging.ERROR)
    try:
        old, new = ir.load(args.old), ir.load(args.new)
    except (OSError, ValueError) as e:
        print(f"cannot read the rules: {e}", file=sys.stderr)
        return 1
    change = diff.compare(old, new, targets=not args.no_targets)
    if args.json:
        args.json.write_text(diff.to_json(change), encoding="utf-8")
    print(diff.to_markdown(change, args.limit), end="")
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

    show = commands.add_parser("coverage", help="what each target does with each rule")
    show.add_argument("--input", type=Path, default=ir.DEFAULT_INPUT, help="the IR file (default: owasp_rules.json)")
    show.add_argument("--json", action="store_true", help="print coverage.json instead of the table")
    mode = show.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="put the table in README.md and docs/coverage.md")
    mode.add_argument("--check", action="store_true",
                      help="exit 1 if the table in README.md and docs/coverage.md is out of date")
    show.set_defaults(run=_coverage)

    compare = commands.add_parser("diff", help="what changed between two versions of the rules")
    compare.add_argument("old", type=Path, help="the earlier IR file")
    compare.add_argument("new", type=Path, help="the later IR file")
    compare.add_argument("--json", type=Path, help="write the whole change here (changes.json)")
    compare.add_argument("--no-targets", action="store_true",
                         help="do not compile both versions to say what the change does to each target")
    compare.add_argument("--limit", type=int, default=25,
                         help="how many rules to list under each heading (default: 25)")
    compare.set_defaults(run=_diff)
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
