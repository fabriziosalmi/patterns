#!/usr/bin/env python3
"""
The command line, the registry, and whether a build gives the same files twice.

Four scripts did one job each, shared nothing, and two of them wrote a `set`. A
`set` of strings iterates in an order that depends on the hash seed of the
process, so `json2apache.py` and `json2traefik.py` produced different files on
every run from the same input (23 differing files between two runs). That made
"the committed output is what the generator produces" impossible to state, let
alone to check, and it is why the committed Apache files were a different
sample of the same rules from the ones a fresh run gives.

This checks:

  * `list`, `validate` and `build` do what they say, and fail the way they say;
  * `build --check` tells a stale commit from a current one, which is what CI
    runs on the committed `waf_patterns/`;
  * the output is the same across hash seeds, for every target;
  * the committed `waf_patterns/` is what the committed IR produces;
  * the registry takes a new target without any other file changing;
  * the `json2*.py` entry points still work and give the same files;
  * code that was copied four times is not copied again.

The committed output is built with Python 3.11 or later, which is what the docs
ask for and what CI runs: the dialect check needs the parser of 3.11 to see atomic
groups and possessive quantifiers, which Go's RE2 does not have. Below 3.11 the two
checks that compare with the committed files are skipped and say so.

Usage:
    python3 tests/test_cli.py
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from patterns import backends  # noqa: E402
from patterns.backends import Compiled  # noqa: E402
from patterns.ir import IR  # noqa: E402

failures = 0
checks = 0


def check(description, actual, expected=True):
    global failures, checks
    checks += 1
    if actual != expected:
        failures += 1
        print(f"  FAIL  {description}")
        print(f"        expected {expected!r}, got {actual!r}")


def patterns(*args, seed=None, cwd=REPO_ROOT):
    """Runs `python3 -m patterns ...` and returns (exit code, stdout, stderr)."""
    env = dict(os.environ)
    if seed is not None:
        env["PYTHONHASHSEED"] = str(seed)
    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-m", "patterns", *args],
        cwd=cwd, env={**env, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True, text=True,
    )
    return result.returncode, result.stdout, result.stderr


def tree(root):
    """Every file under root, by relative path, with its bytes."""
    root = Path(root)
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


TARGETS = ["nginx", "apache", "traefik", "haproxy"]
COMPARABLE = sys.version_info >= (3, 11)
if not COMPARABLE:
    print(f"\nPython {sys.version_info[0]}.{sys.version_info[1]}: the committed output is built "
          "with 3.11 or later, so it is not compared here")
tmp = Path(tempfile.mkdtemp(prefix="patterns-cli-"))

try:
    print("\nlist")
    code, out, _ = patterns("list")
    check("lists the four targets, in build order",
          [line.split()[0] for line in out.splitlines()], TARGETS)
    check("list succeeds", code, 0)

    print("validate")
    code, out, _ = patterns("validate")
    check("the committed IR is valid", (code, out.strip()), (0, "owasp_rules.json: valid"))
    broken = tmp / "broken.json"
    broken.write_text(
        (REPO_ROOT / "owasp_rules.json").read_text().replace('"directive"', '"directiv"', 1))
    code, out, err = patterns("validate", "--input", str(broken))
    check("a document that breaks the schema is refused", code, 1)
    check("and the problem says where it is", bool(re.search(r"^rules\[0\]", out, re.M)), True)
    code, _, err = patterns("validate", "--input", str(tmp / "nope.json"))
    check("a file that is not there is an error, not a traceback",
          (code, "Traceback" in err), (1, False))

    print("build")
    out_a = tmp / "a"
    code, _, _ = patterns("build", "--all", "--out", str(out_a))
    check("builds every target", code, 0)
    check("one directory per target, and the coverage matrix beside them",
          sorted(p.name for p in out_a.iterdir()), sorted(TARGETS + ["coverage.json"]))
    code, _, _ = patterns("build", "--target", "nginx", "--out", str(tmp / "one"))
    check("a build of one target writes no coverage matrix",
          sorted(p.name for p in (tmp / "one").iterdir()), ["nginx"])
    check("nginx writes its maps, its rules and its README",
          sorted(p.name for p in (out_a / "nginx").iterdir()),
          ["README.md", "waf_maps.conf", "waf_rules.conf"])
    code, _, _ = patterns("build", "--target", "haproxy", "--target", "traefik",
                          "--out", str(tmp / "two"))
    check("--target can be repeated", sorted(p.name for p in (tmp / "two").iterdir()),
          ["haproxy", "traefik"])
    code, _, err = patterns("build", "--target", "nosuch")
    check("an unknown target is a usage error that names the ones there are",
          (code, "nginx" in err), (2, True))
    code, _, _ = patterns("build")
    check("so is asking for nothing", code, 2)
    code, _, err = patterns("build", "--all", "--input", str(tmp / "nope.json"),
                            "--out", str(tmp / "never"))
    check("a missing input stops before anything is written",
          (code, (tmp / "never").exists()), (1, False))

    print("the committed output is what the IR produces")
    if COMPARABLE:
        code, out, _ = patterns("build", "--all", "--check")
        check("build --all --check passes on the committed waf_patterns/", (code, out.strip()),
              (0, "nginx, apache, traefik, haproxy: output matches owasp_rules.json"))
        committed = tree(REPO_ROOT / "waf_patterns")
        check("coverage.json is the file committed",
              (out_a / "coverage.json").read_bytes() == committed["coverage.json"], True)
        for target in TARGETS:
            built = tree(out_a / target)
            check(f"{target}: every file built is the file committed",
                  sorted(name for name in built
                         if committed.get(f"{target}/{name}") != built[name]), [])
    code, _, err = patterns("build", "--target", "traefik", "--out", str(tmp / "warn"))
    check("an old Python says its output may differ",
          ("the output is built with" in err), sys.version_info < (3, 11))

    print("nothing in a target's directory that is not written")
    # What ships in an archive is the whole directory. The nginx directory held seventeen
    # per-category files from January 2025 that the generator stopped writing long before
    # (their regular expressions are the ones #50 fixed, and their header tells people to
    # include them in a server block, where a `map` is not allowed). A directory holds what
    # the backend renders, the bad-bot list badbots.py writes, and a README.
    BOTS = {"nginx": "bots.conf", "apache": "bots.conf", "traefik": "bots.toml", "haproxy": "bots.acl"}
    for target in TARGETS:
        rendered = {p.relative_to(out_a / target).as_posix() for p in (out_a / target).rglob("*") if p.is_file()}
        present = {p.relative_to(REPO_ROOT / "waf_patterns" / target).as_posix()
                   for p in (REPO_ROOT / "waf_patterns" / target).rglob("*") if p.is_file()}
        check(f"{target}: every file in the directory is written by something",
              sorted(present - rendered - {BOTS[target], "README.md"}), [])

    print("--check sees what is stale")
    stale = tmp / "stale"
    shutil.copytree(out_a, stale)
    code, _, _ = patterns("build", "--all", "--out", str(stale), "--check")
    check("a current tree passes", code, 0)
    with open(stale / "nginx" / "waf_maps.conf", "ab") as f:
        f.write(b"# edited by hand\n")
    code, out, _ = patterns("build", "--all", "--out", str(stale), "--check")
    check("a file edited by hand is reported", (code, "differs: " + str(stale / "nginx" / "waf_maps.conf") in out), (1, True))
    shutil.copy(out_a / "nginx" / "waf_maps.conf", stale / "nginx" / "waf_maps.conf")
    (stale / "haproxy" / "waf.acl").unlink()
    code, out, _ = patterns("build", "--all", "--out", str(stale), "--check")
    check("a file that is gone is reported", (code, "missing: " + str(stale / "haproxy" / "waf.acl") in out), (1, True))
    check("--check writes nothing", (stale / "haproxy" / "waf.acl").exists(), False)

    print("the same files every time")
    by_seed = {}
    for seed in (1, 2, 3):
        destination = tmp / f"seed{seed}"
        patterns("build", "--all", "--out", str(destination), seed=seed)
        by_seed[seed] = tree(destination)
    check("coverage.json: three hash seeds, the same bytes",
          by_seed[1]["coverage.json"] == by_seed[2]["coverage.json"] == by_seed[3]["coverage.json"], True)
    for target in TARGETS:
        names = {s: {n for n in t if n.startswith(target + "/")} for s, t in by_seed.items()}
        differing = sorted(
            name for name in names[1]
            if not (by_seed[1][name] == by_seed[2][name] == by_seed[3][name]))
        check(f"{target}: three hash seeds, the same bytes", differing, [])

    print("the registry")
    class Dummy(backends.Backend):
        name = "dummy"
        title = "Dummy"

        def compile(self, ir):
            return Compiled({"rules.txt": f"{len(ir.rules)} rules from {ir.crs_ref}\n"})

    backends.register(Dummy)
    try:
        check("a registered target is found by name", backends.get("dummy").title, "Dummy")
        check("and listed after the ones there already were",
              backends.names(), TARGETS + ["dummy"])
        check("it renders from an IR",
              backends.get("dummy").render(IR(rules=[{}, {}], crs_ref="v1")),
              {"rules.txt": "2 rules from v1\n"})
        try:
            backends.register(Dummy)
            duplicated = False
        except ValueError:
            duplicated = True
        check("a name cannot be registered twice", duplicated, True)
    finally:
        del backends._REGISTRY["dummy"]
    try:
        backends.get("nosuch")
        message = ""
    except KeyError as e:
        message = str(e)
    check("an unknown name says which ones are known", all(t in message for t in TARGETS), True)

    print("the scripts that came before")
    for target in TARGETS:
        legacy = tmp / "legacy" / target
        result = subprocess.run(
            [sys.executable, "-W", "ignore", f"json2{target}.py"], cwd=REPO_ROOT,
            env={**os.environ, "OUTPUT_DIR": str(legacy), "PYTHONHASHSEED": "1"},
            capture_output=True, text=True)
        check(f"json2{target}.py still works and says it is deprecated",
              (result.returncode, "deprecated" in result.stderr), (0, True))
        check(f"json2{target}.py writes what the CLI writes",
              tree(legacy), {n[len(target) + 1:]: b for n, b in by_seed[1].items()
                             if n.startswith(target + "/")})
    result = subprocess.run(
        [sys.executable, "-W", "ignore", "json2nginx.py"], cwd=REPO_ROOT,
        env={**os.environ, "INPUT_FILE": str(tmp / "nope.json"), "OUTPUT_DIR": str(tmp / "x")},
        capture_output=True, text=True)
    check("and fails with 1 on an input it cannot read", result.returncode, 1)

    print("what was copied four times")
    source = {p: p.read_text() for p in
              list(REPO_ROOT.glob("*.py")) + list((REPO_ROOT / "patterns").rglob("*.py"))
              if p.name != "owasp2json.py"}

    def defined_in(pattern):
        return sorted(str(p.relative_to(REPO_ROOT)) for p, text in source.items()
                      if re.search(pattern, text, re.M))

    check("no converter carries its own copy of the loader",
          defined_in(r"^def load_owasp_rules\(|^def load_provenance_ref\("), [])
    check("the provenance header is written in one place",
          defined_in(r"^def provenance_header\("), ["patterns/backends/_common.py"])
    check("the file-lookup operators no backend can carry are listed in one place",
          defined_in(r'^UNSUPPORTED_\w+ = \["@pmFromFile"'), [])

finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
