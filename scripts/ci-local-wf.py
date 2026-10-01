#!/usr/bin/env python3
"""Run the `run:` steps of a GitHub Actions workflow job locally, in order.

Adapted from fabriziosalmi/zion `scripts/ci-local-wf.py` (Apache-2.0), for this repository: the
repository name and the base branch are this one's, there is no Rust toolchain to select, and
`actions/setup-python` is honoured (see below), because the workflows here pin Python 3.11 and
run a 3.11 / 3.13 matrix, and the box's system Python is neither.

This is how `scripts/ci-local.sh` mirrors CI without a second copy of the commands:
the steps are read from `.github/workflows/*.yml`, so a change to a workflow is
picked up here automatically and the two cannot drift.

What it does, per job (and per `strategy.matrix.include` entry):
  * runs every step that has a `run:`; steps with `uses:` (checkout, node and cache
    setup) are skipped: the box is provisioned by `ci-local-setup.sh` and the repo is
    already checked out. `actions/setup-python` is not skipped: its `python-version`
    becomes a `uv` virtual environment put first on PATH for the rest of the job, which
    is what the action does on GitHub, with `pip` in it;
  * applies workflow, job and step `env:`, `working-directory:` and `shell`
    semantics (`bash -eo pipefail`, GitHub's default on Linux);
  * substitutes `${{ matrix.* }}`, `${{ env.* }}`, `${{ github.workspace }}`,
    `${{ runner.os|temp }}`; anything else is an error, not a silent empty string;
  * evaluates simple `if:` conditions (`==`, `!=`, `&&`, `||`, `!`, `always()`,
    `success()`, `failure()`); `always()` steps run even after a failure, like on
    GitHub, so teardown steps (kill the backend, ...) still happen;
  * emulates `$GITHUB_OUTPUT`, `$GITHUB_ENV`, `$GITHUB_PATH`, `$GITHUB_STEP_SUMMARY`.

It does NOT emulate: `needs:` ordering across jobs, services/containers, secrets,
`environment:` deploy jobs. Select the jobs you want explicitly.

Usage:
  ci-local-wf.py <workflow> [job ...] [--skip 'substr']... [--before-leg CMD] [--dry-run]
  <workflow> is a file name or the stem: `ci`, `integration`, ...
"""
from __future__ import annotations

import argparse
import itertools
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML missing: apt-get install -y python3-yaml")

ROOT = Path(__file__).resolve().parent.parent
EXPR = re.compile(r"\$\{\{\s*(.+?)\s*\}\}")


class Unsupported(Exception):
    pass


def lookup(name: str, ctx: dict) -> str:
    """Resolve `matrix.x`, `env.X`, `github.workspace`, `runner.os` ..."""
    scope, _, key = name.partition(".")
    def git(*a: str) -> str:
        return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()

    table = {
        "matrix": ctx["matrix"],
        "env": ctx["env"],
        "github": {"workspace": str(ROOT), "ref": "refs/heads/local", "event_name": "local",
                   "run_id": "0", "repository": "fabriziosalmi/patterns", "sha": git("rev-parse", "HEAD"),
                   # a PR's range is merge-base(origin/main, HEAD)..HEAD
                   "event.pull_request.base.sha": os.environ.get("CI_LOCAL_BASE") or git("merge-base", "origin/main", "HEAD"),
                   "event.pull_request.head.sha": git("rev-parse", "HEAD")},
        "runner": {"os": "Linux", "arch": "X64", "temp": ctx["runner_temp"]},
    }.get(scope)
    if table is None or key not in table:
        raise Unsupported(f"unsupported expression ${{{{ {name} }}}}")
    v = table[key]
    return "" if v is None else str(v)


def subst(text: str, ctx: dict) -> str:
    return EXPR.sub(lambda m: lookup(m.group(1), ctx), str(text))


def eval_if(cond, ctx: dict, failed: bool) -> bool:
    """Tiny `if:` evaluator. Anything it cannot parse raises Unsupported."""
    if cond is None:
        return not failed
    s = str(cond).strip()
    if s.startswith("${{") and s.endswith("}}"):
        s = s[3:-2].strip()
    if "always()" in s:
        return True
    if s == "success()":
        return not failed
    if s == "failure()":
        return failed

    def atom(a: str) -> bool:
        a = a.strip()
        neg = False
        while a.startswith("!"):
            neg, a = not neg, a[1:].strip()
        m = re.fullmatch(r"([\w.]+)\s*(==|!=)\s*'([^']*)'", a)
        if m:
            val = lookup(m.group(1), ctx)
            r = (val == m.group(3)) if m.group(2) == "==" else (val != m.group(3))
        elif re.fullmatch(r"[\w.]+", a):
            r = lookup(a, ctx) not in ("", "false", "0")
        else:
            raise Unsupported(f"unsupported condition: {cond!r}")
        return (not r) if neg else r

    ok = any(all(atom(p) for p in alt.split("&&")) for alt in s.split("||"))
    return ok and not failed


def translate_uses(step: dict, ctx: dict) -> str | None:
    """A few `uses:` actions are really just a command; run that command locally.

    None of the actions of these workflows is, so this is a hook and not a table: everything
    (checkout, node and cache setup, artifact upload, pages) is skipped, because the box is
    provisioned by ci-local-setup.sh. `actions/setup-python` is handled by `python_venv`.
    Returning None = skip.
    """
    return None


def python_venv(version: str, tmp: Path) -> Path:
    """
    The `bin` directory of a virtual environment for this Python, made with `uv` if it is not there.

    `actions/setup-python` puts that version first on PATH, with pip. The environment is kept
    between runs, so the packages a job installs are installed once: a GitHub leg gets a fresh
    runner, and a stale package here would be the one thing that makes the two differ, so
    `pip install` still runs in every job, and what it finds already installed it leaves.
    """
    cache = Path(os.environ.get("CI_LOCAL_CACHE", Path.home() / ".cache" / "ci-local"))
    venv = cache / f"venv-{version}"
    if not (venv / "bin" / "python").exists():
        cache.mkdir(parents=True, exist_ok=True)
        subprocess.run(["uv", "venv", "--seed", "--python", version, str(venv)], check=True)
    return venv / "bin"


def matrices(job: dict) -> list[dict]:
    m = (job.get("strategy") or {}).get("matrix")
    if not m:
        return [{}]
    m = dict(m)
    include = m.pop("include", [])
    m.pop("exclude", None)
    combos = [dict(zip(m, vals)) for vals in itertools.product(*m.values())] if m else []
    return (combos + [dict(i) for i in include]) or [{}]


def run_job(wf: dict, wf_name: str, jname: str, args, matrix: dict) -> bool:
    job = wf["jobs"][jname]
    label = f"{wf_name}:{jname}" + (f" [{', '.join(f'{k}={v}' for k, v in matrix.items() if k in ('python-version', 'os', 'name'))}]" if matrix else "")
    print(f"\n\033[1;36m━━━ {label}\033[0m", flush=True)

    tmp = Path(tempfile.mkdtemp(prefix="ci-local-"))
    ctx = {"matrix": matrix, "env": {}, "runner_temp": str(tmp)}
    env = dict(os.environ)
    env.update({
        "CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ROOT),
        "GITHUB_REPOSITORY": "fabriziosalmi/patterns", "RUNNER_OS": "Linux", "RUNNER_TEMP": str(tmp),
        "GITHUB_OUTPUT": str(tmp / "output"), "GITHUB_ENV": str(tmp / "env"),
        "GITHUB_PATH": str(tmp / "path"), "GITHUB_STEP_SUMMARY": str(tmp / "summary"),
        "GITHUB_EVENT_NAME": "local", "GITHUB_REF": "refs/heads/local",
    })
    for f in ("output", "env", "path", "summary"):
        (tmp / f).touch()
    def add_env(block) -> None:
        for k, v in (block or {}).items():
            ctx["env"][k] = subst(v, ctx)
            env[k] = ctx["env"][k]

    add_env(wf.get("env"))
    add_env(job.get("env"))

    failed = False
    executed = 0
    skipped_uses: list[str] = []
    t0 = time.time()
    for i, step in enumerate(job.get("steps", []), 1):
        name = step.get("name") or f"step {i}"
        try:
            if "run" not in step and step.get("uses", "").startswith("actions/setup-python"):
                version = subst((step.get("with") or {}).get("python-version", ""), ctx)
                if version and not args.dry_run:
                    bin_dir = python_venv(version, tmp)
                    env["PATH"] = f"{bin_dir}:{env['PATH']}"
                    env["VIRTUAL_ENV"] = str(bin_dir.parent)
                print(f"\n\033[1m▶ python {version}\033[0m (actions/setup-python)", flush=True)
                continue
            if "run" not in step:
                cmd = translate_uses(step, ctx) if eval_if(step.get("if"), ctx, failed) else None
                if cmd is None:
                    skipped_uses.append(step.get("uses", "?").split("@")[0])
                    continue
                name = f"{step['uses'].split('@')[0]} -> {cmd}"
                step = {**step, "run": cmd}
            if not eval_if(step.get("if"), ctx, failed):
                continue
            script = subst(step["run"], ctx)
            add_env(step.get("env"))
        except Unsupported as e:
            print(f"\033[33m  skip '{name}': {e}\033[0m")
            continue
        if any(s in script for s in args.skip):
            print(f"\033[33m  skip '{name}' (--skip)\033[0m")
            continue
        wd = ROOT / subst(step.get("working-directory", ""), ctx)
        print(f"\n\033[1m▶ {name}\033[0m", flush=True)
        if args.dry_run:
            print("  " + "\n  ".join(script.strip().splitlines()))
            continue
        p = tmp / "path"
        if p.read_text().strip():
            env["PATH"] = p.read_text().strip().replace("\n", ":") + ":" + env["PATH"]
        executed += 1
        rc = subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=wd, env=env).returncode
        # $GITHUB_ENV: KEY=VALUE lines become env for the following steps
        for line in (tmp / "env").read_text().splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                env[k] = v
        if rc != 0 and not step.get("continue-on-error"):
            failed = True
            print(f"\033[1;31m✗ '{name}' exited {rc}\033[0m", flush=True)
    dt = time.time() - t0
    if not failed and not args.dry_run and executed == 0:
        # A job that ran nothing must never look green: that is a hole in this mirror.
        failed = True
        print(f"\033[1;31m✗ no step was executed\033[0m: every step of {label} is a `uses:` this "
              f"script does not translate ({', '.join(sorted(set(skipped_uses)))})")
    if skipped_uses and not args.dry_run:
        print(f"\033[2m  (skipped setup actions: {', '.join(sorted(set(skipped_uses)))})\033[0m")
    print(f"\033[1;{'31' if failed else '32'}m{'✗ FAILED' if failed else '✓ ok'}\033[0m {label}  ({dt:.0f}s, {executed} step(s))")
    return not failed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("workflow")
    ap.add_argument("jobs", nargs="*")
    ap.add_argument("--skip", action="append", default=[], help="skip steps whose script contains this text")
    ap.add_argument("--python", help="only this matrix leg (matrix.python-version)")
    ap.add_argument("--before-leg", help="shell command run before each matrix leg (a GitHub leg gets a fresh runner; "
                                         "locally, clean up what the previous leg left behind)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    name = args.workflow.removesuffix(".yml")
    path = ROOT / ".github" / "workflows" / f"{name}.yml"
    wf = yaml.safe_load(path.read_text())
    jobs = args.jobs or [j for j, v in wf["jobs"].items() if "environment" not in v]
    ok = True
    for j in jobs:
        if j not in wf["jobs"]:
            sys.exit(f"{name}.yml has no job '{j}' (jobs: {', '.join(wf['jobs'])})")
        for m in matrices(wf["jobs"][j]):
            if args.python and m.get("python-version") != args.python:
                continue
            if args.before_leg and not args.dry_run:
                subprocess.run(["bash", "-c", args.before_leg], cwd=ROOT)
            ok &= run_job(wf, name, j, args, m)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
