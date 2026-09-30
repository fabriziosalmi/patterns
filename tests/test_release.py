#!/usr/bin/env python3
"""
What a release is made of, and what it is called.

The nightly build published every release under one tag, `latest`, which it deleted
and created again each night, so nobody could pin a version or roll back. A release
is now a dated tag that is never deleted, with archives that are the same bytes for
the same files, signed by the workflow. This checks the parts that can be checked
without GitHub:

  * the archives: the same files give the same archive whatever the day, the
    machine's clock or the files' modification times, and one changed byte gives a
    different one; every entry is what it says, with no timestamp;
  * SHA256SUMS lists exactly the files it should, in the format `sha256sum -c`
    reads, and release.json names the tag, the CRS tag, the commit and the rules;
  * the tag: the day and the CRS tag, and a second release on the same day gets a
    new name rather than the old one back;
  * whether a release would say nothing new, so an unchanged night publishes
    nothing, and a change to what changed since yesterday does not count;
  * the workflow never deletes a release or a tag, and never publishes under
    `latest`; and the identity the documentation tells people to verify is the one
    the workflow signs with.

What needs GitHub (the signature, the attestation) is shown by running the
workflow: see the pull request.

Usage:
    python3 tests/test_release.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from patterns import release  # noqa: E402

failures = 0
checks = 0


def check(description, actual, expected=True):
    global failures, checks
    checks += 1
    if actual != expected:
        failures += 1
        print(f"  FAIL  {description}")
        print(f"        expected {expected!r}, got {actual!r}")


def tree(root: Path, files: dict) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return root


tmp = Path(tempfile.mkdtemp(prefix="patterns-release-"))
SOURCE_FILES = {
    "nginx/waf_maps.conf": b"map $args $waf {\n}\n",
    "nginx/waf_rules.conf": b"if ($waf) { return 403; }\n",
    "nginx/README.md": b"# nginx\n",
    "apache/sqli.conf": b"SecRule ARGS x\n",
    "traefik/middleware.toml": b"[http.middlewares]\n",
    "haproxy/waf.acl": b"acl a hdr(x)\n",
}
rules_file = tmp / "owasp_rules.json"
rules_file.write_text(json.dumps({"schema_version": 1, "_provenance": {"source_ref": "v4.29.0"}, "rules": []}))


def build(name, source=None, date="2026-09-30", **kwargs):
    out = tmp / name
    made = release.package(
        out, source or tree(tmp / f"src-{name}", SOURCE_FILES), rules_file, date, "v4.29.0",
        kwargs.pop("commit", "abc123"), "https://example.com/run/1",
        kwargs.pop("existing", []), kwargs.pop("previous", None),
        extra={"coverage.json": tmp / "coverage.json", "changes.json": tmp / "changes.json"})
    return out, made


(tmp / "coverage.json").write_text('{"a":1}\n')
(tmp / "changes.json").write_text('{"b":2}\n')

print("\nthe archives")
out1, made1 = build("one")
# the same files, written later, by a different clock, for another day and commit
src2 = tree(tmp / "src-two", SOURCE_FILES)
for path in src2.rglob("*"):
    os.utime(path, (1_000_000_000, 1_000_000_000))
out2, made2 = build("two", src2, date="2026-10-01", commit="def456")
check("the same files give the same archives, whatever the day, commit or mtime",
      (out1 / "SHA256SUMS").read_text(), (out2 / "SHA256SUMS").read_text())
names = sorted(p.name for p in out1.iterdir())
check("a release holds the archives, what it copied, the hashes, its own record and what is attested",
      names, sorted(["apache_waf.zip", "coverage.json", "changes.json", "haproxy_waf.zip", "nginx_waf.zip",
                     "traefik_waf.zip", "SHA256SUMS", "release.json", "rules-predicate.json"]))
with zipfile.ZipFile(out1 / "nginx_waf.zip") as z:
    entries = z.infolist()
    check("an archive holds the files of its target, sorted, and no directory",
          [e.filename for e in entries], ["README.md", "waf_maps.conf", "waf_rules.conf"])
    check("with no timestamp but the earliest a zip can hold",
          {e.date_time for e in entries}, {release.ZIP_EPOCH})
    check("no extra field, and one set of permissions",
          ({e.extra for e in entries}, {(e.external_attr >> 16) & 0o777 for e in entries}),
          ({b""}, {0o644}))
    check("what is in it is what was in the file",
          z.read("waf_maps.conf"), SOURCE_FILES["nginx/waf_maps.conf"])
    check("and it is a valid archive", z.testzip(), None)
changed = dict(SOURCE_FILES, **{"nginx/waf_maps.conf": b"map $args $waf {\n  x;\n}\n"})
out3, _ = build("three", tree(tmp / "src-three", changed))
sums1 = dict(reversed(l.split("  ")) for l in (out1 / "SHA256SUMS").read_text().splitlines())
sums3 = dict(reversed(l.split("  ")) for l in (out3 / "SHA256SUMS").read_text().splitlines())
check("one changed byte changes that archive", sums1["nginx_waf.zip"] != sums3["nginx_waf.zip"], True)
check("and only that one", sorted(n for n in sums1 if sums1[n] != sums3[n]), ["nginx_waf.zip"])

print("the hashes and the record")
lines = (out1 / "SHA256SUMS").read_text().splitlines()
check("one line per file, sorted", [l.split("  ", 1)[1] for l in lines],
      sorted(["apache_waf.zip", "coverage.json", "changes.json", "haproxy_waf.zip", "nginx_waf.zip",
              "traefik_waf.zip"]))
check("each is the hash of the file, as sha256sum -c reads it",
      all(hashlib.sha256((out1 / n).read_bytes()).hexdigest() == h
          for h, n in (l.split("  ", 1) for l in lines)), True)
check("release.json is not in it: it names the day and the commit, so it differs every night",
      "release.json" in (out1 / "SHA256SUMS").read_text(), False)
record = json.loads((out1 / "release.json").read_text())
check("the record names the tag", record["tag"], "2026-09-30-crs-v4.29.0")
check("the CRS tag it was built from", record["source"]["ref"], "v4.29.0")
check("the commit and the run", (record["commit"], record["run"]), ("abc123", "https://example.com/run/1"))
check("the hash of the rules it was built from",
      record["rules_sha256"], hashlib.sha256(rules_file.read_bytes()).hexdigest())
check("and the hash of each file", record["files"], {n: h for h, n in (l.split("  ", 1) for l in lines)})
predicate = json.loads((out1 / "rules-predicate.json").read_text())
check("what is attested names the CRS tag it was built from", predicate["crs"]["ref"], "v4.29.0")
check("the hash of the rules, their version and how many",
      predicate["rules"],
      {"sha256": hashlib.sha256(rules_file.read_bytes()).hexdigest(), "schema_version": 1, "records": 0})
check("it is not in SHA256SUMS: it is what is said about the files, not one of them",
      "rules-predicate.json" in (out1 / "SHA256SUMS").read_text(), False)

print("the tag")
check("the day and the CRS tag", release.tag_for("2026-09-30", "v4.29.0", []), "2026-09-30-crs-v4.29.0")
check("a second release that day is not the first again",
      release.tag_for("2026-09-30", "v4.29.0", ["2026-09-30-crs-v4.29.0"]), "2026-09-30-crs-v4.29.0-2")
check("nor the second",
      release.tag_for("2026-09-30", "v4.29.0",
                      ["2026-09-30-crs-v4.29.0", "2026-09-30-crs-v4.29.0-2"]), "2026-09-30-crs-v4.29.0-3")
check("another day or another CRS tag is not a clash",
      release.tag_for("2026-10-01", "v4.29.0", ["2026-09-30-crs-v4.29.0"]), "2026-10-01-crs-v4.29.0")
for bad_date, bad_ref in (("yesterday", "v4"), ("2026-9-30", "v4"), ("2026-09-30", "v4/../x"),
                          ("2026-09-30", "v4 29"), ("2026-09-30", "-x"), ("2026-09-30", "")):
    try:
        release.tag_for(bad_date, bad_ref, [])
        refused = False
    except ValueError:
        refused = True
    check(f"a tag that is not one is refused: {bad_date!r} {bad_ref!r}", refused, True)

print("whether a release says anything new")
sums_a = (out1 / "SHA256SUMS").read_text()
check("there is nothing to compare with the first time", release.unchanged(None, sums_a), False)
check("the same rules say nothing new", release.unchanged(sums_a, sums_a), True)
check("a changed archive does", release.unchanged(sums_a, (out3 / "SHA256SUMS").read_text()), False)
other_changes = sums_a.replace(next(l for l in sums_a.splitlines() if l.endswith("changes.json")),
                               "0" * 64 + "  changes.json")
check("what changed since yesterday does not count: it differs the day after a change",
      release.unchanged(sums_a, other_changes), True)
other_coverage = sums_a.replace(next(l for l in sums_a.splitlines() if l.endswith("coverage.json")),
                                "0" * 64 + "  coverage.json")
check("but what each target does with each rule does", release.unchanged(sums_a, other_coverage), False)
check("a previous release with no hashes is not evidence of anything",
      release.unchanged("not a list of hashes\n", sums_a), False)
check("not even of a release that has none either",
      release.unchanged("not a list of hashes\n", "nor is this\n"), False)

print("what package decides")
_, first = build("p1")
check("a release with nothing before it is published", first["publish"], True)
_, same = build("p2", previous=sums_a)
check("one that is what the last one was is not", same["publish"], False)
_, changed_again = build("p3", tree(tmp / "src-p3", changed), previous=sums_a)
check("one with a changed archive is", changed_again["publish"], True)
_, clash = build("p4", existing=["2026-09-30-crs-v4.29.0"])
check("and a tag that is taken is not reused", clash["tag"], "2026-09-30-crs-v4.29.0-2")

print("the command")
github_output = tmp / "github_output.txt"
env = dict(os.environ, GITHUB_OUTPUT=str(github_output), PYTHONPATH=str(REPO_ROOT))
result = subprocess.run(
    [sys.executable, "-W", "ignore", "-m", "patterns", "package", "--out", str(tmp / "cli"),
     "--source", str(tmp / "src-one"), "--rules", str(rules_file),
     "--coverage", str(tmp / "coverage.json"), "--changes", str(tmp / "changes.json"),
     "--date", "2026-09-30", "--commit", "abc123"],
    cwd=REPO_ROOT, env=env, capture_output=True, text=True)
check("it succeeds", result.returncode, 0)
check("and says the tag and whether to publish", json.loads(result.stdout),
      {"tag": "2026-09-30-crs-v4.29.0", "publish": True})
check("and tells the workflow, in the form GITHUB_OUTPUT reads",
      github_output.read_text().splitlines(),
      ["tag=2026-09-30-crs-v4.29.0", "publish=true", "crs_ref=v4.29.0"])
bad = subprocess.run(
    [sys.executable, "-W", "ignore", "-m", "patterns", "package", "--out", str(tmp / "bad"),
     "--rules", str(rules_file), "--date", "tomorrow"],
    cwd=REPO_ROOT, env=env, capture_output=True, text=True)
check("a date that is not one is an error, not a traceback",
      (bad.returncode, "Traceback" in bad.stderr), (1, False))

unresolved = tmp / "unresolved.json"
unresolved.write_text(json.dumps({"schema_version": 1, "rules": []}))
nameless = subprocess.run(
    [sys.executable, "-W", "ignore", "-m", "patterns", "package", "--out", str(tmp / "nameless"),
     "--rules", str(unresolved), "--date", "2026-09-30"],
    cwd=REPO_ROOT, env=env, capture_output=True, text=True)
check("rules that do not say which CRS tag they come from are not released",
      (nameless.returncode, (tmp / "nameless").exists()), (1, False))

print("the workflow")
workflow = (REPO_ROOT / ".github" / "workflows" / "update_patterns.yml").read_text()
check("it never deletes a release", "release delete" in workflow, False)
check("nor a tag", bool(re.search(r"git push[^\n]*--delete|git tag -d|tag -d", workflow)), False)
check("and never publishes under the tag `latest`", bool(re.search(r"tag_name:\s*latest", workflow)), False)
check("it publishes under the tag the package command chose",
      "tag_name: ${{ steps.package.outputs.tag }}" in workflow, True)
check("and signs with the workflow's own identity",
      "certificate-identity" in workflow and "workflow_ref" in workflow, True)
docs = (REPO_ROOT / "docs" / "verify.md").read_text()
IDENTITY = "https://github.com/fabriziosalmi/patterns/.github/workflows/update_patterns.yml@refs/heads/main"
check("every identity the documentation tells people to verify is the workflow's, on main",
      sorted(set(re.findall(r"--certificate-identity\s+(\S+)", docs))), [IDENTITY])
check("and the release notes say the same",
      sorted(set(re.findall(r"--certificate-identity\s+(\S+)", workflow))
             - {"\"$IDENTITY\""}), [IDENTITY])
check("issued by GitHub Actions, every time",
      sorted(set(re.findall(r"--certificate-oidc-issuer\s+(\S+)", docs))),
      ["https://token.actions.githubusercontent.com"])
check("and the workflow file it names is the one that is here",
      (REPO_ROOT / ".github" / "workflows" / IDENTITY.split("/workflows/")[1].split("@")[0]).is_file(), True)

print(f"\n{checks - failures}/{checks} checks passed")
if failures:
    print(f"{failures} failing")
    sys.exit(1)
