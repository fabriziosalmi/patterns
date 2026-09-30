"""
What a release is made of, and what it is called.

The nightly build published every release under one tag, `latest`, which it
deleted and created again each night. Nobody could pin a version, refer to "the
rules from 2026-09-14" in an incident report, or roll back to the night before.

A release is now a dated tag that is never deleted, such as
`2026-09-30-crs-v4.29.0`: the day it was built and the CRS tag it was built from.
What the files are is decided here, where it can be tested, and the workflow only
signs and publishes what this wrote.

    <target>_waf.zip   the files of one target, byte for byte the same for the same
                       files: sorted, with no timestamp, owner or extra attribute,
                       so the same rules give the same archive on any machine
    coverage.json      what each target does with each rule (#58)
    changes.json       what changed since the previous release (#61)
    SHA256SUMS         the hash of each of those, in the format `sha256sum -c` reads
    release.json       the tag, the day, the CRS tag, the commit and the run
    rules-predicate.json  the CRS tag and the hash of the rules, which the workflow
                       attests about the files above

The workflow signs every file and attests them, and `SHA256SUMS` is signed with the
rest, so one verified file vouches for the hash of each of the others.
"""

import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from patterns import backends

# The time stored for every file in an archive: the earliest a zip can say. A
# modification time in an archive makes the same files give a different archive
# every night.
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

# Files that are not an archive and go in the release as they are, and that
# SHA256SUMS lists. release.json is not among them: it names the day and the
# commit, so it differs every night and says nothing about the rules.
COPIED = ("coverage.json", "changes.json")


def archive_name(target: str) -> str:
    return f"{target}_waf.zip"


def make_archive(directory: Path, destination: Path) -> str:
    """
    Writes the files under `directory` into a zip, the same bytes for the same files.

    Files are added in sorted order by their path relative to `directory`, with the
    earliest time a zip can hold, owner-read/write and world-read permissions, and
    no extra fields. A directory entry is not added.

    Returns:
        The SHA-256 of the archive.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in directory.rglob("*") if p.is_file())
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(directory).as_posix(), date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 & 0xFFFF) << 16
            info.create_system = 3  # Unix, whatever machine this ran on
            z.writestr(info, path.read_bytes(), compresslevel=9)
    return sha256(destination)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tag_for(date: str, crs_ref: str, existing: Iterable[str]) -> str:
    """
    The name of a release: the day it was built and the CRS tag it was built from.

    A second release on the same day for the same CRS tag gets `-2`, then `-3`, since
    a tag is never reused.

    Args:
        date: `YYYY-MM-DD`, in UTC.
        crs_ref: The CRS tag the rules were read from.
        existing: The tags that are already releases.

    Raises:
        ValueError: The date or the CRS tag has a shape a tag should not.
    """
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ValueError(f"not a date: {date!r}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", crs_ref):
        raise ValueError(f"not a CRS tag: {crs_ref!r}")
    taken = set(existing)
    base = f"{date}-crs-{crs_ref}"
    tag, n = base, 1
    while tag in taken:
        n += 1
        tag = f"{base}-{n}"
    return tag


def unchanged(previous: Optional[str], current: str) -> bool:
    """
    Whether a release would say nothing new.

    Compares the archives and coverage.json of the previous release's SHA256SUMS
    with the ones about to be published. changes.json is left out: it says what
    changed since the night before, so it differs on the day after a change even
    though the rules do not.

    Args:
        previous: The text of the previous release's SHA256SUMS, None if there is
            none or it has none.
        current: The text of this one's.
    """
    if not previous:
        return False

    def rules(text: str) -> Dict[str, str]:
        found = {}
        for line in text.splitlines():
            digest, _, name = line.partition("  ")
            if name.endswith("_waf.zip") or name == "coverage.json":
                found[name] = digest
        return found

    before = rules(previous)
    return bool(before) and before == rules(current)


def checksums(directory: Path, names: Iterable[str]) -> str:
    """SHA256SUMS: a line per file, `<hash>  <name>`, sorted, as `sha256sum -c` reads."""
    return "".join(f"{sha256(directory / n)}  {n}\n" for n in sorted(names))


def package(out: Path, source: Path, rules_file: Path, date: str, crs_ref: str,
            commit: str, run: str, existing_tags: Iterable[str],
            previous_sums: Optional[str], extra: Optional[Dict[str, Path]] = None) -> Dict:
    """
    Builds everything a release holds into `out`, and says what to call it.

    Args:
        out: Where the release files go.
        source: The directory with one directory of output per target (waf_patterns).
        rules_file: The IR the output was built from.
        date: The day, `YYYY-MM-DD`, UTC.
        crs_ref: The CRS tag the rules were read from.
        commit: The commit the release is of.
        run: The url of the workflow run, for the record.
        existing_tags: The tags that are releases already.
        previous_sums: The previous release's SHA256SUMS, if any.
        extra: Files to copy in (`coverage.json`, `changes.json`), by name.

    Returns:
        The release as data: `tag`, `publish` (false if it would say nothing the
        previous release did not) and what release.json holds.
    """
    out.mkdir(parents=True, exist_ok=True)
    archives: Dict[str, str] = {}
    for target in backends.names():
        directory = source / target
        if directory.is_dir():
            archives[archive_name(target)] = make_archive(directory, out / archive_name(target))

    copied = []
    for name, path in (extra or {}).items():
        if path.is_file():
            (out / name).write_bytes(path.read_bytes())
            copied.append(name)

    sums = checksums(out, list(archives) + copied)
    (out / "SHA256SUMS").write_text(sums, encoding="utf-8")

    tag = tag_for(date, crs_ref, existing_tags)
    rules_document = json.loads(rules_file.read_text(encoding="utf-8"))
    rules_list = rules_document["rules"] if isinstance(rules_document, dict) else rules_document
    predicate = {
        "crs": {"repository": "https://github.com/coreruleset/coreruleset", "ref": crs_ref},
        "rules": {"sha256": sha256(rules_file),
                  "schema_version": rules_document.get("schema_version")
                  if isinstance(rules_document, dict) else None,
                  "records": len(rules_list)},
    }
    (out / "rules-predicate.json").write_text(json.dumps(predicate, indent=2) + "\n", encoding="utf-8")
    document = {
        "tag": tag,
        "date": date,
        "source": {"repository": "https://github.com/coreruleset/coreruleset", "ref": crs_ref},
        "rules_sha256": sha256(rules_file),
        "commit": commit,
        "run": run,
        "files": {name: line.split("  ")[0] for line in sums.splitlines()
                  for name in [line.split("  ", 1)[1]]},
    }
    (out / "release.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return {"tag": tag, "publish": not unchanged(previous_sums, sums), "release": document}
