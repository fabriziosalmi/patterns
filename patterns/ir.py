"""
The IR, loaded once.

Every converter used to carry its own copy of the two functions that read
owasp_rules.json. There is one here, and it is the only place that knows the
file can be a bare list (the form before the document had a provenance block)
or the object `schema/ir.schema.json` specifies.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_FILE = REPO_ROOT / "schema" / "ir.schema.json"
DEFAULT_INPUT = Path("owasp_rules.json")


@dataclass
class IR:
    """
    The rules of one CRS release, and where they come from.

    Attributes:
        rules: The records, in file order. See docs/ir.md.
        crs_ref: The upstream tag the rules were read from, "latest" for a file
            that does not record one.
        schema_version: The version the document declares, None for a bare list.
        score_defaults: What each anomaly level is worth.
        provenance: The `_provenance` block, empty for a bare list.
        data_files: The phrases of each `.data` file an `@pmFromFile` rule reads, by file
            name. Empty for a document of schema 1 or a bare list, which has none.
    """

    rules: List[Dict]
    crs_ref: str = "latest"
    schema_version: Optional[int] = None
    score_defaults: Dict[str, int] = field(default_factory=dict)
    provenance: Dict[str, str] = field(default_factory=dict)
    data_files: Dict[str, List[str]] = field(default_factory=dict)


def load(path: Union[str, Path] = DEFAULT_INPUT) -> IR:
    """
    Reads owasp_rules.json.

    Accepts the document `owasp2json.py` writes and, for the files that predate
    it, a bare list of rules.

    Raises:
        OSError: The file cannot be read.
        json.JSONDecodeError: It is not JSON.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Error loading rules from {path}: {e}")
        raise

    if isinstance(data, list):
        return IR(rules=data)

    provenance = data.get("_provenance") or {}
    return IR(
        rules=data.get("rules", []),
        crs_ref=provenance.get("source_ref", "latest"),
        schema_version=data.get("schema_version"),
        score_defaults=data.get("score_defaults") or {},
        provenance=provenance,
        data_files=data.get("data_files") or {},
    )


def validate(path: Union[str, Path] = DEFAULT_INPUT) -> List[str]:
    """
    Checks a file against schema/ir.schema.json.

    Returns:
        One message per violation, each starting with where it is, such as
        `rules[12].operator`. Empty when the file is valid.

    Raises:
        ImportError: The `jsonschema` package is not installed.
    """
    import jsonschema

    with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
        schema = json.load(f)
    with open(path, "r", encoding="utf-8") as f:
        document = json.load(f)

    validator = jsonschema.Draft202012Validator(schema)
    problems = []
    for error in sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path)):
        where = ""
        for part in error.absolute_path:
            where += f"[{part}]" if isinstance(part, int) else f".{part}"
        problems.append(f"{where.lstrip('.') or '<document>'}: {error.message[:200]}")
    return problems
