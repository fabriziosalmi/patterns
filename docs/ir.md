# Intermediate representation

`owasp_rules.json` is the contract between the extractor and every converter. `owasp2json.py` reads the OWASP Core Rule Set into it, and each `json2*.py` builds a web server's configuration from it. It is specified by [`schema/ir.schema.json`](https://github.com/fabriziosalmi/patterns/blob/main/schema/ir.schema.json), which is versioned, and the committed file is checked against that schema on every push.

```text
coreruleset  ──▶  owasp2json.py  ──▶  owasp_rules.json  ──▶  json2{nginx,apache,traefik,haproxy}.py
                                      (schema_version 1)
```

The IR keeps what a CRS rule declares rather than what one converter happens to need. A converter decides what it can express; it should not have to guess what the rule said.

## The document

```json
{
  "schema_version": 1,
  "_provenance": { "source": "OWASP CoreRuleSet", "source_ref": "v4.29.0", "license": "Apache-2.0", "...": "..." },
  "score_defaults": { "critical": 5, "error": 4, "warning": 3, "notice": 2 },
  "rules": [ "..." ]
}
```

| Field | Meaning |
|---|---|
| `schema_version` | The version of the schema the document was written for. A reader that does not know the version should not guess at the fields. |
| `_provenance` | The upstream repository, the **one tag** the rules were read from, and the licence. The file is a derived work of the CRS (Apache-2.0); see [THIRD_PARTY_NOTICES](https://github.com/fabriziosalmi/patterns/blob/main/THIRD_PARTY_NOTICES.md). |
| `score_defaults` | What each anomaly level is worth, read from `REQUEST-901-INITIALIZATION.conf`. These are CRS defaults. A deployment can override them in `crs-setup.conf`. |
| `rules` | One record per directive, in file-name order and, within a file, in file order. |

The order is stable: two runs on the same tag produce the same file.

## A rule

Every field is always present. A field that does not apply is `null`, never missing.

| Field | Type | Meaning |
|---|---|---|
| `id` | string | The CRS rule id, or `"no_id"` for a record that has none: a link of a chain, or a `SecRuleUpdateTargetById`. |
| `directive` | `"SecRule"` \| `"SecRuleUpdateTargetById"` | What the record is. The second adds a target to an existing rule and is **not a rule**. |
| `category` | string | The part of the CRS it comes from: `SQLI`, `XSS`, `RCE`, ... |
| `phase` | 1 to 5 \| null | The phase it runs in. A link of a chain has its head's. |
| `variables` | list | What the operator is matched against. See below. |
| `operator` | object \| null | What is tested. `null` for a directive that is not a rule. |
| `transformations` | list of string | The `t:` chain the argument is written to run after, in order, without `t:none`. |
| `action` | string \| null | The disruptive action: `block`, `deny`, `drop`, `allow`, `pass`, `proxy`, `redirect`. `null` means it inherits `SecDefaultAction`'s. |
| `crs_severity` | string \| null | The severity as written: `CRITICAL`, `ERROR`, ... |
| `severity` | `high` \| `medium` \| `low` | `crs_severity` folded into three levels. `medium` when none is declared. This is a choice of this project, not of CRS. |
| `score` | object \| null | The anomaly score the rule adds when it matches. |
| `chain` | object \| null | Set when the record is part of a chain. |
| `target_rule_id` | string \| null | The rule a `SecRuleUpdateTargetById` changes. |

### Variables

`variables` lists what the operator is matched against, in the order written:

```json
{ "name": "REQUEST_HEADERS", "selector": "Cookie", "count": false, "excluded": true }
```

| Field | Meaning |
|---|---|
| `name` | The variable or collection, as written: `ARGS`, `REQUEST_HEADERS`, `TX`, ... |
| `selector` | What follows the first `:`, as written; `null` for the whole collection. Wrapped in slashes it is a regular expression, except on `XML`, where it is XPath. |
| `count` | `&VAR`: the number of matching variables, not their values. |
| `excluded` | `!VAR`: taken out of the list, not added to it. |

A rule matched against `ARGS|!ARGS:id` has two entries, and the second removes one argument from the first. Reading only the first variable, or folding the list into one request component, is wrong for exactly these rules.

### Operator

```json
{ "name": "rx", "negated": false, "argument": "(?i)<script[^>]*>[\\s\\S]*?" }
```

`name` is the operator without the `@`, as written (`rx`, `pm`, `pmFromFile`, `detectSQLi`, `lt`, ...), and `rx` when the rule names none. `negated` is `!@op`. `argument` is what follows, **exactly as written**: nothing is unescaped and macros such as `%{tx.allowed_methods}` are not expanded. For `pmFromFile` it is the file name.

An operator that is not `rx` is not a regular expression, and a converter that only knows patterns cannot emit it.

### Score

```json
{ "direction": "inbound", "level": "critical", "paranoia_level": 1 }
```

A CRS signature does not refuse a request by itself. It adds `score_defaults[level]` points to the transaction, and a later rule refuses once the total passes a threshold. A rule that adds no score does not count towards that threshold.

### Chain

A chain is a head and the links after it. It matches when **every** record does. CRS writes the id, the phase, the action and the severity on the head only, and the score on the last link; the IR puts the score on the head.

```json
[
  { "id": "901320",  "chain": { "role": "head", "head": "901320", "position": 0 }, "action": "pass", "phase": 1, "operator": { "name": "eq", "argument": "1" } },
  { "id": "no_id",   "chain": { "role": "link", "head": "901320", "position": 1 }, "action": null,   "phase": 1, "operator": { "name": "eq", "argument": "1" } },
  { "id": "no_id",   "chain": { "role": "link", "head": "901320", "position": 2 }, "action": null,   "phase": 1, "operator": { "name": "unconditionalMatch", "argument": "" } }
]
```

The records follow each other in the file, head first, positions `0, 1, 2, ...` without a gap. Each link is still a record of its own, because that is how the converters have always read the file, but **a link is not a rule**: it means nothing without the records before it. A converter that can only match one condition cannot honestly emit a chain.

## What a converter can assume

- Every field of a record is present, with the type above.
- `directive` is `SecRule` exactly when `operator` is not `null`.
- Ids are unique. `"no_id"` is the only repeated value.
- A record with `chain.role == "link"` has `id == "no_id"`, `action == null`, `score == null`, and follows the record it names.
- Every `score.level` has an entry in `score_defaults`.
- `target_rule_id` of an update names a rule that is in the file.

[`tests/test_ir_schema.py`](https://github.com/fabriziosalmi/patterns/blob/main/tests/test_ir_schema.py) checks each of these on the committed file.

## Fields on their way out

`pattern` and `location` are what the converters read today, and they are kept so that no converter changes with the schema.

- **`pattern`** is the operator string with its operator in front (`"@lt 1"`), and with doubled backslashes folded to one. It is `operator` and `argument` put back together, worse.
- **`location`** is `variables` folded into one request component, and is `"UNKNOWN"` when none of them maps. It is the field behind most of the rules a converter drops.

Both are replaced by `operator` and `variables`, and removed when the converters move to them.

## At CRS v4.29.0

| | |
|---|---|
| Records | 749 |
| `SecRule` | 695 |
| `SecRuleUpdateTargetById` (not rules) | 54 |
| Heads of a chain | 55 |
| Links of a chain | 73 |
| Records that add an anomaly score | 345 |

## Versioning

`schema_version` is an integer, and any change to the schema raises it: a field added, a constraint tightened, a value allowed. `schema/checksums.json` pins the content of each version, and `tests/test_ir_schema.py` fails when the schema differs from the pin of the version it declares. To change the schema:

1. edit `schema/ir.schema.json` and raise `schema_version` in it;
2. raise `SCHEMA_VERSION` in `owasp2json.py`;
3. add the digest of the new content to `schema/checksums.json` (the failing test prints it);
4. regenerate `owasp_rules.json`.

## Checking a file

```bash
pip install -r requirements.txt
python3 tests/test_ir_schema.py               # the committed owasp_rules.json
python3 tests/test_ir_schema.py other.json    # any other document
python3 tests/test_ir_extraction.py           # what the extractor reads from a rule
```
