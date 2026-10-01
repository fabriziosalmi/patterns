# Coverage

Every web server here can express less than the Core Rule Set says. Patterns does not hide that: for every rule and every target it records what happened, and this page is generated from that record.

## What each target does

<!-- coverage:start -->
Of the 749 records in the CRS v4.29.0 intermediate representation, what each target does:

| Target | Full | Approximate | Unsound | Dropped |
|---|---:|---:|---:|---:|
| Nginx | 12 | 156 | 0 | 581 |
| Apache (ModSecurity) | 9 | 170 | 0 | 570 |
| Traefik | 0 | 3 | 0 | 746 |
| HAProxy | 2 | 97 | 403 | 247 |

**Why a record is dropped**, by the first reason the backend found:

| Reason | Nginx | Apache (ModSecurity) | Traefik | HAProxy |
|---|---:|---:|---:|---:|
| matched on a request component the target does not have | 96 | 93 | 685 | 160 |
| an operator the backend cannot express | 398 | 398 | 2 | 31 |
| not a rule: it changes another rule | 54 | 54 | 54 | 54 |
| it refuses ordinary traffic once converted | 13 | 21 |  |  |
| longer than the target accepts | 16 |  |  |  |
| it records and does not refuse | 4 | 4 |  |  |
| its severity is below what refuses, and the target cannot only record |  |  | 5 |  |
| the expression does not compile |  |  |  | 2 |

**What a written rule loses**, in how many of them:

| Loss | Nginx | Apache (ModSecurity) | Traefik | HAProxy |
|---|---:|---:|---:|---:|
| matched on other variables than the rule names | 149 | 164 | 3 | 480 |
| transformations the rule was written to run after are not applied | 115 | 116 | 2 | 136 |
| an operator written as something it is not |  |  |  | 301 |
| the expression was rewritten |  |  |  | 100 |
| a chain written without all of its links | 13 | 10 |  | 56 |
<!-- coverage:end -->

The numbers are counted on the records of the [intermediate representation](/ir), which include the links of a chain and the `SecRuleUpdateTargetById` directives, so they are a little more than the number of CRS rules. [`coverage.json`](https://github.com/fabriziosalmi/patterns/blob/main/waf_patterns/coverage.json) holds the verdict for each record, and is published with every release.

## The four statuses

| Status | Means |
|---|---|
| **Full** | Written, and it means what CRS wrote on the request components the target matches: the operator, the expression, the variables, the transformations and the chain are all kept. |
| **Approximate** | Written, with a loss that is named: a transformation that is not applied, a variable that is not matched, a chain reduced to its first link. |
| **Unsound** | Written, and it cannot mean what the rule said: an operator the backend cannot express written out as if it were a pattern, an expression that was rewritten, one link of a chain without the others. A rule like this is not less than the original, it is something else, and it is worth more attention than a rule that is dropped. |
| **Dropped** | Not written, with a reason. |

**Dropped** is decided by the backend where it drops the rule, and the reason is the first one it found. **Approximate** and **unsound** come from comparing what was written with what the target is declared to express (`Capabilities` in each backend), and [`tests/test_coverage.py`](https://github.com/fabriziosalmi/patterns/blob/main/tests/test_coverage.py) holds those declarations to the files: the number of rules a target writes is counted in its output and has to match.

## What is not in the matrix

- **Anomaly scoring.** CRS adds points for each rule that matches and refuses when the total passes a threshold. Every target here decides rule by rule, so a rule that would only have contributed points acts alone. This applies to all of them and is not counted as a loss.
- **What a rule does when it matches.** Deny, log, tarpit or record is chosen by severity or by the target, and is not part of a status.

## Does it load?

Whether a rule is written, and whether the server accepts what was written, are different questions. Each target is also run through its real server with the same corpus of ordinary and hostile requests: [Apache with ModSecurity](https://github.com/fabriziosalmi/patterns/blob/main/tests/test_apache_blocking.py), [HAProxy](https://github.com/fabriziosalmi/patterns/blob/main/tests/test_haproxy_blocking.py) and [Traefik](https://github.com/fabriziosalmi/patterns/blob/main/tests/test_traefik_blocking.py), and nginx by [its own test](https://github.com/fabriziosalmi/patterns/blob/main/tests/test_nginx_blocking.py). The [README](https://github.com/fabriziosalmi/patterns#does-it-load) says what they found. Where a target does not load, the test records the known state and the issue that tracks it, and fails the day that changes. Today nginx, Apache and Traefik load what is generated; HAProxy does not.

## Regular expression dialects

A pattern that does not compile on a target is a configuration that fails to load, so `patterns build` refuses to write anything if a backend would write an expression its target's engine rejects. The engines differ:

| Dialect | Used by | |
|---|---|---|
| `pcre` | Nginx, Apache (ModSecurity), HAProxy (built with PCRE2, as the official image is) | Accepts what Python can parse once PCRE-only syntax is rewritten. |
| `re2` | Traefik (Go's `regexp`) | No lookaround, backreference, atomic group, possessive quantifier or conditional. |

The check needs Python 3.11 or later, and `build` says so when it is skipped.

## Reading `coverage.json`

```json
{ "index": 265, "id": "932240",
  "nginx":   { "status": "dropped", "reason": "parameter-too-long", "detail": "5764 bytes" },
  "apache":  { "status": "unsound", "losses": [ { "kind": "regex", "detail": "...", "unsound": true } ] },
  "haproxy": { "status": "dropped", "reason": "invalid-regex", "detail": "does not parse: ..." } }
```

One line per record, in the order of the IR, with `index` its position there. A dropped record has a `reason` from the table on this page and a `detail` that says what it refers to. A written one has a `losses` list, empty for **full**.
