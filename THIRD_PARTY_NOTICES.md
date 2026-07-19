# Third-Party Notices

`patterns` does not author its detection rules from scratch. It **fetches, parses,
and converts** rule and blocklist data published by third-party projects into the
native configuration syntax of Nginx, Apache, Traefik, and HAProxy.

The original code of this project — the Python converters (`owasp2json.py`,
`json2nginx.py`, `json2apache.py`, `json2traefik.py`, `json2haproxy.py`,
`badbots.py`, `import_*.py`), the documentation, and the tests — is licensed under
the [MIT License](LICENSE) (Copyright (c) Fabrizio Salmi).

The **generated data** is a different matter. The following artifacts are **not**
original works of this project; they are **generated / derived artifacts** built
from the upstream sources listed below, and they are redistributed under the
upstream licenses, not under this project's MIT license:

- `owasp_rules.json` — intermediate JSON extracted from the OWASP Core Rule Set.
- `waf_patterns/**` — the per-platform WAF configurations converted from that JSON
  and from the bad-bot / referrer-spam blocklists.

Each source below states what it provides, its SPDX license identifier, and the
attribution it requires. Where a project's license text is required to accompany
redistribution, a copy is included in the [`LICENSES/`](LICENSES/) directory.

---

## OWASP Core Rule Set (CRS)

- **Upstream:** https://github.com/coreruleset/coreruleset
- **Provides:** the WAF detection rules (SQLi, XSS, RCE, LFI, RFI, generic anomaly
  and protocol-violation patterns). `owasp2json.py` downloads the CRS `.conf` rule
  files, extracts the `SecRule` patterns, and writes them to `owasp_rules.json`;
  the `json2*.py` converters then transform that JSON into
  `waf_patterns/nginx/`, `waf_patterns/apache/`, `waf_patterns/traefik/`, and
  `waf_patterns/haproxy/`.
- **SPDX license:** `Apache-2.0`
- **License copy:** [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt)
  (included to satisfy Apache-2.0 §4(a): recipients of the redistributed material
  must receive a copy of the License).
- **Attribution and required notices:**
  - Copyright © the OWASP® CRS project and its contributors.
  - **Modification / "state changes" notice (Apache-2.0 §4(b)):** the files
    `owasp_rules.json` and everything under `waf_patterns/**` are **derived and
    converted works**. The original CRS `SecRule` directives have been parsed,
    filtered, reformatted, and translated into Nginx `map`/`if` directives, Apache
    ModSecurity `SecRule` sets, Traefik middleware TOML, and HAProxy ACL files.
    These outputs are **not** the unmodified OWASP Core Rule Set and are not
    endorsed by the OWASP CRS project. Every generated file additionally carries a
    provenance header (or, for `owasp_rules.json`, a top-level `_provenance` key)
    recording the CRS reference it was built from and pointing back to this file.
  - "OWASP" is a registered trademark of the OWASP Foundation. This project is not
    affiliated with or endorsed by the OWASP Foundation.

---

## Crawler-Detect (JayBizzle)

- **Upstream:** https://github.com/JayBizzle/Crawler-Detect
- **Provides:** part of the bad-bot User-Agent list consumed by `badbots.py`
  (`raw/Crawlers.txt`), used to generate the `bots.*` files under `waf_patterns/**`.
- **SPDX license:** `MIT`
- **Required copyright notice:**

  ```
  MIT License

  Copyright (c) 2015-2020 Mark Beech

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction ... (full MIT terms as published upstream).
  ```

---

## nginx-ultimate-bad-bot-blocker (mitchellkrogza)

- **Upstream:** https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker
- **Provides:** part of the bad-bot User-Agent list consumed by `badbots.py`
  (`_generator_lists/bad-user-agents.list`), used to generate the `bots.*` files
  under `waf_patterns/**`.
- **SPDX license:** `MIT`
- **Required copyright notice:**

  ```
  MIT License

  Copyright (c) 2017 Mitchell Krog - mitchellkrog@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction ... (full MIT terms as published upstream).
  ```

---

## referrer-spam-blacklist (Matomo / piwik)

- **Upstream:** https://github.com/matomo-org/referrer-spam-blacklist
  (fetched by `badbots.py` via the legacy `piwik/referrer-spam-blacklist` path,
  `spammers.txt`).
- **Provides:** the referrer-spam domain list used as an additional signal when
  generating the `bots.*` files under `waf_patterns/**`.
- **SPDX license:** none — the project is released into the **Public Domain**
  ("Public Domain (no copyright)", per the upstream `README`/`LICENSE`).
- **Attribution:** none legally required. Credit is given here voluntarily.

---

## Summary

| Upstream source | Provides | SPDX | License copy |
|-----------------|----------|------|--------------|
| coreruleset/coreruleset | `owasp_rules.json`, `waf_patterns/**` rules | `Apache-2.0` | [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt) |
| JayBizzle/Crawler-Detect | bad-bot User-Agent list | `MIT` | notice above |
| mitchellkrogza/nginx-ultimate-bad-bot-blocker | bad-bot User-Agent list | `MIT` | notice above |
| matomo-org/referrer-spam-blacklist | referrer-spam domain list | Public Domain | — |

If you redistribute the generated artifacts (for example the release archives
`nginx_waf.zip`, `apache_waf.zip`, `traefik_waf.zip`, `haproxy_waf.zip`, or the
files under `waf_patterns/**`), you must keep this notice and the accompanying
`LICENSES/` directory with them.
