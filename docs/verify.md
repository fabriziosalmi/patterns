# Verify a release

Rules that decide what a server refuses should come with proof of where they came from. Every release of Patterns is a **dated tag that is never deleted or replaced**, every file in it is **signed** by the workflow that built it, and the files and the rules they were built from are **attested**.

## Pin to a release

A release is named for the day it was built and the CRS tag it was built from: `2026-09-30-crs-v4.29.0`. Once it exists, that name is those files. You can refer to it in an incident report, pin a deployment to it, and go back to the night before.

```bash
gh release list --repo fabriziosalmi/patterns                        # the releases, newest first
curl -LO https://github.com/fabriziosalmi/patterns/releases/download/2026-09-30-crs-v4.29.0/nginx_waf.zip
```

`releases/latest/download/...` still works: GitHub's "latest" is the newest release, and it moves to the next one when there is one. Nothing is overwritten. A night on which neither the rules nor what each target does with them changed publishes no release.

## What is in a release

| File | |
|---|---|
| `nginx_waf.zip`, `apache_waf.zip`, `traefik_waf.zip`, `haproxy_waf.zip` | The files of each target. The same files give the same archive, byte for byte, whatever the day or the machine. |
| `coverage.json` | What each target does with each rule. See [Coverage](/coverage). |
| `changes.json` | What changed since the previous release. |
| `SHA256SUMS` | The hash of each of the files above. |
| `release.json` | The tag, the day, the CRS tag, the commit and the run that built it. |
| `rules-predicate.json` | The CRS tag and the hash of the rules, which is what the second attestation says. |
| `*.sigstore.json` | One per file above: the signature, the certificate and the entry in the public log. |

## Verify a file

The signature is made with the identity of the workflow run that built the release. There is no key to keep or to lose: [Sigstore](https://www.sigstore.dev) certifies that identity for a few minutes and writes it to a public log, and you check the certificate against what you expect.

```bash
cosign verify-blob \
  --bundle nginx_waf.zip.sigstore.json \
  --certificate-identity https://github.com/fabriziosalmi/patterns/.github/workflows/update_patterns.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  nginx_waf.zip
```

It prints `Verified OK`. If it says anything else, do not deploy the file. A copy with one byte changed fails it, and so does a file signed by any other workflow or branch: the identity above is this workflow, on `main`, and nothing else.

Install `cosign` from [its releases](https://github.com/sigstore/cosign/releases) or with your package manager (`brew install cosign`).

## Verify all of them at once

`SHA256SUMS` is signed like the rest, so one verified file vouches for the hash of each of the others:

```bash
gh release download 2026-09-30-crs-v4.29.0 --repo fabriziosalmi/patterns \
  --pattern 'SHA256SUMS*' --pattern '*_waf.zip' --pattern coverage.json

cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/fabriziosalmi/patterns/.github/workflows/update_patterns.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS

sha256sum -c SHA256SUMS --ignore-missing
```

## Verify where they came from

Two attestations are stored with the repository, about the same files:

```bash
# which commit and which workflow run built the file
gh attestation verify nginx_waf.zip --repo fabriziosalmi/patterns

# which rules it was built from: the CRS tag, and the hash of the rules
gh attestation verify nginx_waf.zip --repo fabriziosalmi/patterns \
  --predicate-type https://github.com/fabriziosalmi/patterns/attestations/rules/v1 \
  --format json --jq '.[].verificationResult.statement.predicate'
```

The second prints the CRS tag (`"ref": "v4.29.0"`), its repository, and the hash, version and number of records of the rules the files were built from. The CRS tag is also in the name of the release.

## What this proves, and what it does not

It proves that the files were built by this repository's release workflow, running on `main`, from the commit `release.json` names, and that nobody changed them afterwards. It does not prove that the rules are good: that is what the [coverage matrix](/coverage), the tests and the gate in front of every release are for. And it only means something if you check the identity above, not just that *a* signature exists.
