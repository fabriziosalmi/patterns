#!/usr/bin/env bash
# Reproduce the GitHub Actions workflows locally, before pushing.
#
# The commands come from .github/workflows/*.yml (read by scripts/ci-local-wf.py), so
# this cannot drift from CI. Run it on a Linux box provisioned with
# scripts/ci-local-setup.sh (the `ci-patterns` LXC), as an unprivileged user; from a
# laptop, scripts/ci-remote.sh sends the working tree there and runs this.
#
#   scripts/ci-local.sh --list
#   scripts/ci-local.sh fast                 # what a change needs first: the IR, the committed output, nginx
#   scripts/ci-local.sh ci                   # everything the PR checks run on GitHub
#   scripts/ci-local.sh all                  # ci + the checks CI does not run
#   scripts/ci-local.sh apache envoy         # any stages, in order
#   scripts/ci-local.sh --fail-fast ci
#
# Stages that mirror a workflow job run its real `run:` steps. Stages marked (extra) are
# NOT in GitHub CI. The nightly workflow (update_patterns.yml) is not here: it fetches CRS
# and publishes, and what it checks first is the same tests, which are.
set -uo pipefail
cd "$(dirname "$0")/.."

WF="python3 scripts/ci-local-wf.py"
# a fresh runner has no leftover containers; a box that ran a test that was interrupted does
cleanup() { docker ps -aq --filter "name=patterns-" | xargs -r docker rm -f >/dev/null 2>&1; true; }

declare -A DESC
stage_ir()                { $WF test_ir validate-ir; }; DESC[ir]="test_ir.yml validate-ir: extraction and schema tests, Python 3.11 and 3.13"
stage_reproducible()      { $WF test_ir build-reproducible; }; DESC[reproducible]="test_ir.yml build-reproducible: the committed output is what the IR builds, and the release is reproducible"
stage_nginx()             { $WF test_nginx validate-nginx-configuration; }; DESC[nginx]="test_nginx.yml: nginx loads the generated files and refuses attacks, not ordinary traffic"
stage_apache()            { $WF test_conformance apache; }; DESC[apache]="test_conformance.yml: Apache with ModSecurity (docker)"
stage_haproxy()           { $WF test_conformance haproxy; }; DESC[haproxy]="test_conformance.yml: HAProxy (docker)"
stage_traefik()           { $WF test_conformance traefik; }; DESC[traefik]="test_conformance.yml: Traefik with the real plugin (docker)"
stage_envoy()             { $WF test_conformance envoy; }; DESC[envoy]="test_conformance.yml: Envoy RBAC filter (docker)"
stage_docs()              { $WF docs build; }; DESC[docs]="docs.yml: vitepress build"
stage_workflows_lint()    { actionlint; }; DESC[workflows-lint]="actionlint on every workflow (extra)"
stage_bots() {
  # The bad-bot lists are written from public sources by badbots.py, and the nightly commits what
  # it writes. Run it, and what it writes must be what is committed (extra, needs the network).
  local venv="$HOME/.cache/ci-local/venv-3.11"
  [ -x "$venv/bin/python" ] || uv venv --seed --python 3.11 "$venv" || return 1
  "$venv/bin/pip" install -q -r requirements.txt || return 1
  "$venv/bin/python" badbots.py >/dev/null 2>&1 || { echo "badbots.py failed"; return 1; }
  git diff --exit-code -- 'waf_patterns/*/bots*' && echo "the bad-bot lists are what is committed"
}; DESC[bots]="badbots.py reproduces the committed bad-bot lists (extra, network: public sources)"

FAST="ir nginx"
CI="ir reproducible nginx apache haproxy traefik envoy docs"
ALL="$CI workflows-lint bots"

list() {
  echo "groups:  fast = $FAST"; echo "         ci   = $CI  (what PR checks run)"; echo "         all  = ci + workflows-lint bots"; echo
  for s in $ALL; do printf '  %-18s %s\n' "$s" "${DESC[$s]:-}"; done
}

FAILFAST=0; STAGES=()
for a in "$@"; do
  case "$a" in
    --list|-l) list; exit 0;;
    --fail-fast) FAILFAST=1;;
    fast) STAGES+=($FAST);; ci) STAGES+=($CI);; all) STAGES+=($ALL);;
    -h|--help) sed -n '2,19p' "$0"; exit 0;;
    *) STAGES+=("$a");;
  esac
done
[ ${#STAGES[@]} -gt 0 ] || { list; exit 2; }

rc=0; summary=()
for s in "${STAGES[@]}"; do
  fn="stage_${s//-/_}"
  if ! declare -F "$fn" >/dev/null; then echo "unknown stage: $s (see --list)" >&2; exit 2; fi
  cleanup
  t0=$SECONDS
  if "$fn"; then summary+=("ok    $s ($((SECONDS - t0))s)"); else summary+=("FAIL  $s ($((SECONDS - t0))s)"); rc=1; [ $FAILFAST = 1 ] && break; fi
done
cleanup
echo; echo "== summary"; printf '  %s\n' "${summary[@]}"
exit $rc
