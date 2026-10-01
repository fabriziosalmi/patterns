#!/usr/bin/env bash
# Run the local CI on the CI box, on the working tree as it is now: committed or not.
#
#   CI_HOST=ci@<address of ci-patterns> scripts/ci-remote.sh fast
#   CI_HOST=ci@<address of ci-patterns> scripts/ci-remote.sh ci
#   CI_HOST=ci@<address of ci-patterns> scripts/ci-remote.sh apache envoy
#
# The tree is copied with rsync, without .git (a worktree has no .git directory, and the box
# does not need your history), then scripts/ci-local.sh runs there with the stages you give.
# A few checks ask git whether a step changed the tree (test_nginx.yml rebuilds the nginx output
# and fails on a diff), so the box makes a one-commit repository of what it was sent: a diff is
# then what the step changed, which is what it means on GitHub after a checkout.
# The box is the `ci-patterns` LXC; its address is a DHCP lease, which is why it is not here:
# it is in git-infra, and in your ~/.ssh/config if you want a name for it.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${CI_HOST:?set CI_HOST to ci@<address of the ci-patterns box>}"
DEST="${CI_DIR:-patterns}"

rsync -az --delete \
  --exclude '.git' --exclude '__pycache__/' --exclude '*.pyc' \
  --exclude 'docs/node_modules/' --exclude 'docs/.vitepress/dist/' --exclude 'docs/.vitepress/cache/' \
  --exclude 'dist/' --exclude '.DS_Store' \
  ./ "$CI_HOST:$DEST/"
ssh "$CI_HOST" "cd $DEST && rm -rf .git && git init -q -b main && git add -A \
  && git -c user.name=ci -c user.email=ci@local commit -q -m 'the tree that was sent'"

TTY=""; [ -t 1 ] && TTY="-t"   # a terminal when there is one, so the output is as it is on the box
# shellcheck disable=SC2086
exec ssh $TTY "$CI_HOST" "cd $DEST && scripts/ci-local.sh $*"
