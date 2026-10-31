#!/usr/bin/env bash
# Phase C: activate the main rulesets. Run by the repository OWNER only, after
# the badges token is in place (docs/ci.md, Phase C). This script never
# changes visibility, plans, environments, secrets or access.
#   ci/main-protection/apply.sh check   show current rulesets and whether the API is available
#   ci/main-protection/apply.sh apply   create or update each ruleset from ruleset*.json, matched by name
set -euo pipefail
REPO=${TMB_REPO:-Vchekryzhov/tmb}
DIR=$(cd "$(dirname "$0")" && pwd)
# ruleset.json: PR and green ci-gate, bypassed by the admin role (the badges PAT).
# ruleset-history.json: no deletion or force-push, with no bypass at all.
FILES=("$DIR/ruleset.json" "$DIR/ruleset-history.json")
case "${1:-check}" in
  check)
    gh api "repos/$REPO" --jq '"visibility: \(.visibility)"'
    if out=$(gh api "repos/$REPO/rulesets" 2>&1); then
      echo "rulesets API available; current rulesets:"; echo "$out"
    else
      echo "rulesets API unavailable: $out"; exit 1
    fi ;;
  apply)
    for f in "${FILES[@]}"; do
      name=$(sed -n 's/^  "name": "\(.*\)",$/\1/p' "$f")
      [ -n "$name" ] || { echo "no name in $f"; exit 1; }
      id=$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name==\"$name\") | .id")
      if [ -n "$id" ]; then gh api -X PUT "repos/$REPO/rulesets/$id" --input "$f" >/dev/null; echo "updated ruleset $name ($id)"
      else gh api -X POST "repos/$REPO/rulesets" --input "$f" --jq "\"created ruleset $name (\(.id))\""; fi
    done
    echo "verify: open a PR with a deliberately failing test and confirm 'gh pr merge' without --admin is refused" ;;
  *) sed -n '2,8p' "$0"; exit 2 ;;
esac
