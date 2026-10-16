#!/usr/bin/env bash
# Phase C: activate the main ruleset. Run by the repository OWNER only, after
# deciding that the repository plan/visibility allows rulesets. This script
# never changes visibility, plans or access.
#   ci/main-protection/apply.sh check   show current rulesets and whether the API is available
#   ci/main-protection/apply.sh apply   create or update the "main" ruleset from ruleset.json
set -euo pipefail
REPO=${TMB_REPO:-Vchekryzhov/tmb}
DIR=$(cd "$(dirname "$0")" && pwd)
case "${1:-check}" in
  check)
    gh api "repos/$REPO" --jq '"visibility: \(.visibility)"'
    if out=$(gh api "repos/$REPO/rulesets" 2>&1); then
      echo "rulesets API available; current rulesets:"; echo "$out"
    else
      echo "rulesets API unavailable: $out"; exit 1
    fi ;;
  apply)
    id=$(gh api "repos/$REPO/rulesets" --jq '.[] | select(.name=="main") | .id')
    if [ -n "$id" ]; then gh api -X PUT "repos/$REPO/rulesets/$id" --input "$DIR/ruleset.json" >/dev/null; echo "updated ruleset $id"
    else gh api -X POST "repos/$REPO/rulesets" --input "$DIR/ruleset.json" --jq '"created ruleset \(.id)"'; fi
    echo "verify: open a PR with a deliberately failing test and confirm merge is blocked by ci-gate" ;;
  *) sed -n '2,8p' "$0"; exit 2 ;;
esac
