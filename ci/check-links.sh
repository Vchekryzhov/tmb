#!/usr/bin/env bash
# Documentation links. "local": relative links in tracked Markdown must point
# at existing files (exit 1 otherwise). "external": http(s) links must answer
# (exit 1 for HTTP errors, 2 when only network failures occurred).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
mode=${1:-local}
rc=0 neterr=0
while IFS= read -r md; do
  dir=$(dirname "$md")
  while IFS= read -r target; do
    case "$mode:$target" in
      local:http://*|local:https://*|local:mailto:*|local:\#*) ;;
      local:*)
        p=${target%%#*}
        [ -z "$p" ] && continue
        if [ ! -e "$ROOT/$dir/$p" ]; then echo "$md: broken link $target"; rc=1; fi ;;
      external:http://*|external:https://*)
        code=$(curl -sS -o /dev/null -L --max-time 20 -w '%{http_code}' "$target" 2>/dev/null) || { echo "$md: network error $target"; neterr=1; continue; }
        case "$code" in 2*|3*|429) ;; *) echo "$md: HTTP $code $target"; rc=1 ;; esac ;;
    esac
  done < <(grep -oE '\]\([^) ]+\)' "$ROOT/$md" | sed 's/^](//; s/)$//' | sort -u)
done < <(cd "$ROOT" && git ls-files '*.md')
[ $rc -eq 0 ] && [ $neterr -ne 0 ] && exit 2
[ $rc -eq 0 ] && echo "links ok"
exit $rc
