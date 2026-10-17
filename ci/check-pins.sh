#!/usr/bin/env bash
# Pin consistency: one Go patch version for CI, harness build images and the
# local entrypoint; every action pinned by full commit SHA; every Docker base
# image pinned by digest. Exit 1 on any mismatch.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
rc=0
want=$(tr -d '[:space:]' <"$ROOT/.go-version")
want=${want#go}
echo ".go-version: $want"
for f in "$ROOT"/harness/images/Dockerfile.* "$ROOT"/packaging/test/Dockerfile.*; do
  while read -r img; do
    case "$img" in
      golang:*) v=${img#golang:}; v=${v%%-*}
        [ "$v" = "$want" ] || { echo "$(basename "$f"): $img does not match .go-version $want"; rc=1; } ;;
    esac
    case "$img" in
      *@sha256:*) ;;
      *) echo "$(basename "$f"): base image $img is not pinned by digest"; rc=1 ;;
    esac
  done < <(sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' "$f")
done
for s in "$ROOT"/harness/*.sh; do
  while read -r img; do
    v=${img#golang:}; v=${v%%-*}
    [ "$v" = "$want" ] || { echo "$(basename "$s"): $img does not match .go-version $want"; rc=1; }
    case "$img" in *@sha256:*) ;; *) echo "$(basename "$s"): $img is not pinned by digest"; rc=1 ;; esac
  done < <(grep -oE 'golang:[^[:space:]"]+' "$s" || true)
done
for wf in "$ROOT"/.github/workflows/*.yml "$ROOT"/.github/actions/*/action.yml; do
  while IFS=: read -r ln _ v; do
    v=$(echo "$v" | tr -d " \"'")
    [ "$v" = "$want" ] || { echo "$(basename "$wf"):$ln GO_PRIMARY $v != $want"; rc=1; }
  done < <(grep -n 'GO_PRIMARY:' "$wf" || true)
  while IFS=: read -r ln line; do
    first=$(echo "$line" | sed -n 's/.*go: \["\([0-9.]*\)".*/\1/p')
    [ -z "$first" ] || [ "$first" = "$want" ] || { echo "$(basename "$wf"):$ln matrix starts with Go $first, want $want"; rc=1; }
  done < <(grep -n 'go: \["' "$wf" || true)
  while IFS=: read -r ln line; do
    ref=$(echo "$line" | sed -n 's/.*uses:[[:space:]]*\([^[:space:]#]*\).*/\1/p')
    case "$ref" in ./*|'$/'*|'') continue ;; esac   # in-repo actions run at the tested commit
    echo "$ref" | grep -qE '@[0-9a-f]{40}$' || { echo "$(basename "$wf"):$ln action $ref is not pinned by full commit SHA"; rc=1; }
  done < <(grep -n 'uses:' "$wf")
done
# ci/tools.lock: every binary tool is pinned for linux/amd64, linux/arm64 and
# darwin/arm64 at one version, and each URL names that version.
while read -r tool; do
  for plat in "linux amd64" "linux arm64" "darwin arm64"; do
    n=$(awk -v t="$tool" -v p="$plat" '$1 == t && ($3 " " $4) == p' "$ROOT/ci/tools.lock" | wc -l | tr -d ' ')
    [ "$n" = 1 ] || { echo "ci/tools.lock: $tool has $n entries for $plat, want 1"; rc=1; }
  done
  vers=$(awk -v t="$tool" '$1 == t {print $2}' "$ROOT/ci/tools.lock" | sort -u)
  [ "$(echo "$vers" | wc -l | tr -d ' ')" = 1 ] || { echo "ci/tools.lock: $tool pinned at several versions: $(echo "$vers" | tr '\n' ' ')"; rc=1; }
  while read -r v url; do
    case "$url" in *"$v"*) ;; *) echo "ci/tools.lock: $tool $v URL does not name the version: $url"; rc=1 ;; esac
  done < <(awk -v t="$tool" '$1 == t {print $2, $5}' "$ROOT/ci/tools.lock")
done < <(awk '$1 !~ /^#/ && NF {print $1}' "$ROOT/ci/tools.lock" | sort -u)
for d in "$ROOT"/ci/tools/*/; do
  grep -q "^go $want\$" "$d/go.mod" || { echo "ci/tools/$(basename "$d")/go.mod: go line differs from $want"; rc=1; }
done
if [ -x "${TMB_CI_BIN:-$ROOT/out/ci/bin}/tmbci" ]; then
  "${TMB_CI_BIN:-$ROOT/out/ci/bin}/tmbci" badges -mode tools -check -dir "$ROOT/docs/badges" -go-version "$ROOT/.go-version" -tools-lock "$ROOT/ci/tools.lock" -tools-dir "$ROOT/ci/tools" || rc=1
else
  echo "tmbci not built: tool badges in docs/badges not checked"; rc=1
fi
[ $rc -eq 0 ] && echo "pins consistent"
exit $rc
