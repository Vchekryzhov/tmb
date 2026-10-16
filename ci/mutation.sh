#!/usr/bin/env bash
# Security mutation checks (nightly). Each mutant breaks one security
# property in a TEMPORARY copy of src/ and runs the product Go tests; the
# tests must fail ("killed"). The working tree is never modified.
# Exit: 0 all killed, 1 a mutant survived, 2 harness error (mutation point
# not found exactly once, copy failed).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:?report dir}
mkdir -p "$OUT"
: >"$OUT/summary.txt"

# id | file (relative to src/) | exact original | replacement | property
MUTANTS=(
  "M1-client-cert|cmd/tmb-broker/tls.go|ClientAuth:   tls.RequireAndVerifyClientCert,|ClientAuth:   tls.RequestClientCert,|mTLS listener stops verifying client certificates"
  "M2-allowlist-uid|cmd/tmb-broker/broker.go|if u == id.UID {|if true {|any uid passes the requester allowlist"
  "M3-allowlist-cert|cmd/tmb-broker/broker.go|if fp == id.FP {|if true {|any certificate fingerprint passes the allowlist"
  "M4-requester-binding|cmd/tmb-broker/broker.go|has \&\& !p.Requester.Equal(id) {|has \&\& false {|another requester may redeem an approval"
  "M5-request-binding|cmd/tmb-broker/broker.go|if req.ClaimToken != tokenID {|if false {|token no longer binds to the exact request"
  "M6-one-shot|cmd/tmb-broker/store.go|os.O_CREATE\|os.O_EXCL\|os.O_WRONLY, 0o600|os.O_CREATE\|os.O_TRUNC\|os.O_WRONLY, 0o600|claim file no longer exclusive: replay possible"
)

survived=0
errors=0
for m in "${MUTANTS[@]}"; do
  IFS='|' read -r id file orig repl what <<<"$(printf '%s' "$m" | sed 's/\\|/\x01/g')"
  orig=${orig//$'\x01'/|}; repl=${repl//$'\x01'/|}
  orig=${orig//\\&/&}; repl=${repl//\\&/&}
  work=$(mktemp -d)
  cp -R "$ROOT/src" "$work/src" || { echo "$id: ERROR copy failed" >>"$OUT/summary.txt"; errors=1; continue; }
  n=$(grep -cF -- "$orig" "$work/src/$file" || true)
  if [ "$n" != 1 ]; then
    echo "$id: ERROR mutation point found $n times in $file (expected exactly 1): update ci/mutation.sh" >>"$OUT/summary.txt"
    errors=1; rm -rf "$work"; continue
  fi
  ORIG="$orig" REPL="$repl" python3 -c 'import os,sys
p=sys.argv[1]; s=open(p).read(); open(p,"w").write(s.replace(os.environ["ORIG"], os.environ["REPL"], 1))' "$work/src/$file"
  if (cd "$work/src" && go vet ./... >/dev/null 2>&1 && go test -count=1 -timeout=5m ./... >"$OUT/$id.log" 2>&1); then
    echo "$id: SURVIVED - $what ($file). No product test noticed; GAP in https://github.com/Vchekryzhov/tmb/issues/15" >>"$OUT/summary.txt"
    survived=$((survived + 1))
  else
    echo "$id: killed - $what" >>"$OUT/summary.txt"
  fi
  rm -rf "$work"
done
cat "$OUT/summary.txt"
git -C "$ROOT" diff --quiet -- src || { echo "working tree under src/ changed: mutation leaked" >&2; exit 2; }
[ $errors -ne 0 ] && exit 2
[ $survived -ne 0 ] && exit 1
exit 0
