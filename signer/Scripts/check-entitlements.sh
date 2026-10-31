#!/usr/bin/env bash
# Signer process integrity (ADR 0007 R5): hardened runtime, no debug or
# code-injection entitlements.
#
#   check-entitlements.sh TARGET...   check each target
#   check-entitlements.sh --self-test prove the checker on throwaway binaries
#
# A TARGET ending in .entitlements is an entitlements plist: its content is
# checked. Any other TARGET is a signed binary or bundle: the signature must
# verify, carry the hardened runtime flag, and its embedded entitlements must
# pass the same content check. Exit 0 clean, 1 findings, 2 tool error.
set -uo pipefail

# Entitlements the signer never carries: each one lets another process of
# the same user attach, inject code or relax code signing.
FORBIDDEN=(
  com.apple.security.get-task-allow
  com.apple.security.cs.debugger
  com.apple.security.cs.disable-library-validation
  com.apple.security.cs.allow-dyld-environment-variables
  com.apple.security.cs.allow-unsigned-executable-memory
  com.apple.security.cs.disable-executable-page-protection
  com.apple.security.cs.allow-jit
)

# check_plist FILE LABEL: 0 clean, 1 a forbidden entitlement is true, 2 unreadable
check_plist() {
  local json key bad=0
  json=$(plutil -convert json -o - "$1" 2>/dev/null) || { echo "ERROR $2: not a readable plist"; return 2; }
  for key in "${FORBIDDEN[@]}"; do
    if grep -qE "\"${key//./\\.}\"[[:space:]]*:[[:space:]]*true" <<<"$json"; then
      echo "FAIL $2: forbidden entitlement $key"
      bad=1
    fi
  done
  return $bad
}

# check_signed PATH: 0 clean, 1 findings, 2 tool error
check_signed() {
  local t=$1 info ents rc=0
  [ -e "$t" ] || { echo "ERROR $t: does not exist"; return 2; }
  codesign --verify --strict "$t" >/dev/null 2>&1 || { echo "FAIL $t: signature does not verify"; rc=1; }
  info=$(codesign -dv "$t" 2>&1) || { echo "ERROR $t: codesign -dv failed"; return 2; }
  grep -qE '^CodeDirectory .*flags=0x[0-9a-f]*\([^)]*runtime' <<<"$info" || { echo "FAIL $t: no hardened runtime flag"; rc=1; }
  ents=$(mktemp)
  if ! codesign -d --entitlements - --xml "$t" >"$ents" 2>/dev/null; then
    echo "ERROR $t: cannot read entitlements"; rm -f "$ents"; return 2
  fi
  if [ -s "$ents" ]; then
    check_plist "$ents" "$t"
    local p=$?
    [ $p -gt $rc ] && rc=$p
  fi
  rm -f "$ents"
  return $rc
}

check() {
  local t worst=0 rc
  for t in "$@"; do
    case "$t" in
      *.entitlements) check_plist "$t" "$t"; rc=$? ;;
      *) check_signed "$t"; rc=$? ;;
    esac
    [ $rc -eq 0 ] && echo "OK $t"
    [ $rc -gt $worst ] && worst=$rc
  done
  return $worst
}

# expect WANT DESC TARGET: run the checker on TARGET and compare its exit code
expect() {
  local want=$1 desc=$2 got
  check "$3" >/dev/null 2>&1
  got=$?
  if [ "$got" = "$want" ]; then echo "self-test ok: $desc (rc=$got)"; return 0; fi
  echo "self-test FAILED: $desc: rc=$got, want $want"
  return 1
}

self_test() {
  local d rc=0
  d=$(mktemp -d)
  trap 'rm -rf "$d"' RETURN
  cat >"$d/clean.entitlements" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><false/></dict></plist>
EOF
  cat >"$d/debug.entitlements" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
EOF
  printf 'not a plist' >"$d/broken.entitlements"
  for b in hardened debug plain; do cp /usr/bin/true "$d/$b" || return 2; done
  codesign -f -s - -o runtime --entitlements "$d/clean.entitlements" "$d/hardened" >/dev/null 2>&1 || { echo "self-test: ad-hoc signing failed"; return 2; }
  codesign -f -s - -o runtime --entitlements "$d/debug.entitlements" "$d/debug" >/dev/null 2>&1 || { echo "self-test: ad-hoc signing failed"; return 2; }
  codesign -f -s - "$d/plain" >/dev/null 2>&1 || { echo "self-test: ad-hoc signing failed"; return 2; }
  expect 0 "clean entitlements file passes" "$d/clean.entitlements" || rc=1
  expect 1 "get-task-allow in an entitlements file fails" "$d/debug.entitlements" || rc=1
  expect 2 "unreadable entitlements file is an error" "$d/broken.entitlements" || rc=1
  expect 0 "hardened runtime binary with clean entitlements passes" "$d/hardened" || rc=1
  expect 1 "hardened runtime binary with get-task-allow fails" "$d/debug" || rc=1
  expect 1 "binary without hardened runtime fails" "$d/plain" || rc=1
  expect 2 "missing target is an error" "$d/absent" || rc=1
  return $rc
}

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  '' ) echo "usage: $0 --self-test | TARGET..." >&2; exit 2 ;;
  *) check "$@"; exit $? ;;
esac
