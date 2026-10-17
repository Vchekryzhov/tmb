#!/usr/bin/env bash
# PROTOTYPE runner - throwaway PoC, not production.
#
# run-all.sh: milestone wrapper (ticket #10). Runs the three harnesses in
# sequence and aggregates their verdicts into ONE combined log:
#
#   1. harness/run.sh            N-series (unix socket + SO_PEERCRED path)
#   2. harness/run-pair.sh       docker-pair mTLS (O7/O8/O9; also re-runs
#                                run.sh internally as its regression stage)
#   3. harness/run-openshell.sh  full OpenShell rig (O0-O6)
#   4. harness/run-vm.sh         VM proof on Lima (V0-V9), only with --vm:
#                                it needs Lima and takes minutes (spec #39)
#
# Exits 0 only if EVERY part is green. Everything is tee'd to
# last-full-run.log; each part also keeps its own last-*-run.log with the
# full per-part evidence. Idempotent and cleanup-safe: each part script is
# idempotent by design and wipes its own containers/volumes/sandboxes via
# its EXIT trap; this wrapper holds no state of its own.

set -u
cd "$(dirname "$0")" || exit 1

WITH_VM=0
for a in "$@"; do
  case $a in
    --vm) WITH_VM=1 ;;
    *) echo "usage: run-all.sh [--vm]" >&2; exit 2 ;;
  esac
done

LOG=last-full-run.log

exec > >(tee "$LOG") 2>&1

log() { printf '\n================================================================\n== %s\n================================================================\n' "$*"; }

# run_part NAME SCRIPT OW LOG-FILE -> sets PART_RC/NAME_PASS/NAME_FAIL (eval)
run_part() {
  local name=$1 script=$2 ownlog=$3
  local rc summary p f
  log "PART $name: bash $script"
  bash "$script"
  rc=$?
  summary=$(sed -n 's/^PASS: \([0-9]*\)  FAIL: \([0-9]*\)$/\1 \2/p' "$ownlog" 2>/dev/null | tail -1)
  p=${summary%% *}
  f=${summary##* }
  echo "-- PART $name finished: rc=$rc, own summary '${summary:-<not parsed>}' (from $ownlog)"
  PART_RC=$rc
  PART_PASS=${p:-0}
  PART_FAIL=${f:-1}   # unparsed summary counts as failure
  if [ -z "${summary:-}" ] || [ "${PART_PASS:-0}" = "0" ]; then
    PART_FAIL=${PART_FAIL:-1}
  fi
}

OVERALL=0

VM_PART=""; [ "$WITH_VM" = 1 ] && VM_PART=" + VM proof"
log "TMB FULL RUN: N-series + docker-pair + OpenShell rig$VM_PART ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
echo "-- each part tees its own detailed log: last-run.log, last-pair-run.log, last-openshell-run.log$( [ "$WITH_VM" = 1 ] && echo ', last-vm-run.log')"

run_part "N-series (run.sh)" run.sh last-run.log
N_RC=$PART_RC; N_PASS=$PART_PASS; N_FAIL=$PART_FAIL
[ "$N_RC" = 0 ] && [ "$N_FAIL" = 0 ] || OVERALL=1

run_part "docker-pair (run-pair.sh)" run-pair.sh last-pair-run.log
P_RC=$PART_RC; P_PASS=$PART_PASS; P_FAIL=$PART_FAIL
[ "$P_RC" = 0 ] && [ "$P_FAIL" = 0 ] || OVERALL=1

run_part "OpenShell rig (run-openshell.sh)" run-openshell.sh last-openshell-run.log
O_RC=$PART_RC; O_PASS=$PART_PASS; O_FAIL=$PART_FAIL
[ "$O_RC" = 0 ] && [ "$O_FAIL" = 0 ] || OVERALL=1

V_SUM=""
if [ "$WITH_VM" = 1 ]; then
  run_part "VM proof (run-vm.sh)" run-vm.sh last-vm-run.log
  V_RC=$PART_RC; V_PASS=$PART_PASS; V_FAIL=$PART_FAIL
  [ "$V_RC" = 0 ] && [ "$V_FAIL" = 0 ] || OVERALL=1
fi

# =============================================================================
log "FULL-RUN SUMMARY"
printf '%s\n' "------------------------------------------------------------------"
printf 'N-series   (run.sh):          rc=%s  PASS=%s  FAIL=%s\n' "$N_RC" "$N_PASS" "$N_FAIL"
printf 'docker-pair(run-pair.sh):     rc=%s  PASS=%s  FAIL=%s\n' "$P_RC" "$P_PASS" "$P_FAIL"
printf 'OpenShell  (run-openshell.sh): rc=%s  PASS=%s  FAIL=%s\n' "$O_RC" "$O_PASS" "$O_FAIL"
if [ "$WITH_VM" = 1 ]; then
  printf 'VM proof   (run-vm.sh):       rc=%s  PASS=%s  FAIL=%s\n' "$V_RC" "$V_PASS" "$V_FAIL"
fi
printf '%s\n' "------------------------------------------------------------------"
if [ "$OVERALL" = 0 ]; then
  [ "$WITH_VM" = 1 ] && V_SUM=", vm=$V_PASS/$V_PASS"
  echo "FULL-RUN VERDICT: GREEN - N=$N_PASS/$N_PASS, pair=$P_PASS/$P_PASS, openshell=$O_PASS/$O_PASS$V_SUM, all parts green"
  echo "(combined log: $LOG; per-part logs: last-run.log, last-pair-run.log, last-openshell-run.log)"
  sleep 1
  exit 0
fi
[ "$WITH_VM" = 1 ] && V_SUM=", vm=$V_PASS/$V_FAIL"
echo "FULL-RUN VERDICT: RED - N=$N_PASS/$N_FAIL, pair=$P_PASS/$P_FAIL, openshell=$O_PASS/$O_FAIL$V_SUM failed (see $LOG)"
sleep 1
exit 1
