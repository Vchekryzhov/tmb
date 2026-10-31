#!/usr/bin/env bash
# PROTOTYPE runner - throwaway PoC, not production.
#
# run-vm.sh: the VM proof of milestone B (issue #45, spec #39). One command
# proves the packaged broker on a real Linux host with systemd:
#
#   Mac (this script, limactl)
#    -> Lima VM "tmb-vm" (Ubuntu 24.04 LTS arm64, image pinned by digest,
#       no host mounts; cloud-init installs Docker and OpenShell 0.1.3 from
#       harness/vm/tmb-vm.yaml)
#        -> tmb-broker from the deb of the current commit, systemd unit,
#           TLS listener 127.0.0.1:17600, CA of the broker in /etc/tmb/ca
#        -> OpenShell gateway (user service of the VM user, docker driver)
#        -> OpenShell sandbox (opencode image + tmb client of the tmb deb,
#           NET=none, ONE network rule: tcp + tls skip ->
#           host.openshell.internal:17600 for /usr/local/bin/tmb)
#
# Scenarios V0-V9 (registry ci/scenarios/v-series.txt): prerequisites,
# install and start, CA and reload, enrollment by key, reissue, revoke,
# logrotate, SIGKILL fail-closed, restart keeps an approved command,
# package removal. `vm` = a command through `limactl shell`, `sbx` = through
# `openshell sandbox exec`, `human` = the approver user in a second session.
#
# The packages are built with `ci/run.sh dist` into a temp dir and copied
# into the VM with `limactl copy`; nothing of the Mac is mounted. The VM is
# created from scratch and deleted on every exit (TMB_VM_KEEP=1 keeps it for
# debugging; the next run deletes it first). Only the instance named
# $TMB_VM_NAME (default tmb-vm) is touched.
#
# Everything is logged to last-vm-run.log (tee'd).

set -u
cd "$(dirname "$0")" || exit 1

VM=${TMB_VM_NAME:-tmb-vm}
KEEP=${TMB_VM_KEEP:-0}
TEMPLATE=vm/tmb-vm.yaml
OPENSHELL_VERSION=0.1.3
UBUNTU_VERSION=24.04
SERVER_NAME=host.openshell.internal
TLS_PORT=17600
GW_PORT=17670
RJ=/var/log/tmb/journal.jsonl     # broker journal inside the VM
VD=/tmp/tmb-vm                    # copied packages and build context inside the VM
SK=/home/sandbox                  # key, certificate and CA inside the sandbox
TD=$(mktemp -d /tmp/tmb-vm.XXXXXX)
LOG=last-vm-run.log

to36() { local n=$1 d="0123456789abcdefghijklmnopqrstuvwxyz" out=""; while [ "$n" -gt 0 ]; do out="${d:$((n%36)):1}$out"; n=$((n/36)); done; printf '%s' "$out"; }
SBX=tmbv-$(to36 "$(date +%s)")

PASS=0
FAIL=0
ROWS=()

exec > >(tee "$LOG") 2>&1

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  echo "=== cleanup ==="
  jobs -p | xargs -r kill 2>/dev/null
  if [ "$KEEP" = 1 ]; then
    echo "-- TMB_VM_KEEP=1: VM $VM kept (limactl shell $VM; limactl delete -f $VM)"
  elif limactl list -q 2>/dev/null | grep -qx "$VM"; then
    limactl delete -f "$VM" >/dev/null 2>&1 && echo "-- VM $VM deleted" || echo "-- WARN: VM $VM not deleted"
  fi
  rm -rf "$TD"
}
trap cleanup EXIT

log() { printf '\n================================================================\n== %s\n================================================================\n' "$*"; }

ok()  { PASS=$((PASS+1)); ROWS+=("PASS | $1"); printf 'CHECK PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); ROWS+=("FAIL | $1"); printf 'CHECK FAIL: %s\n' "$1"; }
fatal() { echo "FATAL: $*"; exit 1; }
check() { # check NAME CMD... : PASS when CMD exits 0
  local name=$1; shift
  if "$@"; then ok "$name"; else bad "$name"; fi
}

RUNC=-1
OUT_FILE=$TD/last.out
ERR_FILE=$TD/last.err
show_io() {
  echo "-- rc=$RUNC"
  echo "-- stderr --"; sed 's/^/  | /' "$ERR_FILE" 2>/dev/null
  echo "-- stdout --"; sed 's/^/  | /' "$OUT_FILE" 2>/dev/null
}
assert_rc()      { if [ "$RUNC" = "$2" ]; then ok "$1 (rc=$RUNC)"; else bad "$1 (want rc=$2, got $RUNC)"; fi; }
assert_out_eq()  { if [ "$(cat "$OUT_FILE" 2>/dev/null)" = "$2" ]; then ok "$1 (stdout='$2')"; else bad "$1 (stdout='$(cat "$OUT_FILE" 2>/dev/null)' want='$2')"; fi; }
assert_out_has() { if grep -qF -- "$2" "$OUT_FILE" 2>/dev/null; then ok "$1"; else bad "$1 (stdout lacks '$2')"; fi; }
assert_err_has() { if grep -qF -- "$2" "$ERR_FILE" 2>/dev/null; then ok "$1"; else bad "$1 (stderr lacks '$2')"; fi; }

# vm CMD... : root inside the VM; vm_sh SCRIPT : root shell snippet
vm()    { limactl shell --workdir / "$VM" sudo "$@" </dev/null; }
vm_sh() { limactl shell --workdir / "$VM" sudo bash -c "$1" </dev/null; }
# vm_user_sh SCRIPT : the VM user that owns the OpenShell gateway
vm_user_sh() { limactl shell --workdir / "$VM" bash -c "$1" </dev/null; }
# human CMD... : the approver, a separate `limactl shell` session
human() { limactl shell --workdir / "$VM" sudo -u human "$@" </dev/null; }
# vm_run CMD... : root command with stdout/stderr captured
vm_run() { vm "$@" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io; }

CLIENV=(--env "TMB_ADDR=$SERVER_NAME:$TLS_PORT" --env "TMB_CA=$SK/ca.crt" --env "TMB_CERT=$SK/sbx.crt" --env "TMB_KEY=$SK/sbx.key")
# sbx CMD... : `openshell sandbox exec` as the VM user; stdin from the caller
sbx() { limactl shell --workdir / "$VM" timeout 150 openshell sandbox exec "$SBX" --no-login-shell "$@"; }
sbx_run() { sbx -- "$@" </dev/null >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io; }
# sbx_put LOCAL-FILE PATH : copy a file into the sandbox over exec stdin
sbx_put() { sbx -- sh -c "cat > '$2'" <"$1"; }

jcount() { vm_sh "grep -c -- '$1' $RJ 2>/dev/null" | tr -d '[:space:]'; }
jlast()  { vm_sh "grep -- '$1' $RJ | tail -1"; }
wait_jcount() { # PATTERN N [TRIES of 0.5s]
  local _ n
  for _ in $(seq 1 "${3:-60}"); do
    n=$(jcount "$1"); [ "${n:-0}" -ge "$2" ] 2>/dev/null && return 0
    sleep 0.5
  done
  echo "-- journal never reached $2 x '$1'"; return 1
}
journal_tail() { echo "---- broker journal (last ${1:-6} lines) ----"; vm tail -n "${1:-6}" "$RJ" 2>/dev/null | cut -c1-240 | sed 's/^/  | /'; }
set_config() { # JQ-FILTER : edit /etc/tmb/config.json in place (mode kept)
  vm_sh "jq '$1' /etc/tmb/config.json > /tmp/tmb-config.next && cat /tmp/tmb-config.next > /etc/tmb/config.json && rm -f /tmp/tmb-config.next"
}
main_pid() { vm systemctl show -p MainPID --value tmb-broker | tr -d '[:space:]'; }
listener_serial() { vm_sh "echo | timeout 10 openssl s_client -connect 127.0.0.1:$TLS_PORT -servername $SERVER_NAME 2>/dev/null | openssl x509 -noout -serial" | sed 's/^serial=//'; }
file_serial() { vm openssl x509 -in "$1" -noout -serial | sed 's/^serial=//'; }

# start_request NAME CMD... : tmb exec from the sandbox in the background;
# sets REQ_PID and REQ_ITEM once the broker queued it and the client waits
start_request() {
  local name=$1 _; shift
  REQ_OUT=$TD/$name.out; REQ_ERR=$TD/$name.err
  sbx "${CLIENV[@]}" -- tmb exec --root -- "$@" </dev/null >"$REQ_OUT" 2>"$REQ_ERR" &
  REQ_PID=$!
  REQ_ITEM=""
  for _ in $(seq 1 120); do
    REQ_ITEM=$(sed -n 's/^tmb: waiting for approval (item \([0-9a-f]*\),.*/\1/p' "$REQ_ERR" | head -1)
    [ -n "$REQ_ITEM" ] && return 0
    kill -0 "$REQ_PID" 2>/dev/null || break
    sleep 0.5
  done
  echo "-- the request never reached the queue"; sed 's/^/  | /' "$REQ_ERR"
  return 1
}
finish_request() { wait "$REQ_PID"; RUNC=$?; OUT_FILE=$REQ_OUT; ERR_FILE=$REQ_ERR; show_io; }
reset_io() { OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err; }

# request_approved NAME CMD... : queued request approved by human -> RUNC
request_approved() {
  local name=$1; shift
  if ! start_request "$name" "$@"; then RUNC=-1; return 1; fi
  echo "-- queued item $REQ_ITEM; human approves it from a second session"
  human tmb approve --yes "$REQ_ITEM" | sed 's/^/  | human: /'
  finish_request
}

# =============================================================================
log "TMB VM RUNNER: milestone B on a systemd host in Lima ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
echo "VM: $VM (template harness/$TEMPLATE), sandbox: $SBX, temp dir: $TD"
GIT_SHA=$(git rev-parse HEAD)
# the tracked stand logs are rewritten by this run and, under run-all.sh, by
# the parts before it: leave them out; any other change goes into the packages
echo "commit: $GIT_SHA$( [ -n "$(git status --porcelain --untracked-files=no -- ':(top)' ':(top,exclude,glob)harness/last-*.log')" ] && echo ' (working tree has uncommitted changes; the packages carry them)')"

# -----------------------------------------------------------------------------
log "STAGE 1: packages of the current commit, VM from scratch"

command -v limactl >/dev/null || fatal "limactl not found (brew install lima)"
echo "-- ci/run.sh dist into $TD/dist (log: $TD/dist.log)"
if ! TMB_DIST=$TD/dist ../ci/run.sh dist >"$TD/dist.log" 2>&1; then
  tail -20 "$TD/dist.log"; fatal "ci/run.sh dist failed"
fi
DEB_B=$(find "$TD/dist" -name "tmb-broker_*_arm64.deb" | head -1)
DEB_C=$(find "$TD/dist" -name "tmb_*_arm64.deb" | head -1)
if [ -f "$DEB_B" ] && [ -f "$DEB_C" ]; then ok "STAGE 1: arm64 debs built: $(basename "$DEB_B"), $(basename "$DEB_C")"
else bad "STAGE 1: arm64 debs missing in $TD/dist"; fatal "no packages"; fi

if limactl list -q 2>/dev/null | grep -qx "$VM"; then
  echo "-- deleting the leftover instance $VM of an earlier run"
  limactl delete -f "$VM" >/dev/null 2>&1 || fatal "cannot delete the leftover instance $VM"
fi
echo "-- limactl start $VM (cloud-init: Docker, OpenShell $OPENSHELL_VERSION; log: $TD/limactl.log)"
T0=$(date +%s)
if limactl start --name "$VM" --tty=false "$TEMPLATE" >"$TD/limactl.log" 2>&1; then
  ok "STAGE 1: VM $VM created from scratch and provisioned in $(( $(date +%s) - T0 ))s"
else
  tail -20 "$TD/limactl.log"; bad "STAGE 1: limactl start failed"; fatal "VM did not start"
fi
check "STAGE 1: provisioning finished (marker file)" vm test -f /var/lib/tmb-vm-provisioned
if [ "$(vm_sh 'mount | grep -cE " type (virtiofs|9p|fuse.sshfs) "; true' | tr -d '[:space:]')" = 0 ]; then
  ok "STAGE 1: no host directory is mounted in the VM"
else
  bad "STAGE 1: the VM mounts host directories"; vm_sh 'mount | grep -E " type (virtiofs|9p|fuse.sshfs) "' | sed 's/^/  | /'
fi

# -----------------------------------------------------------------------------
log "SCENARIO V0: prerequisites (Lima, Ubuntu LTS image, deb of this commit, OpenShell $OPENSHELL_VERSION)"

V0_OK=1
v0() { if "${@:2}"; then ok "V0: $1"; else bad "V0: $1"; V0_OK=0; fi; }
echo "-- $(limactl --version)"
v0 "limactl is Lima 2.x" sh -c 'limactl --version | grep -q "version 2\."'
# shellcheck disable=SC2016 # expands inside the VM
vm_sh '. /etc/os-release; echo "$PRETTY_NAME $(uname -m) kernel $(uname -r)"' | sed 's/^/  | /'
v0 "guest is Ubuntu $UBUNTU_VERSION LTS on aarch64" vm_sh ". /etc/os-release; [ \"\$VERSION_ID\" = $UBUNTU_VERSION ] && [ \"\$(uname -m)\" = aarch64 ] && echo \"\$VERSION\" | grep -q LTS"
# shellcheck disable=SC2016 # expands inside the VM
v0 "guest runs systemd as PID 1" vm_sh '[ "$(ps -o comm= -p 1)" = systemd ]'
WANT_VER=$(git describe --tags --exact-match --match 'v*' HEAD 2>/dev/null | sed 's/^v//')
[ -n "$WANT_VER" ] || WANT_VER=${GIT_SHA:0:12}
DEB_VER=$(basename "$DEB_B" | sed -n 's/^tmb-broker_\(.*\)_arm64\.deb$/\1/p')
echo "-- tmb-broker deb version: $DEB_VER (want it to carry $WANT_VER)"
v0 "the deb is built from the current commit ($WANT_VER)" grep -qF -- "$WANT_VER" <<<"$DEB_VER"
echo "-- docker in the VM: $(vm docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}' 2>&1)"
v0 "Docker engine answers in the VM" vm docker info -f '{{.ServerVersion}}'
OSV=$(vm openshell --version 2>/dev/null | awk '{print $2}')
v0 "openshell version is $OPENSHELL_VERSION (got '$OSV')" test "$OSV" = "$OPENSHELL_VERSION"
SBX_FROM=$(sed -n 's/^FROM //p' images/Dockerfile.vmsbx)
RIG_FROM=$(sed -n 's/^FROM \(ghcr\.io\/anomalyco\/opencode@sha256:[0-9a-f]*\).*/\1/p' images/Dockerfile.opensbx)
echo "-- sandbox base: $SBX_FROM"
v0 "sandbox base image is the opencode digest of the OpenShell rig" test -n "$RIG_FROM" -a "$SBX_FROM" = "$RIG_FROM"
[ "$V0_OK" = 1 ] || fatal "V0 prerequisites failed: the V-series does not start"

# -----------------------------------------------------------------------------
log "STAGE 2: OpenShell gateway (user service, docker driver) and the sandbox image"

# The deb ships openshell-gateway as a systemd user unit; it needs the docker
# driver named and the user in the docker group (its manager is restarted so
# the group applies). grpc_endpoint is an IPv4 loopback value so the driver
# pins host.openshell.internal to 127.0.0.1 for the host-networked
# supervisor, where the broker's TLS listener answers.
VMUSER=$(limactl shell --workdir / "$VM" id -un </dev/null)
VMUID=$(limactl shell --workdir / "$VM" id -u </dev/null)
# images the gateway and the sandbox need, pulled with retries first: a
# registry hiccup otherwise fails the gateway start (it pulls on startup)
for img in "ghcr.io/nvidia/openshell/sandbox:$OPENSHELL_VERSION" "$SBX_FROM"; do
  PULLED=0
  for i in 1 2 3 4 5; do
    if vm docker pull -q "$img" >/dev/null 2>"$ERR_FILE"; then PULLED=1; break; fi
    echo "-- pull $img attempt $i failed: $(tail -1 "$ERR_FILE")"; sleep 5
  done
  [ "$PULLED" = 1 ] || fatal "cannot pull $img"
  echo "-- pulled $img"
done
vm_sh "usermod -aG docker $VMUSER && loginctl enable-linger $VMUSER && systemctl restart user@$VMUID.service" \
  || fatal "VM user setup failed"
vm_user_sh "mkdir -p ~/.config/openshell && printf '%s\n' '[openshell]' 'version = 2' '' '[openshell.gateway]' 'compute_driver = \"docker\"' '' '[openshell.drivers.docker]' 'grpc_endpoint = \"https://127.0.0.1:$GW_PORT\"' > ~/.config/openshell/gateway.toml && echo OPENSHELL_COMPUTE_DRIVER=docker > ~/.config/openshell/gateway.env && systemctl --user start openshell-gateway" \
  || fatal "gateway start failed"
GW_OK=0
for _ in $(seq 1 90); do
  if vm_user_sh "ss -ltn | grep -q '127.0.0.1:$GW_PORT '"; then GW_OK=1; break; fi
  sleep 2
done
[ "$GW_OK" = 1 ] || { vm_sh "journalctl _SYSTEMD_USER_UNIT=openshell-gateway.service --no-pager -n 20" | sed 's/^/  | /'; fatal "OpenShell gateway did not come up on Linux"; }
vm_user_sh "openshell gateway add --local --name openshell https://127.0.0.1:$GW_PORT" >/dev/null 2>&1
vm_user_sh "openshell status" >"$OUT_FILE" 2>&1; sed 's/^/  | /' "$OUT_FILE"
if grep -q "Status: Connected" "$OUT_FILE"; then ok "STAGE 2: OpenShell gateway Connected on 127.0.0.1:$GW_PORT (docker driver)"
else bad "STAGE 2: OpenShell gateway not Connected"; fatal "gateway not reachable"; fi

echo "-- copy the packages and the sandbox Dockerfile into the VM (limactl copy, no mounts)"
limactl shell --workdir / "$VM" mkdir -p "$VD/sbximg" </dev/null
limactl copy "$DEB_B" "$DEB_C" "$VM:$VD/" || fatal "limactl copy of the packages failed"
limactl copy images/Dockerfile.vmsbx "$VM:$VD/sbximg/Dockerfile" || fatal "limactl copy of the Dockerfile failed"
ok "STAGE 2: packages copied into $VD"

# -----------------------------------------------------------------------------
log "SCENARIO V1: dpkg -i, start without config fails with a reason, start with config"

vm_run dpkg -i "$VD/$(basename "$DEB_B")" "$VD/$(basename "$DEB_C")"
assert_rc "V1: dpkg -i tmb-broker + tmb -> exit 0" 0
for f in /usr/bin/tmb-broker /usr/bin/tmb /usr/lib/systemd/system/tmb-broker.service /etc/tmb/config.json.example /etc/logrotate.d/tmb-broker /usr/lib/tmpfiles.d/tmb.conf; do
  check "V1: $f installed" vm test -f "$f"
done
echo "-- $(vm tmb-broker -version)"
check "V1: package does not enable the service" sh -c "[ \"\$(limactl shell --workdir / '$VM' systemctl is-enabled tmb-broker </dev/null)\" = disabled ]"
check "V1: /etc/tmb/config.json is not shipped" vm test ! -e /etc/tmb/config.json

vm_run systemctl start tmb-broker
if [ "$RUNC" != 0 ]; then ok "V1: systemctl start without config -> exit $RUNC"; else bad "V1: systemctl start without config succeeded"; fi
# Restart=on-failure retries until StartLimitBurst; the unit ends failed
for _ in $(seq 1 30); do
  STATE=$(vm systemctl show -p ActiveState --value tmb-broker | tr -d '[:space:]')
  [ "$STATE" = failed ] && break
  sleep 0.5
done
if [ "$STATE" = failed ]; then ok "V1: unit is failed without config"; else bad "V1: unit state '$STATE', want failed"; fi
vm journalctl -u tmb-broker --no-pager -o cat >"$OUT_FILE" 2>&1; grep -m1 -F "not found" "$OUT_FILE" | sed 's/^/  | /'; tail -3 "$OUT_FILE" | sed 's/^/  | /'
assert_out_has "V1: systemd journal names the missing file" "/etc/tmb/config.json not found"
echo "-- Restart=on-failure retried until the start limit; reset-failed clears it"
vm systemctl show -p NRestarts -p Result tmb-broker | sed 's/^/  | /'

HUMAN_UID=$(vm_sh 'useradd -m -s /bin/bash human && echo human:human | chpasswd && usermod -aG sudo human && id -u human' | tr -d '[:space:]')
echo "-- approver: user human, uid $HUMAN_UID (password sudo for V7)"
vm_sh "jq --argjson hu $HUMAN_UID '.approver_uids=[\$hu]' /etc/tmb/config.json.example > /etc/tmb/config.json && chmod 0644 /etc/tmb/config.json" \
  || fatal "writing /etc/tmb/config.json failed"
vm systemctl reset-failed tmb-broker
vm_run systemctl start tmb-broker
assert_rc "V1: systemctl start with config -> exit 0" 0
check "V1: tmb-broker is active" vm systemctl is-active --quiet tmb-broker
check "V1: requester socket /run/tmb/tmb.sock" vm test -S /run/tmb/tmb.sock
check "V1: approver socket /run/tmb/approve.sock" vm test -S /run/tmb/approve.sock
vm ls -l /run/tmb | sed 's/^/  | /'
if wait_jcount '"event":"broker_start"' 1; then ok "V1: broker_start in $RJ"; else bad "V1: no broker_start in $RJ"; fi
journal_tail 3

# -----------------------------------------------------------------------------
log "SCENARIO V2: ca init, ca issue-server, systemctl reload serves the new certificate"

vm_run tmb-broker ca init
assert_rc "V2: tmb-broker ca init -> exit 0" 0
if [ "$(vm stat -c '%a %U' /etc/tmb/ca/ca.key)" = "600 root" ]; then ok "V2: CA key /etc/tmb/ca/ca.key is 0600 root"; else bad "V2: CA key mode/owner is '$(vm stat -c '%a %U' /etc/tmb/ca/ca.key)'"; fi
Y=$((365*86400))
check "V2: CA certificate valid for ~10 years" vm_sh "openssl x509 -in /etc/tmb/ca/ca.crt -noout -checkend $((9*Y)) >/dev/null && ! openssl x509 -in /etc/tmb/ca/ca.crt -noout -checkend $((11*Y)) >/dev/null"
vm_run tmb-broker ca issue-server --dns "$SERVER_NAME" --ip 127.0.0.1
assert_rc "V2: ca issue-server --dns $SERVER_NAME --ip 127.0.0.1 -> exit 0" 0
vm openssl x509 -in /etc/tmb/ca/server.crt -noout -subject -ext subjectAltName -dates | sed 's/^/  | /'
check "V2: server certificate valid for 1 year" vm_sh "openssl x509 -in /etc/tmb/ca/server.crt -noout -checkend $((364*86400)) >/dev/null && ! openssl x509 -in /etc/tmb/ca/server.crt -noout -checkend $((366*86400)) >/dev/null"
check "V2: server certificate SAN has DNS:$SERVER_NAME" vm_sh "openssl x509 -in /etc/tmb/ca/server.crt -noout -ext subjectAltName | grep -q 'DNS:$SERVER_NAME'"

echo "-- tls_addr is a startup-only field: set it and restart once"
set_config ".tls_addr=\"127.0.0.1:$TLS_PORT\""
vm systemctl restart tmb-broker
if wait_jcount '"event":"tls_listen"' 1; then ok "V2: tls_listen on 127.0.0.1:$TLS_PORT after restart"; else bad "V2: no tls_listen"; fi
SERIAL_A=$(file_serial /etc/tmb/ca/server.crt)
GOT=$(listener_serial)
if [ -n "$SERIAL_A" ] && [ "$GOT" = "$SERIAL_A" ]; then ok "V2: listener serves serial $SERIAL_A"; else bad "V2: listener serial '$GOT', want '$SERIAL_A'"; fi

PID_BEFORE=$(main_pid)
vm_run tmb-broker ca issue-server --dns "$SERVER_NAME" --ip 127.0.0.1
assert_rc "V2: reissued server certificate -> exit 0" 0
SERIAL_B=$(file_serial /etc/tmb/ca/server.crt)
RLN=$(jcount '"event":"reload"'); RLN=${RLN:-0}
vm_run systemctl reload tmb-broker
assert_rc "V2: systemctl reload -> exit 0" 0
wait_jcount '"event":"reload"' $((RLN+1)) || true
if jlast '"event":"reload"' | grep -q '"tls_material"'; then ok "V2: reload event names tls_material"; else bad "V2: reload event lacks tls_material"; fi
GOT=$(listener_serial)
if [ -n "$SERIAL_B" ] && [ "$SERIAL_B" != "$SERIAL_A" ] && [ "$GOT" = "$SERIAL_B" ]; then ok "V2: after reload the listener serves the new serial $SERIAL_B"; else bad "V2: listener serial '$GOT', want new '$SERIAL_B' (old $SERIAL_A)"; fi
if [ "$(main_pid)" = "$PID_BEFORE" ]; then ok "V2: reload kept the broker pid $PID_BEFORE"; else bad "V2: broker pid changed on reload"; fi
journal_tail 2

# -----------------------------------------------------------------------------
log "STAGE 3: sandbox up (OpenShell, opencode image + tmb from the tmb deb, single rule)"

if vm_sh "cp /usr/bin/tmb $VD/sbximg/tmb && docker build -q -t tmb-vm/sandbox $VD/sbximg" >"$OUT_FILE" 2>&1; then
  ok "STAGE 3: sandbox image tmb-vm/sandbox built"
else
  sed 's/^/  | /' "$OUT_FILE"; bad "STAGE 3: sandbox image build failed"; fatal "no sandbox image"
fi
vm_user_sh "timeout 180 openshell sandbox create --name $SBX --from tmb-vm/sandbox --detach -- sleep infinity" >"$OUT_FILE" 2>&1 \
  || { sed 's/^/  | /' "$OUT_FILE"; fatal "sandbox create failed"; }
READY=0
for _ in $(seq 1 60); do
  if vm_user_sh "openshell sandbox get $SBX -o json | jq -e 'any(.conditions[]?; .type==\"Ready\" and .status==\"True\")' >/dev/null"; then READY=1; break; fi
  sleep 1
done
if [ "$READY" = 1 ]; then ok "STAGE 3: sandbox $SBX Ready"; else bad "STAGE 3: sandbox never Ready"; fatal "sandbox not Ready"; fi
sbx_run id -u
if [ "$RUNC" = 0 ] && [ "$(cat "$OUT_FILE")" != 0 ]; then ok "STAGE 3: sandbox runs as uid $(cat "$OUT_FILE"), not root"; else bad "STAGE 3: sandbox uid check failed"; fi
vm docker ps --format '{{.Names}} network={{.Networks}}' | sed 's/^/  | /'
check "STAGE 3: sandbox container has network none" vm_sh "docker ps --format '{{.Names}} {{.Networks}}' | grep -- '--$SBX-' | grep -v -- '-supervisor ' | grep -q ' none\$'"
check "STAGE 3: /run/tmb is not visible in the sandbox" sh -c "! limactl shell --workdir / '$VM' openshell sandbox exec '$SBX' --no-login-shell -- test -e /run/tmb/tmb.sock </dev/null"

vm_user_sh "openshell policy get $SBX --full -o json | jq '.policy | .network_policies = {\"tmb\": {\"endpoints\": [{\"host\": \"$SERVER_NAME\", \"port\": $TLS_PORT, \"protocol\": \"tcp\", \"tls\": \"skip\"}], \"binaries\": [{\"path\": \"/usr/local/bin/tmb\"}]}}' > /tmp/tmb-policy.json && timeout 90 openshell policy set $SBX --policy /tmp/tmb-policy.json --wait" >"$OUT_FILE" 2>&1 \
  || { sed 's/^/  | /' "$OUT_FILE"; fatal "policy set failed"; }
vm_user_sh "openshell policy get $SBX --full -o json | jq -c '.policy.network_policies'" >"$OUT_FILE" 2>&1; sed 's/^/  | /' "$OUT_FILE"
# shellcheck disable=SC2016 # jq variables
check "STAGE 3: effective policy is the single rule tcp + tls skip -> $SERVER_NAME:$TLS_PORT for /usr/local/bin/tmb" \
  jq -e --arg h "$SERVER_NAME" --argjson p "$TLS_PORT" '(keys == ["tmb"]) and (.tmb.endpoints | length == 1) and (.tmb.endpoints[0] | .host == $h and .port == $p and .protocol == "tcp" and .tls == "skip") and (.tmb.binaries == [{"path": "/usr/local/bin/tmb"}])' "$OUT_FILE"
# Lima forwards guest loopback listeners to the Mac unless the template
# ignores them; the broker and the gateway have listened for a while by now
LIMA_LISTEN=$(lsof -nP -a -c limactl -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $9}' | grep -E ":($TLS_PORT|$GW_PORT)\$")
if [ -z "$LIMA_LISTEN" ]; then ok "STAGE 3: Lima forwards neither the broker ($TLS_PORT) nor the gateway ($GW_PORT) port to the Mac"
else bad "STAGE 3: Lima forwards guest ports to the Mac: $(echo "$LIMA_LISTEN" | tr '\n' ' ')"; fi

# -----------------------------------------------------------------------------
log "SCENARIO V3: tmb keygen in the sandbox, ca issue-sandbox, allowlist, reload, approval from a second session"

sbx -- tmb keygen --out "$SK/sbx.key" </dev/null >"$TD/keygen.out" 2>"$TD/keygen.err"; RUNC=$?
OUT_FILE=$TD/keygen.out; ERR_FILE=$TD/keygen.err; show_io; reset_io
assert_rc "V3: tmb keygen in the sandbox -> exit 0" 0
if [ "$(sbx -- stat -c %a "$SK/sbx.key" </dev/null)" = 600 ]; then ok "V3: sandbox key file is 0600"; else bad "V3: sandbox key file mode is not 0600"; fi
if grep -q "PRIVATE KEY" "$TD/keygen.out"; then bad "V3: keygen printed private key material"; else ok "V3: keygen printed only the public key"; fi
sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$TD/keygen.out" >"$TD/sbx.pub"
FP=$(sed -n 's/^fingerprint: //p' "$TD/keygen.out")
echo "-- public key goes to the host; the CA signs it"
limactl shell --workdir / "$VM" sudo tmb-broker ca issue-sandbox --in - --name "$SBX" --out /etc/tmb/ca/sandbox-v.crt <"$TD/sbx.pub" >"$TD/issue.out" 2>&1
sed 's/^/  | /' "$TD/issue.out"
FP_CA=$(sed -n 's/^fingerprint: //p' "$TD/issue.out")
if [ "${#FP}" = 64 ] && [ "$FP_CA" = "$FP" ]; then ok "V3: ca issue-sandbox prints the fingerprint keygen printed ($FP)"; else bad "V3: fingerprints differ (keygen '$FP', CA '$FP_CA')"; fi
check "V3: sandbox certificate valid for 7 days" vm_sh "openssl x509 -in /etc/tmb/ca/sandbox-v.crt -noout -checkend $((6*86400)) >/dev/null && ! openssl x509 -in /etc/tmb/ca/sandbox-v.crt -noout -checkend $((8*86400)) >/dev/null"
vm cat /etc/tmb/ca/sandbox-v.crt >"$TD/sbx-v3.crt"
vm cat /etc/tmb/ca/ca.crt >"$TD/ca.crt"
sbx_put "$TD/sbx-v3.crt" "$SK/sbx.crt" </dev/null
sbx_put "$TD/ca.crt" "$SK/ca.crt"
if [ "$(sbx -- tmb fingerprint "$SK/sbx.crt" </dev/null)" = "$FP" ]; then ok "V3: certificate in the sandbox carries the key fingerprint"; else bad "V3: certificate in the sandbox has another fingerprint"; fi
check "V3: the sandbox private key never reached the host" sh -c "! limactl shell --workdir / '$VM' sudo grep -rlsI -e 'BEGIN PRIVATE KEY' /etc/tmb /tmp /home/human /root </dev/null | grep -v '^/etc/tmb/ca/\(ca\|server\)\.key\$' | grep -q ."

echo "-- before enrollment the key is not allowlisted"
RLN=$(jcount '"event":"reload"'); RLN=${RLN:-0}
set_config ".allowed_requester_keys=[\"$FP\"]"
vm_run systemctl reload tmb-broker
assert_rc "V3: systemctl reload after adding the fingerprint -> exit 0" 0
wait_jcount '"event":"reload"' $((RLN+1)) || true
if jlast '"event":"reload"' | grep -q '"allowed_requester_keys"'; then ok "V3: reload event names allowed_requester_keys"; else bad "V3: reload event lacks allowed_requester_keys"; fi

if start_request v3 /usr/bin/id -u; then
  ok "V3: request queued as item $REQ_ITEM"
  sleep 2
  if kill -0 "$REQ_PID" 2>/dev/null; then ok "V3: tmb exec in the sandbox waits for approval"; else bad "V3: tmb exec did not wait"; fi
  check "V3: queued event carries requester_fp of the sandbox key" sh -c "limactl shell --workdir / '$VM' sudo grep '\"item\":\"$REQ_ITEM\"' $RJ </dev/null | grep '\"event\":\"queued\"' | grep -q '\"requester_fp\":\"$FP\"'"
  human tmb approve --list >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
  assert_out_has "V3: human sees the item in tmb approve --list" "$REQ_ITEM"
  human tmb approve --yes "$REQ_ITEM" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
  assert_rc "V3: tmb approve --yes as human (uid $HUMAN_UID) -> exit 0" 0
  finish_request
  assert_rc     "V3: tmb exec --root -- /usr/bin/id -u -> exit 0" 0
  assert_out_eq "V3: stdout is exactly '0'" "0"
  reset_io
else
  bad "V3: request never queued"
fi
journal_tail 4

# -----------------------------------------------------------------------------
log "SCENARIO V4: reissue on the same key, allowlist untouched -> passes, same requester_fp"

CFG_SUM=$(vm sha256sum /etc/tmb/config.json | awk '{print $1}')
limactl shell --workdir / "$VM" sudo tmb-broker ca issue-sandbox --in - --name "$SBX" --out /etc/tmb/ca/sandbox-v.crt <"$TD/sbx.pub" >"$TD/issue2.out" 2>&1
sed 's/^/  | /' "$TD/issue2.out"
if [ "$(sed -n 's/^fingerprint: //p' "$TD/issue2.out")" = "$FP" ]; then ok "V4: reissue prints the same fingerprint"; else bad "V4: reissue printed another fingerprint"; fi
vm cat /etc/tmb/ca/sandbox-v.crt >"$TD/sbx-v4.crt"
S3=$(openssl x509 -in "$TD/sbx-v3.crt" -noout -serial); S4=$(openssl x509 -in "$TD/sbx-v4.crt" -noout -serial)
if [ "$S3" != "$S4" ]; then ok "V4: new certificate ($S4, was $S3)"; else bad "V4: certificate serial did not change"; fi
sbx_put "$TD/sbx-v4.crt" "$SK/sbx.crt"
if cmp -s <(sbx -- cat "$SK/sbx.crt" </dev/null) "$TD/sbx-v4.crt"; then ok "V4: the sandbox holds the reissued certificate"; else bad "V4: the sandbox certificate was not replaced"; fi
if [ "$(vm sha256sum /etc/tmb/config.json | awk '{print $1}')" = "$CFG_SUM" ]; then ok "V4: /etc/tmb/config.json untouched, no reload"; else bad "V4: config changed"; fi
REQ_N=$(jcount '"event":"request"')
request_approved v4 /usr/bin/id -u
assert_rc     "V4: request with the reissued certificate -> exit 0" 0
assert_out_eq "V4: stdout '0'" "0"
reset_io
if vm_sh "tail -n +$((REQ_N+1)) $RJ" | grep '"event":"request"' | grep -q "\"requester_fp\":\"$FP\""; then ok "V4: request event carries the same requester_fp $FP"; else bad "V4: request event lacks requester_fp $FP"; fi

# -----------------------------------------------------------------------------
log "SCENARIO V5: fingerprint removed, reload -> requester_not_allowed"

RLN=$(jcount '"event":"reload"'); RLN=${RLN:-0}
set_config '.allowed_requester_keys=[]'
vm_run systemctl reload tmb-broker
assert_rc "V5: systemctl reload after removing the fingerprint -> exit 0" 0
wait_jcount '"event":"reload"' $((RLN+1)) || true
RD=$(jcount '"event":"requester_denied"'); RD=${RD:-0}
sbx "${CLIENV[@]}" -- tmb exec --root -- /usr/bin/id -u </dev/null >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "V5: removed key -> client exit 125 (denied)" 125
assert_err_has "V5: deny reason requester_not_allowed" "requester_not_allowed"
if [ "$(jcount '"event":"requester_denied"')" -gt "$RD" ] && jlast '"event":"requester_denied"' | grep -q "\"requester_fp\":\"$FP\""; then
  ok "V5: requester_denied with requester_fp of the removed key"
else bad "V5: no requester_denied for the removed key"; fi
if [ "$(human tmb approve --list)" = "queue is empty" ]; then ok "V5: nothing reached the approval queue"; else bad "V5: the queue is not empty"; fi
echo "-- restore the fingerprint for V6-V8"
RLN=$(jcount '"event":"reload"'); RLN=${RLN:-0}
set_config ".allowed_requester_keys=[\"$FP\"]"
vm systemctl reload tmb-broker
wait_jcount '"event":"reload"' $((RLN+1)) || true

# -----------------------------------------------------------------------------
log "SCENARIO V6: logrotate --force with the packaged config; events continue; tail -F follows"

vm_sh "rm -f /tmp/tailf.out; setsid nohup tail -n 0 -F $RJ >/tmp/tailf.out 2>&1 </dev/null & echo \$! >/tmp/tailf.pid"
sleep 1
INO1=$(vm stat -c %i "$RJ" | tr -d '[:space:]')
RLN_OLD=$(jcount '"event":"reload"'); RLN_OLD=${RLN_OLD:-0}
vm_run logrotate --force /etc/logrotate.d/tmb-broker
assert_rc "V6: logrotate --force /etc/logrotate.d/tmb-broker -> exit 0" 0
vm ls -li /var/log/tmb | sed 's/^/  | /'
if [ "$(vm stat -c %i "$RJ.1" 2>/dev/null | tr -d '[:space:]')" = "$INO1" ]; then ok "V6: old journal renamed to journal.jsonl.1 (same inode)"; else bad "V6: journal.jsonl.1 is not the old file"; fi
if [ "$(vm stat -c '%i %a' "$RJ" 2>/dev/null)" != "" ] && [ "$(vm stat -c %i "$RJ" | tr -d '[:space:]')" != "$INO1" ] && [ "$(vm stat -c %a "$RJ" | tr -d '[:space:]')" = 600 ]; then ok "V6: new journal.jsonl created with mode 0600"; else bad "V6: new journal.jsonl missing or wrong mode"; fi
if wait_jcount '"event":"reload"' 1; then ok "V6: postrotate reload wrote its event into the new file"; else bad "V6: no reload event in the new file"; fi
check "V6: broker_start stays in the rotated file only" sh -c "limactl shell --workdir / '$VM' sudo grep -q '\"event\":\"broker_start\"' $RJ.1 </dev/null && ! limactl shell --workdir / '$VM' sudo grep -q '\"event\":\"broker_start\"' $RJ </dev/null"
request_approved v6 /usr/bin/id -u
assert_rc     "V6: request after rotation -> exit 0" 0
assert_out_eq "V6: stdout '0'" "0"
reset_io
if vm grep -q "\"item\":\"$REQ_ITEM\"" "$RJ"; then ok "V6: events of the new request are in the new journal.jsonl"; else bad "V6: new request not in journal.jsonl"; fi
sleep 1
vm_sh "kill \$(cat /tmp/tailf.pid) 2>/dev/null; cat /tmp/tailf.out" >"$TD/tailf.out"
sed 's/^/  | /' "$TD/tailf.out" | cut -c1-200
if grep -q "\"item\":\"$REQ_ITEM\"" "$TD/tailf.out" && grep -q '"event":"exec_exit"' "$TD/tailf.out"; then ok "V6: tail -F saw the events written after the rotation"; else bad "V6: tail -F missed the events after the rotation"; fi
echo "(the rotated file is renamed; delaycompress gzips it on the next rotation; $RLN_OLD reload events before rotation)"

# -----------------------------------------------------------------------------
log "SCENARIO V7: systemctl kill -s KILL -> in-flight request exits 3, Restart=on-failure, human sudo works"

PID_OLD=$(main_pid)
NR_OLD=$(vm systemctl show -p NRestarts --value tmb-broker | tr -d '[:space:]')
if start_request v7 /usr/bin/id -u; then
  echo "-- item $REQ_ITEM waits for approval; SIGKILL to the broker (pid $PID_OLD)"
  # --kill-whom=main: the broker process only (KillMode=process semantics);
  # the default "all" also reports a failure for the gone ExecStartPre helper
  vm systemctl kill --kill-whom=main -s KILL tmb-broker
  finish_request
  assert_rc      "V7: in-flight request after SIGKILL -> client exit 3 (fail closed)" 3
  assert_err_has "V7: client reports the lost broker" "connection to broker lost"
  reset_io
  if vm grep -F "$REQ_ITEM" "$RJ" | grep -q '"event":"exec_start"'; then bad "V7: the killed request executed"; else ok "V7: nothing executed for item $REQ_ITEM"; fi
else
  bad "V7: request never queued"
fi
UP=0
for _ in $(seq 1 30); do
  P=$(main_pid)
  if vm systemctl is-active --quiet tmb-broker && [ -n "$P" ] && [ "$P" != 0 ] && [ "$P" != "$PID_OLD" ]; then UP=1; break; fi
  sleep 0.5
done
NR_NEW=$(vm systemctl show -p NRestarts --value tmb-broker | tr -d '[:space:]')
if [ "$UP" = 1 ] && [ "${NR_NEW:-0}" -gt "${NR_OLD:-0}" ]; then ok "V7: Restart=on-failure brought the broker back (pid $PID_OLD -> $(main_pid), NRestarts $NR_OLD -> $NR_NEW)"; else bad "V7: broker not restarted (active=$UP, NRestarts $NR_OLD -> $NR_NEW)"; fi
human bash -c 'echo human | sudo -S -p "" id' >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "V7: human sudo -S id -> exit 0" 0
assert_out_has "V7: sudo -S id returns uid=0(root)" "uid=0(root)"
PLUGIN_N=$(vm_sh 'grep -c "^Plugin" /etc/sudo.conf; true' | tr -d '[:space:]')
if [ "$PLUGIN_N" = 0 ]; then ok "V7: /etc/sudo.conf has 0 Plugin lines"; else bad "V7: /etc/sudo.conf has $PLUGIN_N Plugin lines"; fi
request_approved v7b /usr/bin/id -u
assert_rc "V7: the restarted broker serves the sandbox again -> exit 0" 0
reset_io

# -----------------------------------------------------------------------------
log "SCENARIO V8: an approved python3 one-liner (sleep 30, then a marker) survives systemctl restart"

# The approved command sleeps 30 s and then writes the marker. It is a
# python3 one-liner: shells are on shell_deny_list, and the broker refuses a
# '#!' script with executable_script before approval (PR #80): it execs the
# approved inode through /proc/self/fd/N, which is closed on exec before an
# interpreter could open it.
MARKER=/var/lib/tmb-v8.marker
V8_CODE="import time; time.sleep(30); open('$MARKER', 'w').close()"
check "V8: /usr/bin/python3 present on the host" vm test -x /usr/bin/python3
vm rm -f "$MARKER"
ES=$(jcount '"event":"exec_start"'); ES=${ES:-0}
if start_request v8 /usr/bin/python3 -c "$V8_CODE"; then
  human tmb approve --yes "$REQ_ITEM" | sed 's/^/  | human: /'
  if wait_jcount '"event":"exec_start"' $((ES+1)); then ok "V8: approved command started (exec_start)"; else bad "V8: no exec_start"; fi
  sleep 2
  if vm grep -F "$REQ_ITEM" "$RJ" | grep -q '"event":"exec_exit"'; then bad "V8: the command already exited before the restart"; else ok "V8: no exec_exit yet: the command runs"; fi
  PID_OLD=$(main_pid)
  T0=$(date +%s)
  vm_run systemctl restart tmb-broker
  assert_rc "V8: systemctl restart -> exit 0" 0
  if vm systemctl is-active --quiet tmb-broker && [ "$(main_pid)" != "$PID_OLD" ]; then ok "V8: broker active again with a new pid $(main_pid)"; else bad "V8: broker not active after restart"; fi
  # anchored: the sudo/pgrep ancestors of this probe must not match
  if vm pgrep -f '^/usr/bin/python3 -c import time' >/dev/null; then ok "V8: the approved command still runs after the restart (KillMode=process)"; else bad "V8: the approved command died with the broker"; fi
  check "V8: no marker yet right after the restart" vm test ! -e "$MARKER"
  M=0
  for _ in $(seq 1 60); do vm test -e "$MARKER" && { M=1; break; }; sleep 1; done
  if [ "$M" = 1 ]; then ok "V8: marker $MARKER appeared $(( $(date +%s) - T0 ))s after the restart"; else bad "V8: marker never appeared"; fi
  finish_request
  echo "-- the client lost its broker with the restart (rc=$RUNC); the command itself finished on the host"
  reset_io
else
  bad "V8: request never queued"
fi
check "V8: broker active at the end" vm systemctl is-active --quiet tmb-broker

# -----------------------------------------------------------------------------
log "SCENARIO V9: apt remove deletes the binary and the unit, keeps config, state and journal"

vm_run apt-get remove -y tmb-broker
assert_rc "V9: apt-get remove -y tmb-broker -> exit 0" 0
check "V9: /usr/bin/tmb-broker removed" vm test ! -e /usr/bin/tmb-broker
check "V9: unit file removed" vm test ! -e /usr/lib/systemd/system/tmb-broker.service
check "V9: broker no longer runs" sh -c "! limactl shell --workdir / '$VM' pgrep -x tmb-broker </dev/null >/dev/null"
for f in /etc/tmb/config.json /etc/tmb/ca/ca.key /etc/tmb/ca/server.crt /var/lib/tmb "$RJ" "$RJ.1"; do
  check "V9: $f kept" vm test -e "$f"
done
vm ls -la /etc/tmb /var/lib/tmb /var/log/tmb | sed 's/^/  | /'

# =============================================================================
log "SUMMARY"
printf '%s\n' "------------------------------------------------------------------"
printf '%s\n' "${ROWS[@]}"
printf '%s\n' "------------------------------------------------------------------"
echo "PASS: $PASS  FAIL: $FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: RED - unexpected behaviour detected"
  sleep 1
  exit 1
fi
echo "RESULT: GREEN - the packaged broker behaves as designed on a systemd host (OpenShell gateway on Linux, no topology deviation)"
sleep 1
exit 0
