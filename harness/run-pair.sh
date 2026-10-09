#!/usr/bin/env bash
# PROTOTYPE runner - throwaway PoC, not production.
#
# run-pair.sh: docker-pair proof of the mTLS transport (ticket #6), WITHOUT
# OpenShell (that is #8). host-sim runs tmb-broker with the second (TLS)
# listener; sandbox-sim reaches it over a dedicated docker network as
# host.openshell.internal.
#
# Ticket #7 adds the channel denials on the same pair: O7a (client cert fp2,
# same CA, not in allowlist), O7b (openssl s_client without a client cert),
# O7c (TMB_ADDR without cert env), O8 (foreign-CA broker endpoint) and O9
# (approval bound to the certificate identity).
#
# Certificates: harness CA + server cert (SAN host.openshell.internal) +
# client certs for fp1/fp2/fp3 are generated into a TEMP dir per run and
# never committed. The CA KEY never enters any container: only the crt/key
# files each side needs are mounted (O0-pair checks this).
#
# harness/run.sh (N-series, unix path) stays untouched: this script runs it
# as the final regression stage.
#
# Everything is logged to last-pair-run.log (tee'd).

set -u
cd "$(dirname "$0")"

HOST=tmb-pair-host
SBX=tmb-pair-sandbox
NET=tmb-pair-net
FAKE=tmb-pair-fakebroker # O8: throwaway foreign-CA TLS server (sandbox image has openssl, host-sim does not)
IMG_HOST=tmb-poc/host-sim
IMG_SBX=tmb-poc/sandbox-sim
SOCK_VOL=tmb-pair-sock-wipe-me
STATE_VOL=tmb-pair-state-wipe-me
TLS_PORT=17600
TLS_PUBLISH_PORT=${TLS_PUBLISH_PORT:-17600} # mac-side publish of the TLS port; scenarios go over the docker network, override when 17600 is taken on the host
SERVER_NAME=host.openshell.internal
TTL=3
TD=$(mktemp -d /tmp/tmb-pair.XXXXXX)
LOG=last-pair-run.log

PASS=0
FAIL=0
ROWS=()

exec > >(tee "$LOG") 2>&1

cleanup() {
  echo "=== cleanup ==="
  exec 9>&- 2>/dev/null
  docker rm -f "$HOST" "$SBX" "$FAKE" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  docker volume rm -f "$SOCK_VOL" "$STATE_VOL" >/dev/null 2>&1
  rm -rf "$TD"
}
trap cleanup EXIT

log() { printf '\n================================================================\n== %s\n================================================================\n' "$*"; }

ok()  { PASS=$((PASS+1)); ROWS+=("PASS | $1"); printf 'CHECK PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); ROWS+=("FAIL | $1"); printf 'CHECK FAIL: %s\n' "$1"; }

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
assert_err_has() { if grep -qF -- "$2" "$ERR_FILE" 2>/dev/null; then ok "$1"; else bad "$1 (stderr lacks '$2')"; fi; }

# run_tls_client CLIENT TMB-ARGS... : exec inside sandbox-sim with the TLS
# endpoint env of the named client certificate.
run_tls_client() {
  local cl=$1; shift
  docker exec \
    -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" \
    -e TMB_CA=/certs/ca.crt \
    -e TMB_CERT=/certs/$cl.crt \
    -e TMB_KEY=/certs/$cl.key \
    "$SBX" "$@" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
}

# run_tls_client_addr ADDR CLIENT TMB-ARGS... : same, but dials an arbitrary
# TMB_ADDR (O8 points the client at the foreign-CA endpoint).
run_tls_client_addr() {
  local addr=$1 cl=$2; shift 2
  docker exec \
    -e TMB_ADDR="$addr" \
    -e TMB_CA=/certs/ca.crt \
    -e TMB_CERT=/certs/$cl.crt \
    -e TMB_KEY=/certs/$cl.key \
    "$SBX" "$@" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
}

pair_token_of() { sed -n 's/.*"token":"\([0-9a-f]\{16\}\)".*/\1/p' "$ERR_FILE" | head -1; }

broker_log_count() { # PATTERN -> count of matching lines in broker.log
  docker exec "$HOST" sh -c "grep -c '$1' /var/log/tmb/broker.log" 2>/dev/null | tr -d '[:space:]'
}

broker_log_lines() { # total line count of broker.log (proves "nothing new")
  docker exec "$HOST" sh -c 'wc -l < /var/log/tmb/broker.log' 2>/dev/null | tr -d '[:space:]'
}

wait_broker_log_count() { # PATTERN N -> wait until count >= N
  local i pat=$1 want=$2
  for i in $(seq 1 150); do
    [ "$(broker_log_count "$pat")" -ge "$want" ] 2>/dev/null && return 0
    sleep 0.1
  done
  echo "FATAL: broker.log never reached $want x '$pat'"; exit 1
}

start_broker() { # MODE TTL
  echo "-- starting tmb-broker (mode=$1 ttl=$2s, config=/etc/tmb/config-pair.json)"
  docker exec -d "$HOST" tmb-broker -approval "$1" -ttl "$2" -config /etc/tmb/config-pair.json
}

# start_broker_console MODE TTL LOGFILE : detached broker whose console is
# captured to a file INSIDE host-sim (stdin detached, so a prompt that
# leaked through would fail closed into the log and be visible to grep).
start_broker_console() { # MODE TTL LOGFILE
  echo "-- starting tmb-broker with captured console (mode=$1 ttl=$2s, console=$3)"
  docker exec -d "$HOST" sh -c \
    "exec tmb-broker -approval '$1' -ttl '$2' -config /etc/tmb/config-pair.json >'$3' 2>&1"
}

stop_broker() {
  echo "-- stopping tmb-broker"
  docker exec "$HOST" pkill -TERM -x tmb-broker 2>/dev/null
  local i
  for i in $(seq 1 150); do
    docker exec "$HOST" sh -c 'pgrep -x tmb-broker >/dev/null' 2>/dev/null || return 0
    sleep 0.1
  done
  docker exec "$HOST" pkill -KILL -x tmb-broker 2>/dev/null
  sleep 0.3
}

state_dump() {
  echo "---- STATE: broker.log (last 10 lines) ----"
  docker exec "$HOST" tail -n 10 /var/log/tmb/broker.log 2>/dev/null | sed 's/^/  | /'
}

# =============================================================================
log "TMB PAIR RUNNER: mTLS transport proof ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
docker version --format 'docker {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})'
command -v openssl >/dev/null || { echo "FATAL: openssl is required on the harness host"; exit 1; }
echo "workdir: $(pwd), cert dir: $TD (temp, never committed)"

# -----------------------------------------------------------------------------
log "STAGE 1: generate harness CA + server + client certs into $TD"

cat > "$TD/openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
[ext_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:host.openshell.internal
[ext_client]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -keyout "$TD/ca.key" -out "$TD/ca.crt" \
  -subj "/CN=TMB Pair Harness CA" \
  -config "$TD/openssl.cnf" -extensions v3_ca >/dev/null 2>&1 \
  || { echo "FATAL: CA generation failed"; exit 1; }

openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -keyout "$TD/server.key" -out "$TD/server.csr" \
  -subj "/CN=$SERVER_NAME" -config "$TD/openssl.cnf" >/dev/null 2>&1
openssl x509 -req -sha256 -days 2 -in "$TD/server.csr" \
  -CA "$TD/ca.crt" -CAkey "$TD/ca.key" -CAcreateserial \
  -out "$TD/server.crt" -extfile "$TD/openssl.cnf" -extensions ext_server >/dev/null 2>&1 \
  || { echo "FATAL: server certificate failed"; exit 1; }

for n in 1 2 3; do
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$TD/client$n.key" -out "$TD/client$n.csr" \
    -subj "/CN=tmb-pair-client$n" -config "$TD/openssl.cnf" >/dev/null 2>&1
  openssl x509 -req -sha256 -days 2 -in "$TD/client$n.csr" \
    -CA "$TD/ca.crt" -CAkey "$TD/ca.key" -CAcreateserial \
    -out "$TD/client$n.crt" -extfile "$TD/openssl.cnf" -extensions ext_client >/dev/null 2>&1 \
    || { echo "FATAL: client$n certificate failed"; exit 1; }
done

# lower-case hex SHA-256 of the DER, no colons - the broker's identity form
fp_of() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 \
    | sed -n 's/^.*Fingerprint=//p' | tr -d ':' | tr 'A-F' 'a-f'
}
FP1=$(fp_of "$TD/client1.crt")
FP2=$(fp_of "$TD/client2.crt")
FP3=$(fp_of "$TD/client3.crt")
FP1_16=${FP1:0:16}
echo "-- fp1=$FP1"
echo "-- fp2=$FP2 (NOT in allowlist; exercised by ticket #7)"
echo "-- fp3=$FP3"
[ "${#FP1}" = 64 ] && [ "${#FP2}" = 64 ] && [ "${#FP3}" = 64 ] \
  || { echo "FATAL: fingerprints must be 64 hex chars"; exit 1; }
[ "$FP1" != "$FP2" ] && [ "$FP1" != "$FP3" ] \
  || { echo "FATAL: client fingerprints must differ"; exit 1; }

cat > "$TD/config-pair.json" <<EOF
{
  "_comment": "generated by run-pair.sh into a temp dir; never committed",
  "socket_path": "/run/tmb/tmb.sock",
  "state_dir": "/var/lib/tmb-proto",
  "log_path": "/var/log/tmb/broker.log",
  "pid_file": "/var/run/tmb-broker.pid",
  "allowed_requester_uids": [4242],
  "allowed_requester_fps": ["$FP1", "$FP3"],
  "socket_gid": 4242,
  "allowed_env_keys": ["LANG"],
  "fixed_env": {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8"
  },
  "shell_deny_list": [
    "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh",
    "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh",
    "/usr/bin/ksh", "/usr/bin/env", "/usr/bin/fish", "/bin/tcsh",
    "/usr/bin/tcsh", "/bin/csh", "/usr/bin/csh", "/usr/bin/busybox"
  ],
  "token_ttl_seconds": $TTL,
  "approval_default": "mock-approve",
  "tls_addr": ":$TLS_PORT",
  "tls_ca_file": "/etc/tmb/certs/ca.crt",
  "tls_cert_file": "/etc/tmb/certs/server.crt",
  "tls_key_file": "/etc/tmb/certs/server.key"
}
EOF

# Docker Desktop mounts these as root-owned files; the sandbox user (4242)
# must be able to read the client material. ca.key stays 0600 on the host
# and is never mounted anywhere.
chmod 644 "$TD/ca.crt" "$TD/server.crt" "$TD/server.key" \
  "$TD/client1.crt" "$TD/client1.key" "$TD/client2.crt" "$TD/client2.key" \
  "$TD/client3.crt" "$TD/client3.key" "$TD/config-pair.json"
chmod 600 "$TD/ca.key"

# -----------------------------------------------------------------------------
log "STAGE 2: O0-pair prerequisites (dependency surface + cert hygiene)"

echo "-- O0: go list -m all in src/ (in the pinned builder image)"
GOLIST=$(docker run --rm -e GOCACHE=/tmp/gocache \
  -v "$(cd .. && pwd)/src":/src:ro -w /src golang:1.23-alpine go list -m all 2>/dev/null)
echo "$GOLIST" | sed 's/^/  | /'
if [ "$(echo "$GOLIST" | tr -d '[:space:]')" = "tmb-poc" ]; then
  ok "O0-pair: go list -m all -> only tmb-poc (stdlib only)"
else
  bad "O0-pair: go list -m all -> '$GOLIST' (want only tmb-poc)"
fi

echo "-- O0: build images (context: repo root)"
docker build -q -f images/Dockerfile.host -t "$IMG_HOST" .. || { echo "FATAL: host image build failed"; exit 1; }
docker build -q -f images/Dockerfile.sandbox -t "$IMG_SBX" .. || { echo "FATAL: sandbox image build failed"; exit 1; }

docker network rm "$NET" >/dev/null 2>&1
docker network create "$NET" >/dev/null || { echo "FATAL: network create failed"; exit 1; }

echo "-- starting host-sim (broker host; TLS port published, network alias $SERVER_NAME)"
docker run -d --name "$HOST" \
  --network "$NET" --network-alias "$SERVER_NAME" \
  -p "127.0.0.1:${TLS_PUBLISH_PORT}:${TLS_PORT}" \
  -v "$SOCK_VOL":/run/tmb \
  -v "$STATE_VOL":/var/lib/tmb-proto \
  -v "$TD/ca.crt":/etc/tmb/certs/ca.crt:ro \
  -v "$TD/server.crt":/etc/tmb/certs/server.crt:ro \
  -v "$TD/server.key":/etc/tmb/certs/server.key:ro \
  -v "$TD/config-pair.json":/etc/tmb/config-pair.json:ro \
  "$IMG_HOST" >/dev/null || { echo "FATAL: host-sim run failed"; exit 1; }

echo "-- starting sandbox-sim (uid 4242, client material only)"
docker run -d --name "$SBX" \
  --network "$NET" \
  -v "$SOCK_VOL":/run/tmb \
  -v "$TD/ca.crt":/certs/ca.crt:ro \
  -v "$TD/client1.crt":/certs/client1.crt:ro -v "$TD/client1.key":/certs/client1.key:ro \
  -v "$TD/client2.crt":/certs/client2.crt:ro -v "$TD/client2.key":/certs/client2.key:ro \
  -v "$TD/client3.crt":/certs/client3.crt:ro -v "$TD/client3.key":/certs/client3.key:ro \
  "$IMG_SBX" >/dev/null || { echo "FATAL: sandbox-sim run failed"; exit 1; }
sleep 0.5

echo "-- O0: ca.crt mounted, ca.key NOT in any container"
docker exec "$HOST" test -f /etc/tmb/certs/ca.crt \
  && ok "O0-pair: ca.crt present in host-sim" || bad "O0-pair: ca.crt missing in host-sim"
docker exec "$HOST" test ! -e /etc/tmb/certs/ca.key \
  && ok "O0-pair: ca.key NOT in host-sim" || bad "O0-pair: ca.key LEAKED into host-sim"
docker exec "$SBX" test -f /certs/ca.crt \
  && ok "O0-pair: ca.crt present in sandbox-sim" || bad "O0-pair: ca.crt missing in sandbox-sim"
docker exec "$SBX" test ! -e /certs/ca.key \
  && ok "O0-pair: ca.key NOT in sandbox-sim" || bad "O0-pair: ca.key LEAKED into sandbox-sim"
docker exec "$SBX" test ! -e /certs/server.key \
  && ok "O0-pair: server.key NOT in sandbox-sim" || bad "O0-pair: server.key LEAKED into sandbox-sim"

echo "-- O0: sandbox tools required by the O-series (sh, id, test, openssl)"
for tool in sh id test openssl; do
  if docker exec "$SBX" sh -c "command -v $tool" >/dev/null 2>&1; then
    ok "O0-pair: sandbox has $tool"
  else
    bad "O0-pair: sandbox lacks $tool"
  fi
done

echo "-- O0: sandbox resolves $SERVER_NAME via the docker network"
if docker exec "$SBX" getent hosts "$SERVER_NAME" >/dev/null 2>&1; then
  ok "O0-pair: $SERVER_NAME resolves in sandbox-sim"
else
  bad "O0-pair: $SERVER_NAME does NOT resolve in sandbox-sim"
fi

# -----------------------------------------------------------------------------
log "STAGE 3: broker with the TLS listener (mock-approve)"
start_broker mock-approve "$TTL"
wait_broker_log_count '"event":"tls_listen"' 1
ok "PAIR: broker logged tls_listen (TLS 1.3, client certs required)"
docker exec "$HOST" grep '"event":"tls_listen"' /var/log/tmb/broker.log | tail -1 | sed 's/^/  | /'

# -----------------------------------------------------------------------------
log "SCENARIO PAIR-HAPPY: tmb exec over mTLS from sandbox-sim, mock-approve"
run_tls_client client1 tmb exec --root -- /usr/bin/id -u
assert_rc    "PAIR-HAPPY: exit code 0" 0
assert_out_eq "PAIR-HAPPY: stdout is exactly '0'" "0"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO PAIR-JSONL: TLS-path events carry requester_fp (fp1)"
for ev in request approval claim exec_start exec_exit; do
  if docker exec "$HOST" grep -q "\"event\":\"$ev\".*\"requester_fp\":\"$FP1\"" /var/log/tmb/broker.log 2>/dev/null; then
    ok "PAIR-JSONL: $ev carries requester_fp=fp1"
  else
    bad "PAIR-JSONL: $ev lacks requester_fp=fp1"
  fi
done
echo "-- sample request/approval/claim lines:"
docker exec "$HOST" grep -E '"event":"(request|approval|claim|exec_start|exec_exit)"' /var/log/tmb/broker.log 2>/dev/null | tail -5 | sed 's/^/  | /'

# -----------------------------------------------------------------------------
log "SCENARIO PAIR-NOKEY: TMB_ADDR without TMB_CERT/TMB_KEY -> exit 2, NO connection"
REQ_BEFORE=$(broker_log_count '"event":"request"')
docker exec \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
  "$SBX" tmb exec --root -- /usr/bin/id -u >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "PAIR-NOKEY: exit code 2 (usage)" 2
assert_err_has "PAIR-NOKEY: stderr says no connection attempted" "no connection attempted"
REQ_AFTER=$(broker_log_count '"event":"request"')
if [ "$REQ_BEFORE" = "$REQ_AFTER" ]; then
  ok "PAIR-NOKEY: no request reached the broker ($REQ_AFTER requests total)"
else
  bad "PAIR-NOKEY: request count changed $REQ_BEFORE -> $REQ_AFTER"
fi

# -----------------------------------------------------------------------------
log "SCENARIO PAIR-PLAINTEXT: plaintext TCP to the TLS port fails the handshake"
HSF_BEFORE=$(broker_log_count '"event":"tls_handshake_failed"')
docker exec "$SBX" bash -c "exec 3<>/dev/tcp/$SERVER_NAME/$TLS_PORT && printf 'PLAINTEXT-NOT-TLS' >&3 && exec 3>&-" >/dev/null 2>&1
sleep 1
HSF_AFTER=$(broker_log_count '"event":"tls_handshake_failed"')
if [ "$HSF_AFTER" -gt "$HSF_BEFORE" ]; then
  ok "PAIR-PLAINTEXT: broker logged tls_handshake_failed ($HSF_BEFORE -> $HSF_AFTER), no plaintext fallback"
  docker exec "$HOST" grep '"event":"tls_handshake_failed"' /var/log/tmb/broker.log | tail -1 | sed 's/^/  | /'
else
  bad "PAIR-PLAINTEXT: no tls_handshake_failed logged ($HSF_BEFORE -> $HSF_AFTER)"
fi

# -----------------------------------------------------------------------------
log "SCENARIO PAIR-MANUAL: manual console shows 'requester : cert fp=<16 hex>', y then n"
stop_broker
FIFO=$TD/broker-console.in
MANLOG=$TD/manual-console.log
mkfifo "$FIFO"
docker exec -i "$HOST" tmb-broker -approval manual -ttl 10 -config /etc/tmb/config-pair.json <"$FIFO" >"$MANLOG" 2>&1 &
MAN_PID=$!
exec 9>"$FIFO"
wait_broker_log_count '"event":"tls_listen"' 2
echo "-- manual broker up (console captured to $MANLOG)"

wait_prompt() { # Nth prompt
  local i n
  for i in $(seq 1 150); do
    n=$(grep -c 'Approve exactly this command' "$MANLOG" 2>/dev/null || true)
    if [ "${n:-0}" -ge "$1" ]; then return 0; fi
    sleep 0.1
  done
  echo "FATAL: manual prompt #$1 never appeared"; cat "$MANLOG"; exit 1
}

echo "-- round 1: TLS client (fp1) asks for /usr/bin/id -u, human types y"
docker exec \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" \
  -e TMB_CA=/certs/ca.crt -e TMB_CERT=/certs/client1.crt -e TMB_KEY=/certs/client1.key \
  "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/man1.out" 2>"$TD/man1.err" &
CLI1=$!
wait_prompt 1
if grep -qF "requester : cert fp=$FP1_16" "$MANLOG"; then
  ok "PAIR-MANUAL: console line 'requester : cert fp=$FP1_16'"
else
  bad "PAIR-MANUAL: console lacks 'requester : cert fp=$FP1_16'"
fi
echo "---- manual approval console ----"
sed -n '1,12p' "$MANLOG" | sed 's/^/  | /'
printf 'y\n' >&9
wait $CLI1; RUNC=$?
OUT_FILE=$TD/man1.out; ERR_FILE=$TD/man1.err; show_io
assert_rc     "PAIR-MANUAL: human 'y' -> command runs, exit 0" 0
assert_out_eq "PAIR-MANUAL: stdout is exactly '0'" "0"

echo "-- round 2: same client asks again, human types n"
docker exec \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" \
  -e TMB_CA=/certs/ca.crt -e TMB_CERT=/certs/client1.crt -e TMB_KEY=/certs/client1.key \
  "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/man2.out" 2>"$TD/man2.err" &
CLI2=$!
wait_prompt 2
printf 'n\n' >&9
wait $CLI2; RUNC=$?
OUT_FILE=$TD/man2.out; ERR_FILE=$TD/man2.err; show_io
assert_rc      "PAIR-MANUAL: human 'n' -> denied, exit 125" 125
assert_err_has "PAIR-MANUAL: deny reason approval_denied_by_human" "approval_denied_by_human"
if docker exec "$HOST" grep -q "\"event\":\"deny\".*\"requester_fp\":\"$FP1\"" /var/log/tmb/broker.log 2>/dev/null; then
  ok "PAIR-MANUAL: deny event carries requester_fp=fp1"
else
  bad "PAIR-MANUAL: deny event lacks requester_fp=fp1"
fi
stop_broker
wait $MAN_PID 2>/dev/null
exec 9>&-
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO O7-A: foreign client cert fp2 (same CA, NOT in allowlist) -> denied BEFORE approval"

# One manual-mode broker serves all of O7-A/O7-B/O7-C with its console
# captured inside host-sim: a denial that leaked to the approval stage would
# print 'TMB APPROVAL REQUIRED' into the console log (stdin is detached, so
# it would then fail closed with 'CLOSED (no human input)'), which every
# console check below would catch.
TLN=$(broker_log_count '"event":"tls_listen"'); TLN=${TLN:-0}
RD2_BEFORE=$(broker_log_count "\"event\":\"requester_denied\".*\"requester_fp\":\"$FP2\"")
RD2_BEFORE=${RD2_BEFORE:-0}
start_broker_console manual 30 /tmp/o7-console.log
wait_broker_log_count '"event":"tls_listen"' $((TLN+1))

run_tls_client client2 tmb exec --root -- /usr/bin/id -u
assert_rc      "O7-A: fp2 exec -> exit 125" 125
assert_err_has "O7-A: deny reason requester_not_allowed" "requester_not_allowed"

RD2_AFTER=$(broker_log_count "\"event\":\"requester_denied\".*\"requester_fp\":\"$FP2\"")
if [ "${RD2_AFTER:-0}" -gt "$RD2_BEFORE" ]; then
  ok "O7-A: JSONL requester_denied with requester_fp=fp2 ($RD2_BEFORE -> $RD2_AFTER)"
  docker exec "$HOST" grep '"event":"requester_denied"' /var/log/tmb/broker.log | tail -1 | sed 's/^/  | /'
else
  bad "O7-A: no requester_denied event with requester_fp=fp2 ($RD2_BEFORE -> ${RD2_AFTER:-?})"
fi

if docker exec "$HOST" grep -q 'TMB APPROVAL REQUIRED' /tmp/o7-console.log 2>/dev/null; then
  bad "O7-A: approval console WAS bothered (prompt printed)"
else
  ok "O7-A: approval console NOT bothered (denied before approval display)"
fi
if docker exec "$HOST" grep -q 'cert fp=' /tmp/o7-console.log 2>/dev/null; then
  bad "O7-A: console showed a requester line"
else
  ok "O7-A: console shows no 'requester : cert fp=' line"
fi
echo "-- manual broker console so far --"
docker exec "$HOST" cat /tmp/o7-console.log 2>/dev/null | sed 's/^/  | /'

# -----------------------------------------------------------------------------
log "SCENARIO O7-B: openssl s_client WITHOUT a client cert -> TLS alert, handshake failed"

HSF_BEFORE=$(broker_log_count '"event":"tls_handshake_failed"'); HSF_BEFORE=${HSF_BEFORE:-0}
docker exec "$SBX" openssl s_client -connect "$SERVER_NAME:$TLS_PORT" -CAfile /certs/ca.crt </dev/null \
  >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
cat "$OUT_FILE" "$ERR_FILE" >"$TD/sclient-o7b.all"
if [ "$RUNC" -ne 0 ]; then
  ok "O7-B: s_client exited non-zero (rc=$RUNC, handshake failed)"
else
  bad "O7-B: s_client exited 0 despite the failed handshake"
fi
if grep -qi 'alert' "$TD/sclient-o7b.all"; then
  ok "O7-B: output shows a TLS alert"
else
  bad "O7-B: no TLS alert evidence in s_client output"
fi
if grep -Eqi 'certificate[ _-]?required' "$TD/sclient-o7b.all"; then
  ok "O7-B: alert is 'certificate required' (server demands the client cert)"
else
  bad "O7-B: expected 'certificate required' alert text not found"
fi

HSF_AFTER=$(broker_log_count '"event":"tls_handshake_failed"')
if [ "${HSF_AFTER:-0}" -gt "$HSF_BEFORE" ]; then
  ok "O7-B: JSONL tls_handshake_failed logged ($HSF_BEFORE -> $HSF_AFTER)"
  HSF_LINE=$(docker exec "$HOST" grep '"event":"tls_handshake_failed"' /var/log/tmb/broker.log | tail -1)
  echo "  | $HSF_LINE"
  if printf '%s' "$HSF_LINE" | grep -q 'requester_fp'; then
    bad "O7-B: tls_handshake_failed carries a fingerprint (must have none)"
  else
    ok "O7-B: tls_handshake_failed has NO fingerprint field"
  fi
else
  bad "O7-B: no new tls_handshake_failed event ($HSF_BEFORE -> ${HSF_AFTER:-?})"
fi

# -----------------------------------------------------------------------------
log "SCENARIO O7-C: TMB_ADDR set but TMB_CERT/TMB_KEY unset -> exit 2, no connection"

LINES_BEFORE=$(broker_log_lines)
docker exec -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" "$SBX" tmb exec --root -- /usr/bin/id -u \
  >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "O7-C: exit code 2 (usage, no cert material)" 2
assert_err_has "O7-C: client refused to connect" "no connection attempted"
LINES_AFTER=$(broker_log_lines)
if [ "${LINES_BEFORE:-x}" = "${LINES_AFTER:-y}" ]; then
  ok "O7-C: broker JSONL unchanged ($LINES_AFTER lines) - nothing reached the broker"
else
  bad "O7-C: broker JSONL changed $LINES_BEFORE -> ${LINES_AFTER:-?} lines"
fi
if docker exec "$HOST" grep -q 'TMB APPROVAL REQUIRED' /tmp/o7-console.log 2>/dev/null; then
  bad "O7-C: approval console was bothered somewhere in O7-A/B/C"
else
  ok "O7-C: approval console never bothered across O7-A/O7-B/O7-C"
fi
stop_broker
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO O8: foreign-CA broker endpoint -> client fail-closed (x509), no frame sent"

# host-sim has no openssl (its image is intentionally minimal and its
# Dockerfile is out of scope here), so the fake broker runs as a throwaway
# container from the SAME sandbox image on the same network, on the SAME
# port number as the real endpoint, alias fake.openshell.internal. Its
# certificate is signed by a SECOND, untrusted CA generated into the same
# temp-dir lifecycle as the harness CA; the SAN is valid for the fake alias
# on purpose, so the ONLY thing wrong is the trust chain.
cat >"$TD/foreign-openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
[dn]
[foreign_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
[ext_foreign_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:fake.openshell.internal
EOF
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -keyout "$TD/foreign-ca.key" -out "$TD/foreign-ca.crt" \
  -subj "/CN=TMB Pair Foreign CA (untrusted)" \
  -config "$TD/foreign-openssl.cnf" -extensions foreign_ca >/dev/null 2>&1 \
  || { echo "FATAL: foreign CA generation failed"; exit 1; }
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -keyout "$TD/foreign-server.key" -out "$TD/foreign-server.csr" \
  -subj "/CN=fake.openshell.internal" -config "$TD/foreign-openssl.cnf" >/dev/null 2>&1
openssl x509 -req -sha256 -days 2 -in "$TD/foreign-server.csr" \
  -CA "$TD/foreign-ca.crt" -CAkey "$TD/foreign-ca.key" -CAcreateserial \
  -out "$TD/foreign-server.crt" -extfile "$TD/foreign-openssl.cnf" -extensions ext_foreign_server >/dev/null 2>&1 \
  || { echo "FATAL: foreign server certificate failed"; exit 1; }
chmod 644 "$TD/foreign-server.crt" "$TD/foreign-server.key"

docker rm -f "$FAKE" >/dev/null 2>&1
docker run -d --name "$FAKE" --network "$NET" \
  --network-alias fake.openshell.internal "$IMG_SBX" >/dev/null \
  || { echo "FATAL: fake broker container run failed"; exit 1; }
docker cp "$TD/foreign-server.crt" "$FAKE":/tmp/foreign-server.crt >/dev/null
docker cp "$TD/foreign-server.key" "$FAKE":/tmp/foreign-server.key >/dev/null
# tail -f holds s_server's stdin open forever (no EOF exit) and every byte
# s_server ever receives is echoed into the captured log.
docker exec -d "$FAKE" sh -c \
  "tail -f /dev/null | openssl s_server -accept $TLS_PORT -cert /tmp/foreign-server.crt -key /tmp/foreign-server.key >/tmp/fake-broker.log 2>&1"
FAKE_UP=0
for i in $(seq 1 100); do
  docker exec "$FAKE" bash -c "exec 3<>/dev/tcp/127.0.0.1/$TLS_PORT" 2>/dev/null && { FAKE_UP=1; break; }
  sleep 0.1
done
[ "$FAKE_UP" = 1 ] || { echo "FATAL: fake TLS server never listened on :$TLS_PORT"; exit 1; }
ok "O8: foreign-CA TLS server listening on fake.openshell.internal:$TLS_PORT"

run_tls_client_addr "fake.openshell.internal:$TLS_PORT" client1 tmb exec --root -- /usr/bin/id -u
assert_rc      "O8: client to foreign broker -> exit 3 (fail closed)" 3
assert_err_has "O8: stderr shows x509 verification failure" "x509"
assert_err_has "O8: verification reason is unknown authority" "certificate signed by unknown authority"
assert_err_has "O8: stderr says FAIL CLOSED" "FAIL CLOSED"

echo "-- fake broker log (handshake noise only; must contain NO request payload) --"
docker exec "$FAKE" cat /tmp/fake-broker.log 2>/dev/null | sed 's/^/  | /'
if docker exec "$FAKE" grep -Eq 'executable|nonce|argv|/usr/bin/id' /tmp/fake-broker.log 2>/dev/null; then
  bad "O8: fake broker RECEIVED application data (request frame leaked)"
else
  ok "O8: fake broker received NO application-data frame (aborted during handshake)"
fi
docker rm -f "$FAKE" >/dev/null 2>&1

# -----------------------------------------------------------------------------
log "SCENARIO O9: approval bound to cert identity (fp1 approves; fp3 is allowlisted but must not redeem)"

TLN=$(broker_log_count '"event":"tls_listen"'); TLN=${TLN:-0}
start_broker mock-approve 30
wait_broker_log_count '"event":"tls_listen"' $((TLN+1))
cat >"$TD/o9.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"env":{"LANG":"C.UTF-8"},"nonce":"o9-nonce-fixed-000007"}
EOF

echo "-- approve under fp1 (allowlisted)"
docker exec -i \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
  -e TMB_CERT=/certs/client1.crt -e TMB_KEY=/certs/client1.key \
  "$SBX" tmb approve --json - <"$TD/o9.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc "O9: approve under fp1 -> exit 0" 0
T9=$(pair_token_of)
echo "-- token from fp1 approve: ${T9:-<none>}"
if [ -n "$T9" ]; then ok "O9: got one-shot token $T9"; else bad "O9: no token parsed from approve"; fi

echo "-- claim under fp3 (allowlisted, but NOT the approver)"
docker exec -i \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
  -e TMB_CERT=/certs/client3.crt -e TMB_KEY=/certs/client3.key \
  "$SBX" tmb claim --token "$T9" --json - <"$TD/o9.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "O9: claim under fp3 -> exit 125" 125
assert_err_has "O9: deny reason requester_mismatch" "requester_mismatch"
assert_err_has "O9: token NOT consumed by the mismatch" "token not consumed"
if docker exec "$HOST" grep '"reason":"requester_mismatch"' /var/log/tmb/broker.log 2>/dev/null \
  | grep -q "\"requester_fp\":\"$FP3\""; then
  ok "O9: JSONL deny requester_mismatch carries requester_fp=fp3"
else
  bad "O9: JSONL lacks requester_mismatch deny with requester_fp=fp3"
fi

echo "-- claim again under fp1 (the approver): token must still be alive"
docker exec -i \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
  -e TMB_CERT=/certs/client1.crt -e TMB_KEY=/certs/client1.key \
  "$SBX" tmb claim --token "$T9" --json - <"$TD/o9.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc     "O9: token NOT consumed; claim under fp1 -> exit 0" 0
assert_out_eq "O9: stdout is exactly '0'" "0"
stop_broker
state_dump

# -----------------------------------------------------------------------------
log "STAGE 4: N-series regression (harness/run.sh must stay green, untouched)"
echo "-- running: bash run.sh"
if bash run.sh; then
  ok "REGRESSION: harness/run.sh exited 0"
else
  bad "REGRESSION: harness/run.sh exited non-zero"
fi
N_SUMMARY=$(sed -n 's/^PASS: \([0-9]*\)  FAIL: \([0-9]*\)$/\1 \2/p' last-run.log | tail -1)
echo "run.sh summary: PASS/FAIL = ${N_SUMMARY:-<not parsed>}"
N_PASS=${N_SUMMARY%% *}
N_FAIL=${N_SUMMARY##* }
if [ "${N_PASS:-x}" = "62" ] && [ "${N_FAIL:-x}" = "0" ]; then
  ok "REGRESSION: N-series 62/62 green"
else
  bad "REGRESSION: N-series PASS=${N_PASS:-?} FAIL=${N_FAIL:-?} (want 62/0)"
fi

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
echo "RESULT: GREEN - mTLS docker-pair behaves exactly as designed"
echo "(certs were generated into $TD and are wiped by the cleanup trap; CA key never entered any container)"
sleep 1
exit 0
