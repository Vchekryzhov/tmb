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
# Certificates: CA + server cert (SAN host.openshell.internal) + client
# certs for fp1/fp2/fp3 are issued by `tmb-broker ca` into a TEMP dir per run
# and never committed. The CA KEY never enters any container: only the crt/key
# files each side needs are mounted (O0-pair checks this).
#
# harness/run.sh (N-series, unix path) stays untouched: this script runs it
# as the final regression stage.
#
# Everything is logged to last-pair-run.log (tee'd).

set -u
cd "$(dirname "$0")" || exit 1

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

# Integration coverage (#83): with TMB_COVER_DIR set (ci/run.sh harness) the
# images carry binaries built with -cover and the containers get GOCOVERDIR.
# Before the containers go, the running broker is stopped with SIGTERM so it
# writes its counters, then the coverage data and the broker journal are
# copied out with docker cp (no host mounts). A broker killed with SIGKILL
# writes no counters; tmbci covdata accounts for it from the journal.
COVER_BUILD=()
COVER_RUN=()
if [ -n "${TMB_COVER_DIR:-}" ]; then
  COVER_BUILD=(--build-arg TMB_COVER=1)
  COVER_RUN=(-e GOCOVERDIR=/tmp/tmb-cover)
fi
# shellcheck disable=SC2329 # invoked from cleanup (EXIT trap)
cover_collect() { # cover_collect <broker container> <other containers...>
  [ -n "${TMB_COVER_DIR:-}" ] || return 0
  local c _
  docker exec "$1" pkill -TERM -x tmb-broker 2>/dev/null
  for _ in $(seq 1 50); do
    docker exec "$1" sh -c 'pgrep -x tmb-broker >/dev/null' 2>/dev/null || break
    sleep 0.1
  done
  for c in "$@"; do
    mkdir -p "$TMB_COVER_DIR/$c"
    docker cp "$c:/tmp/tmb-cover/." "$TMB_COVER_DIR/$c/covdata" >/dev/null 2>&1 || echo "cover: no coverage data in $c"
  done
  docker cp "$1:/var/log/tmb/." "$TMB_COVER_DIR/$1/journal" >/dev/null 2>&1 || echo "cover: no journal in $1"
}

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  echo "=== cleanup ==="
  exec 9>&- 2>/dev/null
  cover_collect "$HOST" "$SBX"
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
    -e TMB_CERT="/certs/$cl.crt" \
    -e TMB_KEY="/certs/$cl.key" \
    "$SBX" "$@" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
}

# run_tls_client_addr ADDR CLIENT TMB-ARGS... : same, but dials an arbitrary
# TMB_ADDR (O8 points the client at the foreign-CA endpoint).
run_tls_client_addr() {
  local addr=$1 cl=$2; shift 2
  docker exec \
    -e TMB_ADDR="$addr" \
    -e TMB_CA=/certs/ca.crt \
    -e TMB_CERT="/certs/$cl.crt" \
    -e TMB_KEY="/certs/$cl.key" \
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
  local _ pat=$1 want=$2
  for _ in $(seq 1 150); do
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
  local _
  for _ in $(seq 1 150); do
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
command -v go >/dev/null || { echo "FATAL: go is required on the harness host (it builds tmb-broker for the CA)"; exit 1; }
echo "workdir: $(pwd), cert dir: $TD (temp, never committed)"

# -----------------------------------------------------------------------------
log "STAGE 1: generate harness CA + server + client certs into $TD"

# Certificates come from the broker's own CA mode (tmb-broker ca), built for
# the harness host and run there: ca.key never enters an image or container.
# Client keys are generated on the "sandbox" side and only the public key
# is signed, as in production enrollment.
(cd ../src && CGO_ENABLED=0 go build -trimpath -o "$TD/tmb-broker-ca" ./cmd/tmb-broker) \
  || { echo "FATAL: building tmb-broker for the CA failed"; exit 1; }
CA_BIN=$TD/tmb-broker-ca
"$CA_BIN" ca init --dir "$TD" >/dev/null || { echo "FATAL: CA generation failed"; exit 1; }
"$CA_BIN" ca issue-server --dir "$TD" --dns "$SERVER_NAME" >/dev/null \
  || { echo "FATAL: server certificate failed"; exit 1; }

# client4 has its own key but the same Subject as client1 (N23)
for n in 1 2 3 4; do
  name="tmb-pair-client$n"; [ "$n" = 4 ] && name=tmb-pair-client1
  if ! { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TD/client$n.key" 2>/dev/null \
      && openssl pkey -in "$TD/client$n.key" -pubout -out "$TD/client$n.pub" 2>/dev/null \
      && "$CA_BIN" ca issue-sandbox --dir "$TD" --in "$TD/client$n.pub" --name "$name" \
        --out "$TD/client$n.crt" >"$TD/client$n.fp.out"; }; then
    echo "FATAL: client$n certificate failed"; exit 1
  fi
done
# N23: a second certificate on client1's key, issued after the first; N30:
# one on the same key whose 7-day validity ended long ago
cp "$TD/client1.key" "$TD/client1b.key"
cp "$TD/client1.key" "$TD/client1x.key"
"$CA_BIN" ca issue-sandbox --dir "$TD" --in "$TD/client1.pub" --name tmb-pair-client1 \
  --out "$TD/client1b.crt" >"$TD/client1b.fp.out" || { echo "FATAL: client1b certificate failed"; exit 1; }
"$CA_BIN" ca issue-sandbox --dir "$TD" --in "$TD/client1.pub" --name tmb-pair-client1 \
  --not-before "$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --out "$TD/client1x.crt" >/dev/null || { echo "FATAL: expired client1x certificate failed"; exit 1; }

# the key fingerprint (SHA-256 of the public key, hex) as the CA printed it:
# the broker's identity form
fp_of() { sed -n 's/^fingerprint: //p' "$TD/$1.fp.out"; }
FP1=$(fp_of client1)
FP2=$(fp_of client2)
FP3=$(fp_of client3)
FP4=$(fp_of client4)
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
  "approver_uids": [1500],
  "approver_socket_path": "/run/tmb-approver/approve.sock",
  "allowed_requester_keys": ["$FP1", "$FP3"],
  "socket_gid": 4242,
  "allowed_cwd_roots": ["/tmp"],
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
  "approval_default": "queue",
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
  "$TD"/client*.crt "$TD"/client*.key "$TD/config-pair.json"
chmod 600 "$TD/ca.key"

# -----------------------------------------------------------------------------
log "STAGE 2: O0-pair prerequisites (dependency surface + cert hygiene)"

echo "-- O0: go list -m all in src/ (in the pinned builder image)"
GOLIST=$(docker run --rm -e GOCACHE=/tmp/gocache \
  -v "$(cd .. && pwd)/src":/src:ro -w /src golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c go list -m all 2>/dev/null)
# shellcheck disable=SC2001 # prefixes every line of a multi-line value
echo "$GOLIST" | sed 's/^/  | /'
if [ "$(echo "$GOLIST" | tr -d '[:space:]')" = "tmb-poc" ]; then
  ok "O0-pair: go list -m all -> only tmb-poc (stdlib only)"
else
  bad "O0-pair: go list -m all -> '$GOLIST' (want only tmb-poc)"
fi

echo "-- O0: build images (context: repo root)"
docker build -q ${COVER_BUILD[@]+"${COVER_BUILD[@]}"} -f images/Dockerfile.host -t "$IMG_HOST" .. || { echo "FATAL: host image build failed"; exit 1; }
docker build -q ${COVER_BUILD[@]+"${COVER_BUILD[@]}"} -f images/Dockerfile.sandbox -t "$IMG_SBX" .. || { echo "FATAL: sandbox image build failed"; exit 1; }

docker network rm "$NET" >/dev/null 2>&1
docker network create "$NET" >/dev/null || { echo "FATAL: network create failed"; exit 1; }

echo "-- starting host-sim (broker host; TLS port published, network alias $SERVER_NAME)"
docker run -d --name "$HOST" ${COVER_RUN[@]+"${COVER_RUN[@]}"} \
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
docker run -d --name "$SBX" ${COVER_RUN[@]+"${COVER_RUN[@]}"} \
  --network "$NET" \
  -v "$SOCK_VOL":/run/tmb \
  -v "$TD/ca.crt":/certs/ca.crt:ro \
  -v "$TD/client1.crt":/certs/client1.crt:ro -v "$TD/client1.key":/certs/client1.key:ro \
  -v "$TD/client2.crt":/certs/client2.crt:ro -v "$TD/client2.key":/certs/client2.key:ro \
  -v "$TD/client3.crt":/certs/client3.crt:ro -v "$TD/client3.key":/certs/client3.key:ro \
  -v "$TD/client4.crt":/certs/client4.crt:ro -v "$TD/client4.key":/certs/client4.key:ro \
  -v "$TD/client1b.crt":/certs/client1b.crt:ro -v "$TD/client1b.key":/certs/client1b.key:ro \
  -v "$TD/client1x.crt":/certs/client1x.crt:ro -v "$TD/client1x.key":/certs/client1x.key:ro \
  "$IMG_SBX" >/dev/null || { echo "FATAL: sandbox-sim run failed"; exit 1; }
sleep 0.5

echo "-- O0: ca.crt mounted, ca.key NOT in any container"
if docker exec "$HOST" test -f /etc/tmb/certs/ca.crt; then
  ok "O0-pair: ca.crt present in host-sim"
else
  bad "O0-pair: ca.crt missing in host-sim"
fi
if docker exec "$HOST" test ! -e /etc/tmb/certs/ca.key; then
  ok "O0-pair: ca.key NOT in host-sim"
else
  bad "O0-pair: ca.key LEAKED into host-sim"
fi
if docker exec "$SBX" test -f /certs/ca.crt; then
  ok "O0-pair: ca.crt present in sandbox-sim"
else
  bad "O0-pair: ca.crt missing in sandbox-sim"
fi
if docker exec "$SBX" test ! -e /certs/ca.key; then
  ok "O0-pair: ca.key NOT in sandbox-sim"
else
  bad "O0-pair: ca.key LEAKED into sandbox-sim"
fi
if docker exec "$SBX" test ! -e /certs/server.key; then
  ok "O0-pair: server.key NOT in sandbox-sim"
else
  bad "O0-pair: server.key LEAKED into sandbox-sim"
fi

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
log "SCENARIO PAIR-MANUAL: manual console shows 'requester : key fp=<16 hex>', y then n"
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
  local n
  for _ in $(seq 1 150); do
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
if grep -qF "requester : key fp=$FP1_16" "$MANLOG"; then
  ok "PAIR-MANUAL: console line 'requester : key fp=$FP1_16'"
else
  bad "PAIR-MANUAL: console lacks 'requester : key fp=$FP1_16'"
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
if docker exec "$HOST" grep -q 'key fp=' /tmp/o7-console.log 2>/dev/null; then
  bad "O7-A: console showed a requester line"
else
  ok "O7-A: console shows no 'requester : key fp=' line"
fi
echo "-- manual broker console so far --"
docker exec "$HOST" cat /tmp/o7-console.log 2>/dev/null | sed 's/^/  | /'

# -----------------------------------------------------------------------------
log "SCENARIO O7-B: openssl s_client WITHOUT a client cert -> TLS alert, handshake failed"

HSF_BEFORE=$(broker_log_count '"event":"tls_handshake_failed"'); HSF_BEFORE=${HSF_BEFORE:-0}
# In TLS 1.3 the client finishes its side of the handshake before the server
# checks the (missing) client cert, so the certificate_required alert arrives
# only after s_client reports CONNECTED. Without -ign_eof, EOF on stdin races
# that alert: s_client may close first and exit 0 with no alert in its output
# (#87). -ign_eof keeps it reading until the server sends the alert and
# closes; timeout bounds a broker that never closes.
docker exec "$SBX" timeout 20 openssl s_client -ign_eof -connect "$SERVER_NAME:$TLS_PORT" -CAfile /certs/ca.crt </dev/null \
  >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
cat "$OUT_FILE" "$ERR_FILE" >"$TD/sclient-o7b.all"
if [ "$RUNC" -eq 124 ]; then
  bad "O7-B: s_client timed out (rc=124): the server never sent an alert or closed"
elif [ "$RUNC" -ne 0 ]; then
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

# The broker writes the event after its side of the handshake fails, which
# can land just after s_client exits: poll briefly instead of reading once.
for _ in $(seq 1 50); do
  HSF_AFTER=$(broker_log_count '"event":"tls_handshake_failed"')
  [ "${HSF_AFTER:-0}" -gt "$HSF_BEFORE" ] && break
  sleep 0.1
done
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
"$CA_BIN" ca init --dir "$TD/foreign" >/dev/null \
  || { echo "FATAL: foreign CA generation failed"; exit 1; }
"$CA_BIN" ca issue-server --dir "$TD/foreign" --dns fake.openshell.internal >/dev/null \
  || { echo "FATAL: foreign server certificate failed"; exit 1; }
cp "$TD/foreign/server.crt" "$TD/foreign-server.crt"
cp "$TD/foreign/server.key" "$TD/foreign-server.key"
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
for _ in $(seq 1 100); do
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
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"nonce":"o9-nonce-fixed-000007"}
EOF

echo "-- approve under fp1 (allowlisted)"
docker exec -i \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
  -e TMB_CERT=/certs/client1.crt -e TMB_KEY=/certs/client1.key \
  "$SBX" tmb debug approve --json - <"$TD/o9.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc "O9: approve under fp1 -> exit 0" 0
T9=$(pair_token_of)
echo "-- token from fp1 approve: ${T9:-<none>}"
if [ -n "$T9" ]; then ok "O9: got one-shot token $T9"; else bad "O9: no token parsed from approve"; fi

echo "-- claim under fp3 (allowlisted, but NOT the approver)"
docker exec -i \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
  -e TMB_CERT=/certs/client3.crt -e TMB_KEY=/certs/client3.key \
  "$SBX" tmb debug claim --token "$T9" --json - <"$TD/o9.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
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
  "$SBX" tmb debug claim --token "$T9" --json - <"$TD/o9.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc     "O9: token NOT consumed; claim under fp1 -> exit 0" 0
assert_out_eq "O9: stdout is exactly '0'" "0"
stop_broker
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO PAIR-APPROVE: list/decide over the TLS listener -> unknown_request_type, queue untouched"
# The approver protocol exists only on the host's approver socket. A sandbox
# client with an allowlisted certificate tries it over TLS while a request
# of its own waits in the queue.
APPROVE_SOCK=/run/tmb-approver/approve.sock
TLN=$(broker_log_count '"event":"tls_listen"'); TLN=${TLN:-0}
start_broker queue 30
wait_broker_log_count '"event":"tls_listen"' $((TLN+1))
docker exec \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
  -e TMB_CERT=/certs/client1.crt -e TMB_KEY=/certs/client1.key \
  "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/pa.out" 2>"$TD/pa.err" &
CLIPA=$!
QUEUED=0
for _ in $(seq 1 150); do
  docker exec -u human -e TMB_APPROVE_SOCK="$APPROVE_SOCK" "$HOST" tmb approve --list >"$TD/pa-queue.out" 2>&1
  grep -q '^=== ' "$TD/pa-queue.out" && { QUEUED=1; break; }
  sleep 0.1
done
if [ "$QUEUED" = 1 ]; then ok "PAIR-APPROVE: TLS request waits in the queue"; else bad "PAIR-APPROVE: TLS request never queued"; fi
PAID=$(sed -n 's/^=== \([0-9a-f]\{16\}\) ===$/\1/p' "$TD/pa-queue.out" | head -1)
PAHASH=$(sed -n 's/^  hash      : //p' "$TD/pa-queue.out" | head -1)
APPROVALS_BEFORE=$(broker_log_count '"event":"approval"')
run_tls_client client1 sh -c "printf '%s' '{\"type\":\"list\"}' | tmb debug raw --json -"
assert_rc      "PAIR-APPROVE: list over TLS -> exit 125" 125
assert_err_has "PAIR-APPROVE: list deny reason unknown_request_type" "unknown_request_type"
run_tls_client client1 sh -c "printf '%s' '{\"type\":\"decide\",\"item_id\":\"$PAID\",\"item_hash\":\"$PAHASH\",\"decision\":\"approve\"}' | tmb debug raw --json -"
assert_rc      "PAIR-APPROVE: decide over TLS -> exit 125" 125
assert_err_has "PAIR-APPROVE: decide deny reason unknown_request_type" "unknown_request_type"
docker exec -u human -e TMB_APPROVE_SOCK="$APPROVE_SOCK" "$HOST" tmb approve --list >"$TD/pa-queue2.out" 2>&1
if grep -q "^=== $PAID ===" "$TD/pa-queue2.out"; then ok "PAIR-APPROVE: the item is still waiting (queue unchanged)"; else bad "PAIR-APPROVE: the queue changed"; fi
APPROVALS_AFTER=$(broker_log_count '"event":"approval"')
if [ "$APPROVALS_BEFORE" = "$APPROVALS_AFTER" ]; then ok "PAIR-APPROVE: no approval event from the TLS attempts"; else bad "PAIR-APPROVE: approval events $APPROVALS_BEFORE -> $APPROVALS_AFTER"; fi
docker exec -u human -e TMB_APPROVE_SOCK="$APPROVE_SOCK" "$HOST" tmb approve --no "$PAID" >/dev/null 2>&1
wait $CLIPA; RUNC=$?
OUT_FILE=$TD/pa.out; ERR_FILE=$TD/pa.err; show_io
assert_rc "PAIR-APPROVE: the waiting request is denied by the host approver -> exit 125" 125
stop_broker
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N23: identity is the key: a reissued certificate keeps the fingerprint"
# client1b is a second certificate on client1's key, issued after the first;
# client4 has the same Subject as client1 but its own key. The allowlist
# lists keys and is not touched.
CFG_SUM=$(shasum -a 256 "$TD/config-pair.json" | cut -d' ' -f1)
if [ "$(fp_of client1b)" = "$FP1" ]; then ok "N23: ca issue-sandbox printed the same fingerprint for the reissued certificate"; else bad "N23: reissue changed the fingerprint"; fi
TLN=$(broker_log_count '"event":"tls_listen"'); TLN=${TLN:-0}
start_broker queue 30
wait_broker_log_count '"event":"tls_listen"' $((TLN+1))
QUEUED_FP1_BEFORE=$(docker exec "$HOST" grep '"event":"queued"' /var/log/tmb/broker.log | grep -c "\"requester_fp\":\"$FP1\"")
for cl in client1 client1b; do
  docker exec \
    -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
    -e TMB_CERT="/certs/$cl.crt" -e TMB_KEY="/certs/$cl.key" \
    "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n23-$cl.out" 2>"$TD/n23-$cl.err" &
  CLI23=$!
  QUEUED=0
  for _ in $(seq 1 150); do
    docker exec -u human -e TMB_APPROVE_SOCK="$APPROVE_SOCK" "$HOST" tmb approve --list >"$TD/n23-q.out" 2>&1
    grep -q '^=== ' "$TD/n23-q.out" && { QUEUED=1; break; }
    sleep 0.1
  done
  [ "$QUEUED" = 1 ] || bad "N23: $cl request never queued"
  if grep -qF "requester : key fp=$FP1_16" "$TD/n23-q.out"; then ok "N23: approval display shows key fp=$FP1_16 for $cl"; else bad "N23: approval display for $cl lacks key fp=$FP1_16"; fi
  ID23=$(sed -n 's/^=== \([0-9a-f]\{16\}\) ===$/\1/p' "$TD/n23-q.out" | head -1)
  docker exec -u human -e TMB_APPROVE_SOCK="$APPROVE_SOCK" "$HOST" tmb approve --yes "$ID23" >/dev/null 2>&1
  wait $CLI23; RUNC=$?
  OUT_FILE=$TD/n23-$cl.out; ERR_FILE=$TD/n23-$cl.err; show_io
  assert_rc "N23: request with $cl -> exit 0" 0
done
QUEUED_FP1_AFTER=$(docker exec "$HOST" grep '"event":"queued"' /var/log/tmb/broker.log | grep -c "\"requester_fp\":\"$FP1\"")
if [ $((QUEUED_FP1_AFTER - QUEUED_FP1_BEFORE)) = 2 ]; then ok "N23: both certificates logged as requester_fp=fp1"; else bad "N23: JSONL requester_fp differs between the certificates ($QUEUED_FP1_BEFORE -> $QUEUED_FP1_AFTER)"; fi
run_tls_client client4 tmb exec --root -- /usr/bin/id -u
assert_rc      "N23: other key, same Subject -> exit 125" 125
assert_err_has "N23: deny reason requester_not_allowed" "requester_not_allowed"
if docker exec "$HOST" grep '"event":"requester_denied"' /var/log/tmb/broker.log | grep -q "\"requester_fp\":\"$FP4\""; then ok "N23: requester_denied carries the other key's fingerprint"; else bad "N23: requester_denied for the other key missing"; fi
if [ "$(shasum -a 256 "$TD/config-pair.json" | cut -d' ' -f1)" = "$CFG_SUM" ]; then ok "N23: allowlist (config) unchanged"; else bad "N23: config changed"; fi
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N30: an expired sandbox certificate fails the handshake, no deny, no request"
HSF_BEFORE=$(broker_log_count '"event":"tls_handshake_failed"')
REQ_BEFORE=$(broker_log_count '"event":"request"')
DENY_BEFORE=$(broker_log_count '"event":"deny"')
run_tls_client client1x tmb exec --root -- /usr/bin/id -u
assert_rc "N30: expired certificate -> client exit 3 (fail closed)" 3
sleep 0.5
HSF_AFTER=$(broker_log_count '"event":"tls_handshake_failed"')
if [ "$HSF_AFTER" -gt "$HSF_BEFORE" ]; then ok "N30: tls_handshake_failed logged"; docker exec "$HOST" grep '"event":"tls_handshake_failed"' /var/log/tmb/broker.log | tail -1 | sed 's/^/  | /'; else bad "N30: no tls_handshake_failed event"; fi
if [ "$(broker_log_count '"event":"request"')" = "$REQ_BEFORE" ] && [ "$(broker_log_count '"event":"deny"')" = "$DENY_BEFORE" ]; then ok "N30: no request and no deny event"; else bad "N30: request or deny event logged for an expired certificate"; fi
stop_broker
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO PAIR-KEY: the key is born in the sandbox (tmb keygen); only the public key leaves"
docker exec "$SBX" tmb keygen --out /home/tmb/sbx.key >"$TD/pk.out" 2>"$TD/pk.err"; RUNC=$?
assert_rc "PAIR-KEY: tmb keygen in sandbox-sim -> exit 0" 0
if [ "$(docker exec "$SBX" stat -c %a /home/tmb/sbx.key)" = 600 ]; then ok "PAIR-KEY: private key file is 0600"; else bad "PAIR-KEY: private key file mode is not 0600"; fi
if grep -q "PRIVATE KEY" "$TD/pk.out"; then bad "PAIR-KEY: keygen printed private key material"; else ok "PAIR-KEY: keygen printed only the public key"; fi
sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$TD/pk.out" >"$TD/pk.pub"
FPK=$(sed -n 's/^fingerprint: //p' "$TD/pk.out")
"$CA_BIN" ca issue-sandbox --dir "$TD" --in "$TD/pk.pub" --name pair-key --out "$TD/pk.crt" >"$TD/pk.fp.out"
if [ -n "$FPK" ] && [ "$(sed -n 's/^fingerprint: //p' "$TD/pk.fp.out")" = "$FPK" ]; then ok "PAIR-KEY: host CA prints the fingerprint keygen printed"; else bad "PAIR-KEY: fingerprints of keygen and the CA differ"; fi
chmod 644 "$TD/pk.crt"
docker cp "$TD/pk.crt" "$SBX":/home/tmb/pk.crt >/dev/null
if [ "$(docker exec "$SBX" tmb fingerprint /home/tmb/pk.crt)" = "$FPK" ]; then ok "PAIR-KEY: tmb fingerprint of the certificate matches"; else bad "PAIR-KEY: tmb fingerprint of the certificate differs"; fi
sed "s/\"allowed_requester_keys\": \[/\"allowed_requester_keys\": [\"$FPK\", /" "$TD/config-pair.json" >"$TD/config-pair.next"
cat "$TD/config-pair.next" >"$TD/config-pair.json"
TLN=$(broker_log_count '"event":"tls_listen"'); TLN=${TLN:-0}
start_broker mock-approve 30
wait_broker_log_count '"event":"tls_listen"' $((TLN+1))
OUT_FILE=$TD/pk-exec.out; ERR_FILE=$TD/pk-exec.err
docker exec \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
  -e TMB_CERT=/home/tmb/pk.crt -e TMB_KEY=/home/tmb/sbx.key \
  "$SBX" tmb exec --root -- /usr/bin/id -u >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc     "PAIR-KEY: request with the sandbox-born key -> exit 0" 0
assert_out_eq "PAIR-KEY: stdout '0'" "0"
# text files only (-I): the Go binaries carry the PEM type string itself
docker exec "$HOST" sh -c 'grep -rlI -e "-----BEGIN [A-Z ]*PRIVATE KEY-----" / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null' >"$TD/pk-host.out"
sed 's/^/  | /' "$TD/pk-host.out"
# the broker's own keys: its TLS key and its identity key (ADR 0007, R6)
if [ "$(grep -cvE '^(/etc/tmb/certs/server\.key|/var/lib/tmb-proto/identity\.key)$' "$TD/pk-host.out")" = 0 ]; then ok "PAIR-KEY: host-sim holds no private key but the broker's own"; else bad "PAIR-KEY: host-sim holds other private key files"; fi
stop_broker
state_dump

# -----------------------------------------------------------------------------
# Reload (N25-N27): the broker runs from a config and TLS files that live
# inside host-sim (/etc/tmb/reload, written with docker exec), so the
# scenarios can change them and send SIGHUP; nothing new is mounted.
RL=/etc/tmb/reload
put_host() { # put_host LOCAL-FILE PATH-IN-HOST-SIM
  docker exec -i "$HOST" sh -c "cat >'$2'" <"$1"
}
hup_broker() {
  echo "-- SIGHUP to tmb-broker"
  docker exec "$HOST" pkill -HUP -x tmb-broker
}
broker_pid() { docker exec "$HOST" pgrep -x tmb-broker | tr -d '[:space:]'; }
sock_inodes() { docker exec "$HOST" stat -c %i /run/tmb/tmb.sock /run/tmb-approver/approve.sock | tr '\n' ' '; }
# serial_of FILE: the certificate serial as the client prints it (hex,
# upper case, no leading zeros)
serial_of() { openssl x509 -in "$1" -noout -serial | sed 's/^serial=//; s/^0*//'; }
# client_serial: the serial a TMB_DEBUG client printed in $ERR_FILE
client_serial() { sed -n 's/^tmb: debug: broker certificate serial=\([0-9A-F]*\) .*/\1/p' "$ERR_FILE" | head -1; }
start_broker_reload() { # MODE TTL
  echo "-- starting tmb-broker (mode=$1 ttl=$2s, config=$RL/config.json, console=$RL/console.log)"
  docker exec -d "$HOST" sh -c \
    "exec tmb-broker -approval '$1' -ttl '$2' -config $RL/config.json >$RL/console.log 2>&1"
}

docker exec "$HOST" mkdir -p "$RL"
for f in ca.crt server.crt server.key; do put_host "$TD/$f" "$RL/$f"; done
sed "s#/etc/tmb/certs/#$RL/#" "$TD/config-pair.json" >"$TD/rl-base.json"
sed "s/\"$FP1\", //" "$TD/rl-base.json" >"$TD/rl-nofp1.json"
printf '{"socket_path": "/run/tmb/tmb.sock",\n' >"$TD/rl-broken.json"
sed "s/\"tls_addr\": \":$TLS_PORT\"/\"tls_addr\": \":$((TLS_PORT+1))\"/" "$TD/rl-base.json" >"$TD/rl-newaddr.json"
grep -q "\"$FP1\"" "$TD/rl-base.json" || { echo "FATAL: reload base config lacks fp1"; exit 1; }
if grep -q "\"$FP1\"" "$TD/rl-nofp1.json"; then echo "FATAL: fp1 not removed from the reload config"; exit 1; fi
grep -q "\"tls_addr\": \":$((TLS_PORT+1))\"" "$TD/rl-newaddr.json" || { echo "FATAL: tls_addr not changed"; exit 1; }
put_host "$TD/rl-base.json" "$RL/config.json"

# -----------------------------------------------------------------------------
log "SCENARIO N25: SIGHUP reloads the key allowlist; sockets and pid stay"
TLN=$(broker_log_count '"event":"tls_listen"'); TLN=${TLN:-0}
start_broker_reload mock-approve 30
wait_broker_log_count '"event":"tls_listen"' $((TLN+1))
PID25=$(broker_pid)
INO25=$(sock_inodes)
echo "-- broker pid $PID25, socket inodes $INO25"
run_tls_client client1 tmb exec --root -- /usr/bin/id -u
assert_rc "N25: fp1 allowlisted -> exit 0" 0

put_host "$TD/rl-nofp1.json" "$RL/config.json"
RLN=$(broker_log_count '"event":"reload"'); RLN=${RLN:-0}
hup_broker
wait_broker_log_count '"event":"reload"' $((RLN+1))
ok "N25: SIGHUP -> reload event"
if docker exec "$HOST" grep '"event":"reload"' /var/log/tmb/broker.log | tail -1 | grep -q '"changed":\["allowed_requester_keys"\]'; then ok "N25: reload names allowed_requester_keys as changed"; else bad "N25: reload event does not name allowed_requester_keys"; fi
docker exec "$HOST" grep '"event":"reload"' /var/log/tmb/broker.log | tail -1 | sed 's/^/  | /'
run_tls_client client1 tmb exec --root -- /usr/bin/id -u
assert_rc      "N25: fp1 removed, next request -> exit 125" 125
assert_err_has "N25: deny reason requester_not_allowed" "requester_not_allowed"

put_host "$TD/rl-base.json" "$RL/config.json"
hup_broker
wait_broker_log_count '"event":"reload"' $((RLN+2))
run_tls_client client1 tmb exec --root -- /usr/bin/id -u
assert_rc     "N25: fp1 back, SIGHUP -> exit 0" 0
assert_out_eq "N25: stdout '0'" "0"
if [ "$(broker_pid)" = "$PID25" ]; then ok "N25: broker pid unchanged ($PID25)"; else bad "N25: broker pid changed ($PID25 -> $(broker_pid))"; fi
if [ "$(sock_inodes)" = "$INO25" ]; then ok "N25: socket inodes unchanged ($INO25)"; else bad "N25: socket inodes changed ($INO25 -> $(sock_inodes))"; fi
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N26: an invalid config keeps the running one; tls_addr is not reloaded"
put_host "$TD/rl-broken.json" "$RL/config.json"
RFN=$(broker_log_count '"event":"reload_failed"'); RFN=${RFN:-0}
RLN=$(broker_log_count '"event":"reload"'); RLN=${RLN:-0}
hup_broker
wait_broker_log_count '"event":"reload_failed"' $((RFN+1))
ok "N26: syntax error, SIGHUP -> reload_failed"
docker exec "$HOST" grep '"event":"reload_failed"' /var/log/tmb/broker.log | tail -1 | sed 's/^/  | /'
if docker exec "$HOST" grep -q "reload failed, keeping the running config" "$RL/console.log"; then ok "N26: stderr names the reload failure"; else bad "N26: stderr lacks the reload failure"; fi
if [ "$(broker_log_count '"event":"reload"')" = "$RLN" ]; then ok "N26: no reload event for the broken config"; else bad "N26: broken config logged a reload"; fi
run_tls_client client1 tmb exec --root -- /usr/bin/id -u
assert_rc "N26: requests still pass on the old allowlist (fp1) -> exit 0" 0
run_tls_client client2 tmb exec --root -- /usr/bin/id -u
assert_rc "N26: fp2 still not allowed -> exit 125" 125

put_host "$TD/rl-newaddr.json" "$RL/config.json"
RIN=$(broker_log_count '"event":"reload_ignored_field"'); RIN=${RIN:-0}
hup_broker
wait_broker_log_count '"event":"reload"' $((RLN+1))
if [ "$(broker_log_count '"event":"reload_ignored_field"')" = $((RIN+1)) ] \
  && docker exec "$HOST" grep '"event":"reload_ignored_field"' /var/log/tmb/broker.log | tail -1 | grep -q '"field":"tls_addr"'; then
  ok "N26: tls_addr changed -> one reload_ignored_field for tls_addr"
else
  bad "N26: reload_ignored_field for tls_addr missing"
fi
docker exec "$HOST" grep '"event":"reload_ignored_field"' /var/log/tmb/broker.log | tail -1 | sed 's/^/  | /'
run_tls_client client1 tmb exec --root -- /usr/bin/id -u
assert_rc "N26: the old port $TLS_PORT still serves -> exit 0" 0
run_tls_client_addr "$SERVER_NAME:$((TLS_PORT+1))" client1 tmb exec --root -- /usr/bin/id -u
assert_rc "N26: nothing listens on the new port $((TLS_PORT+1)) -> exit 3" 3
put_host "$TD/rl-base.json" "$RL/config.json"
hup_broker
wait_broker_log_count '"event":"reload"' $((RLN+2))
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N27: a reissued server certificate is served after SIGHUP; an open connection keeps the old one"
SERIAL_A=$(serial_of "$TD/server.crt")
mkdir -p "$TD/reissue"
"$CA_BIN" ca issue-server --dir "$TD" --dns "$SERVER_NAME" --out "$TD/reissue" >/dev/null \
  || { echo "FATAL: reissuing the server certificate failed"; exit 1; }
SERIAL_B=$(serial_of "$TD/reissue/server.crt")
echo "-- serial before $SERIAL_A, reissued $SERIAL_B"
{ [ -n "$SERIAL_A" ] && [ "$SERIAL_A" != "$SERIAL_B" ]; } || { echo "FATAL: reissued certificate has the same serial"; exit 1; }
run_tls_client client1 env TMB_DEBUG=1 tmb exec --root -- /usr/bin/id -u
assert_rc "N27: before reload -> exit 0" 0
if [ "$(client_serial)" = "$SERIAL_A" ]; then ok "N27: client sees serial $SERIAL_A before reload"; else bad "N27: client saw serial '$(client_serial)', want $SERIAL_A"; fi

echo "-- open a connection before the reload: an approved /usr/bin/sleep 4 holds it"
ES=$(broker_log_count '"event":"exec_start"'); ES=${ES:-0}
docker exec \
  -e TMB_ADDR="$SERVER_NAME:$TLS_PORT" -e TMB_CA=/certs/ca.crt \
  -e TMB_CERT=/certs/client1.crt -e TMB_KEY=/certs/client1.key -e TMB_DEBUG=1 \
  "$SBX" tmb exec --root -- /usr/bin/sleep 4 >"$TD/n27-old.out" 2>"$TD/n27-old.err" &
CLI27=$!
wait_broker_log_count '"event":"exec_start"' $((ES+1))
put_host "$TD/reissue/server.crt" "$RL/server.crt"
put_host "$TD/reissue/server.key" "$RL/server.key"
RLN=$(broker_log_count '"event":"reload"'); RLN=${RLN:-0}
hup_broker
wait_broker_log_count '"event":"reload"' $((RLN+1))
if docker exec "$HOST" grep '"event":"reload"' /var/log/tmb/broker.log | tail -1 | grep -q '"tls_material"'; then ok "N27: reload names tls_material as changed"; else bad "N27: reload event lacks tls_material"; fi
run_tls_client client1 env TMB_DEBUG=1 tmb exec --root -- /usr/bin/id -u
assert_rc "N27: new connection after reload -> exit 0" 0
if [ "$(client_serial)" = "$SERIAL_B" ]; then ok "N27: new connection sees the reissued serial $SERIAL_B"; else bad "N27: new connection saw serial '$(client_serial)', want $SERIAL_B"; fi
wait $CLI27; RUNC=$?
OUT_FILE=$TD/n27-old.out; ERR_FILE=$TD/n27-old.err; show_io
assert_rc "N27: the connection opened before reload finished its command -> exit 0" 0
if [ "$(client_serial)" = "$SERIAL_A" ]; then ok "N27: that connection ran on the old serial $SERIAL_A"; else bad "N27: pre-reload connection saw serial '$(client_serial)', want $SERIAL_A"; fi
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
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
if [ "${N_PASS:-x}" = "195" ] && [ "${N_FAIL:-x}" = "0" ]; then
  ok "REGRESSION: N-series 195/195 green (77 of the OpenShell milestone + N13-N17 approval queue + N18 cwd roots + N19/N20 env policy + N22 held cwd fd + N21 claim GC + N24 removed config field and flags + N28 queue and pending approval across SIGHUP + N29 journal reopen and audit_unavailable)"
else
  bad "REGRESSION: N-series PASS=${N_PASS:-?} FAIL=${N_FAIL:-?} (want 195/0)"
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
