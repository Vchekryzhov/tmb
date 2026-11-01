#!/usr/bin/env bash
# PROTOTYPE runner - throwaway PoC, not production.
#
# Idempotent: wipes containers + named volumes, rebuilds images, runs the full
# scenario matrix (Happy, manual y/n demo, N1..N9 negatives + extras), dumps
# FULL broker state after each scenario, prints a summary table, exits
# non-zero on any unexpected result, and cleans up on exit.
#
# Everything is logged to last-run.log (tee'd).
#
# Named volumes (wipe-me suffix = intentionally disposable):
#   tmb-poc-sock-wipe-me   -> /run/tmb        in BOTH containers (shared socket)
#   tmb-poc-state-wipe-me  -> /var/lib/tmb-proto in host-sim only (claim store)
# No host bind mounts, no docker.sock, no --privileged, sandbox has --network none.

set -u
cd "$(dirname "$0")" || exit 1

HOST=tmb-host-sim
SBX=tmb-sandbox
IMG_HOST=tmb-poc/host-sim
IMG_SBX=tmb-poc/sandbox-sim
SOCK_VOL=tmb-poc-sock-wipe-me
STATE_VOL=tmb-poc-state-wipe-me
TTL=3            # seconds; production would be 60 - kept short so the run is fast
TD=$(mktemp -d /tmp/tmb-run.XXXXXX)
LOG=last-run.log

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
  docker rm -f "$HOST" "$SBX" >/dev/null 2>&1
  docker volume rm -f "$SOCK_VOL" "$STATE_VOL" >/dev/null 2>&1
  rm -rf "$TD"
}
trap cleanup EXIT

log() { printf '\n================================================================\n== %s\n================================================================\n' "$*"; }

ok()  { PASS=$((PASS+1)); ROWS+=("PASS | $1"); printf 'CHECK PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); ROWS+=("FAIL | $1"); printf 'CHECK FAIL: %s\n' "$1"; }

# --- result plumbing: helpers set RUNC / OUT_FILE / ERR_FILE -----------------
RUNC=-1
OUT_FILE=$TD/last.out
ERR_FILE=$TD/last.err

show_io() {
  echo "-- rc=$RUNC"
  echo "-- stderr --"; sed 's/^/  | /' "$ERR_FILE" 2>/dev/null
  echo "-- stdout --"; sed 's/^/  | /' "$OUT_FILE" 2>/dev/null
}

run_client() { # run_client <args...>  (client-side invocation, prints evidence)
  docker exec "$@" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
}
run_client_json() { # run_client_json <tmb-subcommand...> <json-file>
  local jsonf=${*: -1}
  local cmd=("${@:1:$#-1}")
  docker exec -i "$SBX" "${cmd[@]}" --json - <"$jsonf" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
}

assert_rc()        { if [ "$RUNC" = "$2" ]; then ok "$1 (rc=$RUNC)"; else bad "$1 (want rc=$2, got $RUNC)"; fi; }
assert_out_eq()    { if [ "$(cat "$OUT_FILE" 2>/dev/null)" = "$2" ]; then ok "$1 (stdout='$2')"; else bad "$1 (stdout='$(cat "$OUT_FILE" 2>/dev/null)' want='$2')"; fi; }
assert_out_has()   { if grep -qF -- "$2" "$OUT_FILE" 2>/dev/null; then ok "$1"; else bad "$1 (stdout lacks '$2')"; fi; }
assert_out_lacks() { if ! grep -qF -- "$2" "$OUT_FILE" 2>/dev/null; then ok "$1"; else bad "$1 (stdout unexpectedly contains '$2')"; fi; }
assert_err_has()   { if grep -qF -- "$2" "$ERR_FILE" 2>/dev/null; then ok "$1"; else bad "$1 (stderr lacks '$2')"; fi; }
host_absent()      { if docker exec "$HOST" test ! -e "$2" 2>/dev/null; then ok "$1 ($2 absent in host-sim)"; else bad "$1 ($2 EXISTS in host-sim)"; fi; }

token_of() { sed -n 's/.*"token":"\([0-9a-f]\{16\}\)".*/\1/p' "$ERR_FILE" | head -1; }

state_dump() {
  echo "---- STATE: broker.log (last 14 lines) ----"
  docker exec "$HOST" tail -n 14 /var/log/tmb/broker.log 2>/dev/null | sed 's/^/  | /'
  echo "---- STATE: claim store (count + newest files) ----"
  docker exec "$HOST" sh -c 'ls -l /var/lib/tmb-proto/claims 2>/dev/null | tail -n +2 | wc -l; ls -lt /var/lib/tmb-proto/claims 2>/dev/null | head -4' | sed 's/^/  | /'
}

# --- broker lifecycle --------------------------------------------------------

wait_socket() {
  local _
  for _ in $(seq 1 150); do
    docker exec "$HOST" test -S /run/tmb/tmb.sock 2>/dev/null && return 0
    sleep 0.1
  done
  echo "FATAL: broker socket never appeared"; exit 1
}

start_broker() { # $1 mode, $2 ttl-seconds
  echo "-- starting tmb-broker (mode=$1 ttl=$2s)"
  docker exec -d "$HOST" tmb-broker -approval "$1" -ttl "$2"
  wait_socket
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

# =============================================================================
log "TMB BROKER PROTOTYPE RUNNER ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
docker version --format 'docker {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})'
echo "workdir: $(pwd)"

# -----------------------------------------------------------------------------
log "STAGE 0: idempotent teardown + build images + start containers"
cleanup_containers_only() {
  docker rm -f "$HOST" "$SBX" >/dev/null 2>&1
  docker volume rm -f "$SOCK_VOL" "$STATE_VOL" >/dev/null 2>&1
}
cleanup_containers_only

echo "-- building $IMG_HOST (context: repo root, so Dockerfiles can COPY src/)"
docker build -q ${COVER_BUILD[@]+"${COVER_BUILD[@]}"} -f images/Dockerfile.host -t "$IMG_HOST" .. || { echo "FATAL: host image build failed"; exit 1; }
echo "-- building $IMG_SBX"
docker build -q ${COVER_BUILD[@]+"${COVER_BUILD[@]}"} -f images/Dockerfile.sandbox -t "$IMG_SBX" .. || { echo "FATAL: sandbox image build failed"; exit 1; }

echo "-- starting host-sim (root, broker host, normal human sudo present)"
docker run -d --name "$HOST" ${COVER_RUN[@]+"${COVER_RUN[@]}"} \
  -v "$SOCK_VOL":/run/tmb \
  -v "$STATE_VOL":/var/lib/tmb-proto \
  "$IMG_HOST" >/dev/null || { echo "FATAL: host-sim run failed"; exit 1; }
echo "-- starting sandbox-sim (uid 4242, --network none, no docker.sock, no host mounts)"
docker run -d --name "$SBX" ${COVER_RUN[@]+"${COVER_RUN[@]}"} \
  --network none \
  -v "$SOCK_VOL":/run/tmb \
  "$IMG_SBX" >/dev/null || { echo "FATAL: sandbox run failed"; exit 1; }

sleep 0.5
S_UID=$(docker exec "$SBX" id -u 2>/dev/null)
H_UID=$(docker exec "$HOST" id -u 2>/dev/null)
if [ "$S_UID" = "4242" ] && [ "$H_UID" = "0" ]; then ok "containers up (sandbox uid=$S_UID, host uid=$H_UID)"; else bad "container uids wrong (sandbox=$S_UID host=$H_UID)"; fi
NET=$(docker inspect -f '{{range $k, $_ := .NetworkSettings.Networks}}{{$k}} {{end}}' "$SBX" | tr -d ' ')
if [ "$NET" = "none" ]; then ok "sandbox-sim is on the 'none' network only"; else bad "sandbox-sim networks: '$NET' (want 'none')"; fi

# -----------------------------------------------------------------------------
log "SCENARIO HAPPY: mock-approve, tmb exec --root -- /usr/bin/id -u"
start_broker mock-approve "$TTL"
run_client "$SBX" tmb exec --root -- /usr/bin/id -u
assert_rc    "HAPPY: exit code 0" 0
assert_out_eq "HAPPY: stdout is exactly '0'" "0"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO FD-NOLEAK: child lists /proc/self/fd (socket must not leak, stdin=/dev/null)"
run_client "$SBX" tmb exec --root -- /bin/ls -l /proc/self/fd
assert_rc       "FD: ls -l /proc/self/fd ran" 0
assert_out_has  "FD: fd 0 points at /dev/null (child stdin)" "/dev/null"
assert_out_lacks "FD: no socket: fd leaked into child" "socket:"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO MANUAL: broker in manual mode, human answers on console (y then n)"
stop_broker
FIFO=$TD/broker-console.in
MANLOG=$TD/manual-console.log
mkfifo "$FIFO"
docker exec -i "$HOST" tmb-broker -approval manual -ttl "$TTL" <"$FIFO" >"$MANLOG" 2>&1 &
MAN_PID=$!
exec 9>"$FIFO"
wait_socket
echo "-- manual broker up (console captured to $MANLOG)"

wait_prompt() { # $1 = nth prompt
  local n
  for _ in $(seq 1 150); do
    n=$(grep -c 'Approve exactly this command' "$MANLOG" 2>/dev/null || true)
    if [ "${n:-0}" -ge "$1" ]; then return 0; fi
    sleep 0.1
  done
  echo "FATAL: manual prompt #$1 never appeared"; cat "$MANLOG"; exit 1
}

echo "-- round 1: client asks for /usr/bin/id -u, human types y"
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/man1.out" 2>"$TD/man1.err" &
CLI1=$!
wait_prompt 1
printf 'y\n' >&9
wait $CLI1; RUNC=$?
OUT_FILE=$TD/man1.out; ERR_FILE=$TD/man1.err; show_io
assert_rc     "MANUAL-y: human 'y' -> command runs, exit 0" 0
assert_out_eq "MANUAL-y: stdout is exactly '0'" "0"

echo "-- round 2: client asks for /usr/bin/id -G, human types n"
docker exec "$SBX" tmb exec --root -- /usr/bin/id -G >"$TD/man2.out" 2>"$TD/man2.err" &
CLI2=$!
wait_prompt 2
printf 'n\n' >&9
wait $CLI2; RUNC=$?
OUT_FILE=$TD/man2.out; ERR_FILE=$TD/man2.err; show_io
assert_rc     "MANUAL-n: human 'n' -> denied, exit 125" 125
assert_err_has "MANUAL-n: deny reason approval_denied_by_human" "approval_denied_by_human"

echo "---- manual approval console: EXACT request text shown to the human ----"
sed 's/^/  | /' "$MANLOG"
stop_broker
wait $MAN_PID 2>/dev/null
exec 9>&-
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N1: spent token presented with DIFFERENT argv -> deny"
start_broker mock-approve "$TTL"
cat >"$TD/n1-a.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"nonce":"n1-nonce-fixed-000001"}
EOF
cat >"$TD/n1-b.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-G"],"cwd":"/tmp","uid":0,"nonce":"n1-nonce-fixed-000001"}
EOF
run_client_json tmb debug approve "$TD/n1-a.json"
assert_rc "N1: approve phase ok" 0
T1=$(token_of)
echo "-- token from approve: ${T1:-<none>}"
if [ -n "$T1" ]; then ok "N1: got one-shot token $T1"; else bad "N1: no token parsed"; fi
run_client_json tmb debug claim --token "$T1" "$TD/n1-b.json"
assert_rc      "N1: claim with same token but different argv -> exit 125" 125
assert_err_has "N1: deny reason token_binding_mismatch" "token_binding_mismatch"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N2: token/nonce REPLAY (same token, same request, twice) -> deny 2nd"
cat >"$TD/n2.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"nonce":"n2-nonce-fixed-000002"}
EOF
run_client_json tmb debug approve "$TD/n2.json"
assert_rc "N2: approve phase ok" 0
T2=$(token_of)
run_client_json tmb debug claim --token "$T2" "$TD/n2.json"
assert_rc     "N2: first claim executes, exit 0" 0
assert_out_eq "N2: first claim stdout '0'" "0"
run_client_json tmb debug claim --token "$T2" "$TD/n2.json"
assert_rc      "N2: replay claim -> exit 125" 125
assert_err_has "N2: deny reason token_consumed_replay" "token_consumed_replay"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO TTL: token claimed AFTER expiry -> deny, nothing runs (ttl=${TTL}s, no 60s sleeps)"
docker exec "$HOST" rm -f /tmp/ttl-marker
cat >"$TD/ttl.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/touch","argv":["/usr/bin/touch","/tmp/ttl-marker"],"cwd":"/tmp","uid":0,"nonce":"ttl-nonce-fixed-0003"}
EOF
run_client_json tmb debug approve "$TD/ttl.json"
assert_rc "TTL: approve phase ok" 0
TT=$(token_of)
echo "-- sleeping $((TTL+2))s to let the token expire (ttl=$TTL s)"
sleep $((TTL+2))
run_client_json tmb debug claim --token "$TT" "$TD/ttl.json"
assert_rc      "TTL: expired claim -> exit 125" 125
assert_err_has "TTL: deny mentions no live approval" "no_pending_approval"
host_absent "TTL: marker file never created" /tmp/ttl-marker
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N5a: LD_PRELOAD set in CLIENT environment -> child env must lack it"
echo "-- proof the client-side env really carries LD_PRELOAD (same docker -e mechanism):"
docker exec -e LD_PRELOAD=/tmp/evil.so "$SBX" /usr/bin/printenv LD_PRELOAD >"$TD/lp.out" 2>&1
sed 's/^/  | /' "$TD/lp.out"
if grep -qF -- "/tmp/evil.so" "$TD/lp.out"; then ok "N5a: client-side env really had LD_PRELOAD=/tmp/evil.so"; else bad "N5a: could not set LD_PRELOAD client-side"; fi
run_client -e LD_PRELOAD=/tmp/evil.so "$SBX" tmb exec --root -- /usr/bin/printenv
assert_rc       "N5a: printenv child ran" 0
assert_out_has  "N5a: child env has fixed broker PATH" "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
assert_out_has  "N5a: child env has fixed LANG" "LANG=C.UTF-8"
assert_out_lacks "N5a: child env lacks smuggled LD_PRELOAD" "LD_PRELOAD"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N5b: explicit --env LD_PRELOAD smuggle -> rejected at the gate"
run_client "$SBX" tmb exec --root --env LD_PRELOAD=/tmp/evil.so -- /usr/bin/id -u
assert_rc      "N5b: smuggled env key -> exit 125" 125
assert_err_has "N5b: deny reason env_key_not_allowed" "env_key_not_allowed"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N4: /bin/sh -c 'touch /tmp/pwned' -> shell-denylist, /tmp/pwned absent"
docker exec "$HOST" rm -f /tmp/pwned
run_client "$SBX" tmb exec --root -- /bin/sh -c "touch /tmp/pwned"
assert_rc      "N4: /bin/sh request -> exit 125" 125
assert_err_has "N4: deny reason shell_policy" "shell_policy"
host_absent    "N4: /tmp/pwned NOT created in host-sim" /tmp/pwned
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N6: non-absolute executable rejected (broker via raw, client-side)"
cat >"$TD/n6.json" <<'EOF'
{"type":"exec","executable":"id","argv":["id","-u"],"cwd":"/tmp","uid":0,"nonce":"n6-nonce-fixed-000006"}
EOF
run_client_json tmb debug raw "$TD/n6.json"
assert_rc      "N6: broker rejects non-absolute executable (raw 'id')" 125
assert_err_has "N6: deny reason executable_not_absolute" "executable_not_absolute"
run_client "$SBX" tmb exec --root -- ./id -u
assert_rc      "N6: client rejects relative path ./id locally" 2
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N7: wrong-uid client -> SO_PEERCRED deny (can reach socket, uid not allowlisted)"
run_client -u 1000:4242 "$SBX" tmb exec --root -- /usr/bin/id -u
assert_rc      "N7: uid 1000 (gid 4242, can open socket) -> exit 125" 125
assert_err_has "N7: deny reason requester_not_allowed" "requester_not_allowed"
run_client -u 0 "$SBX" tmb exec --root -- /usr/bin/id -u
assert_rc      "N7: even root uid 0 from sandbox -> exit 125" 125
assert_err_has "N7: root also requester_not_allowed" "requester_not_allowed"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N10: approval bound to requester identity (two allowlisted uids)"
# 4242 and 4343 are both allowlisted; approve under 4242, claim under 4343 ->
# requester_mismatch WITHOUT consuming the token, then 4242 still redeems it.
stop_broker
start_broker mock-approve 10
cat >"$TD/n10.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"nonce":"n10-nonce-fixed-000010"}
EOF
run_client_json tmb debug approve "$TD/n10.json"
assert_rc "N10: approve phase ok (requester uid 4242)" 0
T10=$(token_of)
echo "-- token from approve: ${T10:-<none>}"
if [ -n "$T10" ]; then ok "N10: got one-shot token $T10"; else bad "N10: no token parsed"; fi
docker exec -i -u 4343:4242 "$SBX" tmb debug claim --token "$T10" --json - <"$TD/n10.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "N10: claim under OTHER allowlisted uid 4343 -> exit 125" 125
assert_err_has "N10: deny reason requester_mismatch" "requester_mismatch"
docker exec -i "$SBX" tmb debug claim --token "$T10" --json - <"$TD/n10.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc     "N10: token NOT consumed; claim under original uid 4242 -> exit 0" 0
assert_out_eq "N10: stdout is exactly '0'" "0"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N11: exe replaced between claim validation and exec -> the APPROVED inode runs"
# /tmp/n11/prog = copy of /bin/echo (prints its argv: "A"); the replacement is
# a #!/bin/sh script printing B at the SAME path (new inode). The swap is
# timed to land INSIDE the claim processing: a watcher in host-sim busy-polls
# the claim store; the moment the token claim file appears the broker is
# between validateRequest and execute, so the watcher SIGSTOPs the broker,
# renames the replacement over the approved path, and SIGCONTs. The kernel
# must then still execute the inode the human approved (fd pinning), not
# whatever now lives at the path.
stop_broker
start_broker mock-approve 10
docker exec "$HOST" sh -c 'rm -rf /tmp/n11 && mkdir -p /tmp/n11 && cp /bin/echo /tmp/n11/prog && chmod 0755 /tmp/n11/prog && printf "#!/bin/sh\necho B\n" > /tmp/n11/prog.b && chmod 0755 /tmp/n11/prog.b && rm -f /tmp/n11/swapped'
cat >"$TD/n11.json" <<'EOF'
{"type":"approve","executable":"/tmp/n11/prog","argv":["/tmp/n11/prog","A"],"cwd":"/tmp","uid":0,"nonce":"n11-nonce-fixed-000011"}
EOF
run_client_json tmb debug approve "$TD/n11.json"
assert_rc "N11: approve phase ok" 0
T11=$(token_of)
if [ -n "$T11" ]; then ok "N11: got one-shot token $T11"; else bad "N11: no token parsed"; fi
echo "-- arming in-window swapper (SIGSTOP broker at claim-file creation)"
docker exec "$HOST" rm -f /tmp/n11/armed
docker exec "$HOST" sh -c '
  BEFORE=0
  for f in /var/lib/tmb-proto/claims/*; do [ -e "$f" ] && BEFORE=$((BEFORE+1)); done
  BPID=$(pgrep -x tmb-broker)
  touch /tmp/n11/armed
  I=0
  while [ "$I" -lt 400000 ]; do
    N=0
    for f in /var/lib/tmb-proto/claims/*; do [ -e "$f" ] && N=$((N+1)); done
    if [ "$N" -gt "$BEFORE" ]; then
      kill -STOP "$BPID"
      mv -f /tmp/n11/prog.b /tmp/n11/prog
      kill -CONT "$BPID"
      touch /tmp/n11/swapped
      exit 0
    fi
    I=$((I+1))
  done
  exit 3
' &
N11_WATCH=$!
# the watcher must count the store before the claim adds its file
for _ in $(seq 1 100); do docker exec "$HOST" test -e /tmp/n11/armed && break; sleep 0.1; done
run_client_json tmb debug claim --token "$T11" "$TD/n11.json"
assert_rc "N11: claim exit 0 (a program ran)" 0
wait "$N11_WATCH"; N11_WRC=$?
if [ "$N11_WRC" = 0 ] && docker exec "$HOST" test -e /tmp/n11/swapped; then ok "N11: swap landed inside the claim window (broker frozen, exe path replaced)"; else bad "N11: swapper never fired (window not exercised)"; fi
assert_out_eq "N11: stdout 'A' - the APPROVED inode ran, not the replacement" "A"
if docker exec "$HOST" grep -q '"event":"exec_start".*"exe_via_fd":true' /var/log/tmb/broker.log 2>/dev/null; then
  ok "N11: JSONL exec_start has exe_via_fd=true (exec via pinned fd)"
else
  bad "N11: JSONL exec_start lacks exe_via_fd=true"
fi
run_client "$SBX" tmb exec --root -- /bin/ls /proc/self/fd
assert_rc     "N11: fd listing via pinned exec ran" 0
assert_out_eq "N11: child sees only fds 0,1,2 (+ls own dirfd) - pin fd closed at exec" "$(printf '0\n1\n2\n3')"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N12: cwd directory replaced between approve and claim -> deny cwd_changed"
# The approved cwd is moved aside and a NEW directory is created at the same
# path. The path string is identical, so path-only validation cannot tell;
# the broker must compare directory identity (dev/ino) at exec time and deny
# instead of silently running the command in the replacement directory.
docker exec "$HOST" sh -c 'rm -rf /tmp/n12-dir /tmp/n12-dir.old && mkdir /tmp/n12-dir && touch /tmp/n12-dir/old-marker'
cat >"$TD/n12.json" <<'EOF'
{"type":"approve","executable":"/bin/ls","argv":["/bin/ls"],"cwd":"/tmp/n12-dir","uid":0,"nonce":"n12-nonce-fixed-000012"}
EOF
run_client_json tmb debug approve "$TD/n12.json"
assert_rc "N12: approve phase ok" 0
T12=$(token_of)
if [ -n "$T12" ]; then ok "N12: got one-shot token $T12"; else bad "N12: no token parsed"; fi
docker exec "$HOST" sh -c 'mv /tmp/n12-dir /tmp/n12-dir.old && mkdir /tmp/n12-dir && touch /tmp/n12-dir/new-marker'
if docker exec "$HOST" test -e /tmp/n12-dir.old/old-marker; then ok "N12: cwd really replaced (old dir moved aside, new inode at the same path)"; else bad "N12: cwd replacement did not happen"; fi
run_client_json tmb debug claim --token "$T12" "$TD/n12.json"
assert_rc      "N12: claim after cwd swap -> exit 125" 125
assert_err_has "N12: deny reason cwd_changed" "cwd_changed"
assert_out_eq  "N12: no command output (nothing executed)" ""
if docker exec "$HOST" grep -q '"event":"deny".*"reason":"cwd_changed"' /var/log/tmb/broker.log 2>/dev/null; then
  ok "N12: JSONL deny event with reason cwd_changed"
else
  bad "N12: JSONL deny event with reason cwd_changed missing"
fi
state_dump

# -----------------------------------------------------------------------------
# Approval queue helpers: the approver is the host user `human` (uid 1500,
# the only approver_uids entry) running `tmb approve` on the approver socket,
# which lives outside the volume shared with the sandbox.
APPROVE_SOCK=/run/tmb-approver/approve.sock
approve_as() { # approve_as USER ARGS... -> tmb approve in host-sim as USER
  local u=$1; shift
  docker exec -u "$u" -e TMB_APPROVE_SOCK="$APPROVE_SOCK" "$HOST" tmb approve "$@"
}
wait_queue() { # wait_queue N -> the queue lists at least N items ($TD/queue.out)
  local _
  for _ in $(seq 1 150); do
    approve_as human --list >"$TD/queue.out" 2>&1
    [ "$(grep -c '^=== ' "$TD/queue.out")" -ge "$1" ] && return 0
    sleep 0.1
  done
  return 1
}
queue_id() { sed -n 's/^=== \([0-9a-f]\{16\}\) ===$/\1/p' "$TD/queue.out" | head -1; }
queue_has() { if grep -qF -- "$2" "$TD/queue.out"; then ok "$1"; else bad "$1 (queue listing lacks '$2')"; fi; }

log "SCENARIO N13: approval queue: the request waits, the approver decides with tmb approve"
stop_broker
start_broker queue 10
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n13a.out" 2>"$TD/n13a.err" &
CLI13=$!
if wait_queue 1; then ok "N13: request waits in the approval queue"; else bad "N13: request never reached the queue"; fi
sed 's/^/  | /' "$TD/queue.out"
queue_has "N13: listing shows the requester uid" "requester : uid=4242 "
queue_has "N13: listing shows the realpath of the executable" "executable: /usr/bin/id"
queue_has "N13: listing shows argv" 'argv      : ["/usr/bin/id","-u"]'
queue_has "N13: listing shows the cwd realpath" "cwd       : /tmp"
queue_has "N13: listing shows the final env with PATH from fixed_env" '"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
ID13=$(queue_id)
OUT_FILE=$TD/n13y.out; ERR_FILE=$TD/n13y.err
approve_as human --yes "$ID13" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc "N13: tmb approve --yes <id> -> exit 0" 0
wait $CLI13; RUNC=$?
OUT_FILE=$TD/n13a.out; ERR_FILE=$TD/n13a.err; show_io
assert_rc     "N13: approved client -> exit 0" 0
assert_out_eq "N13: approved client stdout '0'" "0"
LOG13=$(docker exec "$HOST" cat /var/log/tmb/broker.log)
if grep '"event":"queued"' <<<"$LOG13" | grep -q "\"item\":\"$ID13\""; then ok "N13: JSONL queued for the item"; else bad "N13: JSONL queued missing"; fi
if grep '"event":"approval"' <<<"$LOG13" | grep '"approver":"uid:1500"' | grep -q '"decision":"approve"'; then ok "N13: JSONL approval with approver=uid:1500, decision approve"; else bad "N13: JSONL approval lacks approver uid:1500 / decision"; fi
if grep '"event":"exec_exit"' <<<"$LOG13" | grep -q "\"token\":\"$ID13\""; then ok "N13: JSONL claim/exec_start/exec_exit follow for the token"; else bad "N13: JSONL exec_exit for the token missing"; fi

echo "-- round 2: the approver says no"
docker exec "$SBX" tmb exec --root -- /usr/bin/id -G >"$TD/n13b.out" 2>"$TD/n13b.err" &
CLI13B=$!
wait_queue 1 || bad "N13: second request never reached the queue"
approve_as human --no "$(queue_id)" >/dev/null 2>&1
wait $CLI13B; RUNC=$?
OUT_FILE=$TD/n13b.out; ERR_FILE=$TD/n13b.err; show_io
assert_rc      "N13: denied client -> exit 125" 125
assert_err_has "N13: deny reason approval_denied_by_human" "approval_denied_by_human"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N14: the approver is not a requester; no approval path from the sandbox"
OUT_FILE=$TD/n14a.out; ERR_FILE=$TD/n14a.err
approve_as 4242 --list >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "N14: requester uid 4242 on the approver socket -> exit 125" 125
assert_err_has "N14: deny reason approver_not_allowed" "approver_not_allowed"
if docker exec "$HOST" grep '"event":"approver_denied"' /var/log/tmb/broker.log | grep -q '"approver_uid":4242'; then ok "N14: JSONL approver_denied with uid 4242"; else bad "N14: JSONL approver_denied for uid 4242 missing"; fi
if docker exec "$SBX" test -e "$APPROVE_SOCK"; then bad "N14: approver socket visible in the sandbox"; else ok "N14: approver socket not visible in the sandbox"; fi
cat >"$TD/n14.json" <<'EOF'
{"type":"list"}
EOF
run_client_json tmb debug raw "$TD/n14.json"
assert_rc      "N14: list on the requester socket -> exit 125" 125
assert_err_has "N14: deny reason unknown_request_type" "unknown_request_type"
OUT_FILE=$TD/n14q.out; ERR_FILE=$TD/n14q.err
approve_as human --list >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?
assert_out_eq "N14: queue unchanged (empty)" "queue is empty"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N16: two approvers: the first decision wins, the second sees already decided"
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n16.out" 2>"$TD/n16.err" &
CLI16=$!
wait_queue 1 || bad "N16: request never reached the queue"
ID16=$(queue_id)
OUT_FILE=$TD/n16y.out; ERR_FILE=$TD/n16y.err
approve_as human --yes "$ID16" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc "N16: first approver --yes -> exit 0" 0
OUT_FILE=$TD/n16n.out; ERR_FILE=$TD/n16n.err
approve_as human --no "$ID16" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "N16: second approver --no on the same id -> exit 1" 1
assert_err_has "N16: stderr says already decided" "already decided"
wait $CLI16; RUNC=$?
OUT_FILE=$TD/n16.out; ERR_FILE=$TD/n16.err; show_io
assert_rc "N16: client of the approved request -> exit 0" 0
N16_STARTS=$(docker exec "$HOST" grep '"event":"exec_start"' /var/log/tmb/broker.log | grep -c "\"token\":\"$ID16\"")
if [ "$N16_STARTS" = 1 ]; then ok "N16: command ran exactly once (one exec_start)"; else bad "N16: exec_start count $N16_STARTS, want 1"; fi
stop_broker
start_broker mock-approve 10
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N15: a request nobody decides times out after approval_wait_seconds"
stop_broker
docker exec "$HOST" sh -c 'sed "s#\"approval_wait_seconds\": 300#\"approval_wait_seconds\": 2#" /etc/tmb/config.json >/tmp/n15.json'
docker exec -d "$HOST" tmb-broker -config /tmp/n15.json -approval queue -ttl 10
wait_socket
docker exec "$HOST" rm -f /tmp/n15-marker
T15=$(date +%s)
run_client "$SBX" tmb exec --root -- /usr/bin/touch /tmp/n15-marker
E15=$(( $(date +%s) - T15 ))
assert_rc      "N15: undecided request -> exit 125" 125
assert_err_has "N15: deny reason approval_timeout" "approval_timeout"
if [ "$E15" -ge 2 ] && [ "$E15" -le 10 ]; then ok "N15: timed out after ${E15}s (2..10s)"; else bad "N15: timed out after ${E15}s, want 2..10s"; fi
W15=$(grep -c "waiting for approval" "$ERR_FILE")
if [ "$W15" = 1 ]; then ok "N15: client said 'waiting for approval' exactly once"; else bad "N15: 'waiting for approval' printed $W15 times"; fi
host_absent "N15: marker never created" /tmp/n15-marker
approve_as human --list >"$TD/n15q.out" 2>&1
if grep -q "queue is empty" "$TD/n15q.out"; then ok "N15: queue is empty after the timeout"; else bad "N15: queue not empty after the timeout"; fi
if docker exec "$HOST" grep -q '"event":"approval_timeout"' /var/log/tmb/broker.log; then ok "N15: JSONL approval_timeout"; else bad "N15: JSONL approval_timeout missing"; fi
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N17: the queue is not a mutex; a client that hangs up leaves the queue"
stop_broker
start_broker queue 10
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n17a.out" 2>"$TD/n17a.err" &
CLI17A=$!
wait_queue 1 || bad "N17: first request never queued"
docker exec "$SBX" tmb exec --root -- /usr/bin/id -G >"$TD/n17b.out" 2>"$TD/n17b.err" &
CLI17B=$!
if wait_queue 2; then ok "N17: both requests wait in the queue"; else bad "N17: the queue never listed two requests"; fi
ID17B=$(awk '/^=== /{id=$2} /argv      : \["\/usr\/bin\/id","-G"\]/{print id; exit}' "$TD/queue.out")
ID17A=$(awk '/^=== /{id=$2} /argv      : \["\/usr\/bin\/id","-u"\]/{print id; exit}' "$TD/queue.out")
approve_as human --yes "$ID17B" >/dev/null 2>&1
wait $CLI17B; RUNC=$?
OUT_FILE=$TD/n17b.out; ERR_FILE=$TD/n17b.err; show_io
assert_rc "N17: second request approved and finished while the first waits" 0
approve_as human --list >"$TD/queue.out" 2>&1
if [ "$(grep -c '^=== ' "$TD/queue.out")" = 1 ] && grep -q "^=== $ID17A ===" "$TD/queue.out"; then ok "N17: only the first request is still waiting"; else bad "N17: queue after the second decision is wrong"; fi
approve_as human --yes "$ID17A" >/dev/null 2>&1
wait $CLI17A; RUNC=$?
OUT_FILE=$TD/n17a.out; ERR_FILE=$TD/n17a.err; show_io
assert_rc     "N17: first request approved afterwards -> exit 0" 0
assert_out_eq "N17: first request stdout '0'" "0"

echo "-- round 2: the waiting client is killed with SIGKILL"
docker exec "$SBX" sh -c 'echo $$ >/tmp/n17.pid; exec tmb exec --root -- /usr/bin/id -n' >/dev/null 2>&1 &
CLI17C=$!
wait_queue 1 || bad "N17: third request never queued"
docker exec "$SBX" sh -c 'kill -9 "$(cat /tmp/n17.pid)"'
wait $CLI17C 2>/dev/null
GONE=0
for _ in $(seq 1 50); do
  approve_as human --list >"$TD/queue.out" 2>&1
  grep -q "queue is empty" "$TD/queue.out" && { GONE=1; break; }
  sleep 0.1
done
if [ "$GONE" = 1 ]; then ok "N17: killed client's request left the queue"; else bad "N17: killed client's request still queued"; fi
if docker exec "$HOST" grep -q '"event":"request_abandoned"' /var/log/tmb/broker.log; then ok "N17: JSONL request_abandoned"; else bad "N17: JSONL request_abandoned missing"; fi
stop_broker
start_broker mock-approve 10
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N18: cwd outside allowed_cwd_roots -> deny cwd_not_allowed before approval"
# The bench config allows only /tmp. The check runs on the realpath, so a
# symlink inside /tmp that points at /etc is denied too, and the denial comes
# from validation: no approval event is logged for it.
docker exec "$HOST" sh -c 'rm -rf /tmp/n18-dir /tmp/n18-link && mkdir /tmp/n18-dir && ln -s /etc /tmp/n18-link'
approvals() { docker exec "$HOST" grep -c '"event":"approval"' /var/log/tmb/broker.log 2>/dev/null; }
A0=$(approvals)
run_client "$SBX" tmb exec --root --cwd /etc -- /usr/bin/id -u
assert_rc      "N18: --cwd /etc -> exit 125" 125
assert_err_has "N18: deny reason cwd_not_allowed" "cwd_not_allowed"
run_client "$SBX" tmb exec --root --cwd /tmp/n18-link -- /usr/bin/id -u
assert_rc      "N18: --cwd /tmp/n18-link (symlink to /etc) -> exit 125" 125
assert_err_has "N18: symlink denied with realpath /etc in detail" "cwd_not_allowed (/etc)"
if [ "$(approvals)" = "$A0" ]; then ok "N18: no approval event for cwd outside the roots"; else bad "N18: approval event logged for a denied cwd"; fi
run_client "$SBX" tmb exec --root --cwd /tmp/n18-dir -- /bin/pwd
assert_rc     "N18: --cwd /tmp/n18-dir inside the root -> approved, exit 0" 0
assert_out_eq "N18: command ran in /tmp/n18-dir" "/tmp/n18-dir"

echo "-- round 2: broker with an empty allowed_cwd_roots denies every cwd"
stop_broker
docker exec "$HOST" sh -c 'sed "s#\"allowed_cwd_roots\": \[\"/tmp\"\]#\"allowed_cwd_roots\": []#" /etc/tmb/config.json >/tmp/n18-empty.json'
docker exec -d "$HOST" tmb-broker -config /tmp/n18-empty.json -approval mock-approve -ttl "$TTL"
wait_socket
run_client "$SBX" tmb exec --root --cwd /tmp -- /usr/bin/id -u
assert_rc      "N18: empty allowed_cwd_roots, --cwd /tmp -> exit 125" 125
assert_err_has "N18: empty roots deny reason cwd_not_allowed" "cwd_not_allowed"
stop_broker

echo "-- round 3: a relative root is a config error, the broker does not start"
docker exec "$HOST" sh -c 'sed "s#\"allowed_cwd_roots\": \[\"/tmp\"\]#\"allowed_cwd_roots\": [\"work/dir\"]#" /etc/tmb/config.json >/tmp/n18-relative.json'
OUT_FILE=$TD/n18r.out; ERR_FILE=$TD/n18r.err
docker exec "$HOST" timeout 10 tmb-broker -config /tmp/n18-relative.json -approval mock-approve >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "N18: relative root -> broker exits 1" 1
assert_err_has "N18: stderr names the relative root" '"work/dir"'
if docker exec "$HOST" test -S /run/tmb/tmb.sock; then bad "N18: socket exists after a failed start"; else ok "N18: no socket after a failed start"; fi
start_broker mock-approve 10
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N19: fixed env keys cannot be requested; PATH only from fixed_env"
# The bench config keeps LANG in both fixed_env and allowed_env_keys: the
# fixed value wins, so the key is not editable.
run_client "$SBX" tmb exec --root --env LANG=ru_RU -- /usr/bin/id -u
assert_rc      "N19: --env LANG=ru_RU (fixed and allowlisted) -> exit 125" 125
assert_err_has "N19: deny reason env_fixed_key" "env_fixed_key"
run_client "$SBX" tmb exec --root --env PATH=/evil -- /usr/bin/id -u
assert_rc      "N19: --env PATH=/evil -> exit 125" 125
assert_err_has "N19: deny reason env_key_not_allowed" "env_key_not_allowed (PATH)"
run_client "$SBX" tmb exec --root -- /usr/bin/printenv LANG
assert_out_eq  "N19: child LANG is the fixed value" "C.UTF-8"

echo "-- a config with PATH in allowed_env_keys does not start"
stop_broker
docker exec "$HOST" sh -c 'sed "s#\"allowed_env_keys\": \[\"LANG\", \"TZ\"\]#\"allowed_env_keys\": [\"LANG\", \"PATH\"]#" /etc/tmb/config.json >/tmp/n19-path.json'
OUT_FILE=$TD/n19p.out; ERR_FILE=$TD/n19p.err
docker exec "$HOST" timeout 10 tmb-broker -config /tmp/n19-path.json -approval mock-approve >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "N19: PATH in allowed_env_keys -> broker exits 1" 1
assert_err_has "N19: stderr names the key" "allowed_env_keys must not contain PATH"
if docker exec "$HOST" test -S /run/tmb/tmb.sock; then bad "N19: socket exists after a failed start"; else ok "N19: no socket after a failed start"; fi
start_broker mock-approve 10
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N20: env values are single-line and at most 4096 bytes"
V4096=$(printf 'a%.0s' $(seq 1 4096))
run_client "$SBX" tmb exec --root --env "TZ=$(printf 'UTC\nX=1')" -- /usr/bin/id -u
assert_rc      "N20: value with a newline -> exit 125" 125
assert_err_has "N20: deny reason env_value_invalid" "env_value_invalid"
run_client "$SBX" tmb exec --root --env "TZ=${V4096}a" -- /usr/bin/id -u
assert_rc      "N20: 4097-byte value -> exit 125" 125
assert_err_has "N20: deny reason env_value_too_long" "env_value_too_long"

echo "-- 4096 bytes pass; the manual console shows the value on the env line"
stop_broker
FIFO20=$TD/n20-console.in
LOG20=$TD/n20-console.log
mkfifo "$FIFO20"
docker exec -i "$HOST" tmb-broker -approval manual -ttl "$TTL" <"$FIFO20" >"$LOG20" 2>&1 &
N20_PID=$!
exec 8>"$FIFO20"
wait_socket
docker exec "$SBX" tmb exec --root --env "TZ=$V4096" -- /usr/bin/printenv TZ >"$TD/n20.out" 2>"$TD/n20.err" &
CLI20=$!
for _ in $(seq 1 150); do grep -q 'Approve exactly this command' "$LOG20" 2>/dev/null && break; sleep 0.1; done
printf 'y\n' >&8
wait $CLI20; RUNC=$?
OUT_FILE=$TD/n20.out; ERR_FILE=$TD/n20.err; show_io
assert_rc     "N20: 4096-byte value -> approved, exit 0" 0
if [ "$(cat "$OUT_FILE")" = "$V4096" ]; then ok "N20: child got the 4096-byte value"; else bad "N20: child TZ differs from the 4096-byte value"; fi
if grep -q "^  env       : .*\"TZ=${V4096}\"" "$LOG20"; then ok "N20: console env line carries the whole value"; else bad "N20: console env line lacks the 4096-byte value"; fi
stop_broker
wait $N20_PID 2>/dev/null
exec 8>&-
start_broker mock-approve 10
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N22: held cwd fd from approval to exec; rename before claim -> cwd_changed"
# The approval holds an O_DIRECTORY fd on the cwd and the child chdirs
# through /proc/self/fd/N. A rename between approve and claim is still
# caught by the identity check (as N12); the window after that check is
# covered by TestExecChdirsThroughHeldCwdDespiteSwapAfterCheck.
docker exec "$HOST" sh -c 'rm -rf /tmp/n22 /tmp/n22-old && mkdir /tmp/n22'
cat >"$TD/n22.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/touch","argv":["/usr/bin/touch","marker"],"cwd":"/tmp/n22","uid":0,"nonce":"n22-nonce-fixed-000022"}
EOF
run_client_json tmb debug approve "$TD/n22.json"
assert_rc "N22: approve phase ok" 0
T22=$(token_of)
docker exec "$HOST" sh -c 'mv /tmp/n22 /tmp/n22-old && mkdir /tmp/n22'
run_client_json tmb debug claim --token "$T22" "$TD/n22.json"
assert_rc      "N22: claim after cwd rename -> exit 125" 125
assert_err_has "N22: deny reason cwd_changed" "cwd_changed"
host_absent    "N22: no marker in the renamed directory" /tmp/n22-old/marker
host_absent    "N22: no marker in the new directory" /tmp/n22/marker

echo "-- positive control: same request, cwd untouched"
cat >"$TD/n22b.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/touch","argv":["/usr/bin/touch","marker"],"cwd":"/tmp/n22","uid":0,"nonce":"n22-nonce-fixed-000023"}
EOF
run_client_json tmb debug approve "$TD/n22b.json"
T22B=$(token_of)
run_client_json tmb debug claim --token "$T22B" "$TD/n22b.json"
assert_rc "N22: claim with intact cwd -> exit 0" 0
if docker exec "$HOST" test -e /tmp/n22/marker; then ok "N22: marker created in /tmp/n22"; else bad "N22: marker missing in /tmp/n22"; fi
if docker exec "$HOST" grep '"event":"exec_start"' /var/log/tmb/broker.log | grep -q '"cwd_via_fd":true'; then ok "N22: exec_start records cwd_via_fd=true"; else bad "N22: exec_start lacks cwd_via_fd=true"; fi
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N21: claim-file GC at start removes expired files, keeps replay protection"
# Every claim file carries expires_at = creation + TTL + 24h. The harness
# plants one file already expired and one far in the future, restarts the
# broker, and checks the start-up pass removed exactly the expired one while
# a token redeemed just before the restart is still refused.
cat >"$TD/n21.json" <<'EOF'
{"type":"exec","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"nonce":"n21-replay-nonce-0021"}
EOF
run_client_json tmb debug raw "$TD/n21.json"
assert_rc "N21: fresh request runs, exit 0" 0
if docker exec "$HOST" sh -c 'grep -l "\"expires_at\"" /var/lib/tmb-proto/claims/*.claim | head -1 | grep -q .'; then ok "N21: claim files carry expires_at"; else bad "N21: claim files lack expires_at"; fi
docker exec "$HOST" sh -c 'echo "{\"kind\":\"token\",\"expires_at\":1}" >/var/lib/tmb-proto/claims/n21-expired.claim && echo "{\"kind\":\"token\",\"expires_at\":4102444800}" >/var/lib/tmb-proto/claims/n21-future.claim'
stop_broker
start_broker mock-approve 10
host_absent "N21: expired claim file removed at start" /var/lib/tmb-proto/claims/n21-expired.claim
if docker exec "$HOST" test -e /var/lib/tmb-proto/claims/n21-future.claim; then ok "N21: unexpired claim file kept"; else bad "N21: unexpired claim file removed"; fi
if docker exec "$HOST" sh -c 'grep "\"event\":\"claim_gc\"" /var/log/tmb/broker.log | tail -1 | grep -q "\"removed\":1"'; then ok "N21: JSONL claim_gc removed=1"; else bad "N21: JSONL claim_gc removed=1 missing"; fi
run_client_json tmb debug raw "$TD/n21.json"
assert_rc      "N21: replay of the redeemed token after restart -> exit 125" 125
assert_err_has "N21: deny reason token_consumed_replay" "token_consumed_replay"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N24: the old certificate allowlist and the -tls-* flags are gone"
# Both failures happen before any socket is touched, so the running broker
# is left alone.
docker exec "$HOST" sh -c 'sed "s#\"allowed_requester_uids\": \[4242, 4343\],#\"allowed_requester_uids\": [4242, 4343], \"allowed_requester_fps\": [\"aa\"],#" /etc/tmb/config.json >/tmp/n24.json'
OUT_FILE=$TD/n24a.out; ERR_FILE=$TD/n24a.err
docker exec "$HOST" timeout 10 tmb-broker -config /tmp/n24.json -approval mock-approve >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "N24: allowed_requester_fps in the config -> broker exits 1" 1
assert_err_has "N24: stderr names the old field" "allowed_requester_fps"
assert_err_has "N24: stderr names the replacement" "allowed_requester_keys"
OUT_FILE=$TD/n24b.out; ERR_FILE=$TD/n24b.err
docker exec "$HOST" timeout 10 tmb-broker -tls-ca /etc/tmb/certs/ca.crt >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "N24: -tls-ca -> usage error, exit 2" 2
assert_err_has "N24: -tls-ca is an unknown flag" "flag provided but not defined: -tls-ca"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N28: a queued request and a pending approval survive SIGHUP"
# SIGHUP re-reads the config (here the same file). The waiting request keeps
# its place and is approved after the reload; an approval granted before
# the reload is redeemed after it. The process is the same throughout.
reload_count() { docker exec "$HOST" grep -c '"event":"reload"' /var/log/tmb/broker.log 2>/dev/null | tr -d '[:space:]'; }
hup_and_wait_reload() { # hup_and_wait_reload -> 0 once one more reload event is logged
  local _ before
  before=$(reload_count); before=${before:-0}
  echo "-- SIGHUP to tmb-broker"
  docker exec "$HOST" pkill -HUP -x tmb-broker
  for _ in $(seq 1 150); do
    [ "$(reload_count)" -gt "$before" ] 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}
stop_broker
start_broker queue 30
PID28=$(docker exec "$HOST" pgrep -x tmb-broker | tr -d '[:space:]')
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n28a.out" 2>"$TD/n28a.err" &
CLI28=$!
if wait_queue 1; then ok "N28: request waits in the queue"; else bad "N28: request never reached the queue"; fi
ID28=$(queue_id)
if hup_and_wait_reload; then ok "N28: SIGHUP -> reload event"; else bad "N28: no reload event after SIGHUP"; fi
docker exec "$HOST" grep '"event":"reload"' /var/log/tmb/broker.log | tail -1 | sed 's/^/  | /'
if wait_queue 1 && [ "$(queue_id)" = "$ID28" ]; then ok "N28: the same item $ID28 still waits after the reload"; else bad "N28: queue lost item $ID28 on reload"; fi
OUT_FILE=$TD/n28y.out; ERR_FILE=$TD/n28y.err
approve_as human --yes "$ID28" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc "N28: tmb approve --yes after the reload -> exit 0" 0
wait $CLI28; RUNC=$?
OUT_FILE=$TD/n28a.out; ERR_FILE=$TD/n28a.err; show_io
assert_rc     "N28: the queued request ran -> exit 0" 0
assert_out_eq "N28: stdout '0'" "0"

echo "-- pending approval: approve before SIGHUP, claim after"
cat >"$TD/n28.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"nonce":"n28-nonce-fixed-000028"}
EOF
OUT_FILE=$TD/n28p.out; ERR_FILE=$TD/n28p.err
docker exec -i "$SBX" tmb debug approve --json - <"$TD/n28.json" >"$OUT_FILE" 2>"$ERR_FILE" &
CLI28P=$!
wait_queue 1 || bad "N28: approve request never reached the queue"
approve_as human --yes "$(queue_id)" >/dev/null 2>&1
wait $CLI28P; RUNC=$?; show_io
assert_rc "N28: approve phase ok before the reload" 0
T28=$(token_of)
if [ -n "$T28" ]; then ok "N28: got one-shot token $T28"; else bad "N28: no token parsed"; fi
if hup_and_wait_reload; then ok "N28: second SIGHUP -> reload event"; else bad "N28: no reload event after the second SIGHUP"; fi
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
docker exec -i "$SBX" tmb debug claim --token "$T28" --json - <"$TD/n28.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc     "N28: claim after the reload redeems the pending approval -> exit 0" 0
assert_out_eq "N28: stdout '0'" "0"
if [ "$(docker exec "$HOST" pgrep -x tmb-broker | tr -d '[:space:]')" = "$PID28" ]; then ok "N28: broker pid unchanged ($PID28)"; else bad "N28: broker pid changed"; fi
stop_broker
start_broker mock-approve 10
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N29: the journal reopens on SIGHUP, an unwritable journal closes the agent path, the schema version on every line"
# logrotate renames the file and sends SIGHUP: the broker opens a new file
# at log_path. Then the log directory becomes unwritable and the file is
# gone: the reopen fails, new requests get audit_unavailable and nothing
# runs, the reason is on the broker's stderr. Write access back, SIGHUP:
# requests pass again. The broker runs here without CAP_DAC_OVERRIDE (and
# CAP_DAC_READ_SEARCH), so mode 0500 on its root-owned log directory binds
# it the way it binds any owner; its stderr goes to /tmp/n29-broker.err.
JLOG=/var/log/tmb/broker.log
JERR=/tmp/n29-broker.err
n29_wait() { # n29_wait FILE STRING -> 0 once FILE in host-sim contains STRING
  local _
  for _ in $(seq 1 150); do
    docker exec "$HOST" grep -qF -- "$2" "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}
n29_unschema() { # n29_unschema FILE -> JSON lines of FILE without "schema":3
  docker exec "$HOST" sh -c "grep '^{' $1 | grep -vc '\"schema\":3'" | tr -d '[:space:]'
}
stop_broker
docker exec "$HOST" rm -f "$JERR"
docker exec -d "$HOST" sh -c "exec setpriv --bounding-set=-dac_override,-dac_read_search --inh-caps=-dac_override,-dac_read_search tmb-broker -approval mock-approve -ttl 10 2>$JERR"
wait_socket
CAPEFF=$(docker exec "$HOST" sh -c 'sed -n "s/^CapEff:[[:space:]]*//p" /proc/$(pgrep -x tmb-broker)/status' | tr -d '[:space:]')
echo "-- broker CapEff=$CAPEFF"
if [ -n "$CAPEFF" ] && [ $((0x$CAPEFF & 0x6)) -eq 0 ]; then ok "N29: broker runs without CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH"; else bad "N29: broker still has DAC override caps (CapEff=$CAPEFF)"; fi
run_client "$SBX" tmb exec --root -- /usr/bin/id -u
assert_rc     "N29: request before the rotation -> exit 0" 0
if [ "$(n29_unschema "$JLOG")" = "0" ]; then ok "N29: every journal line carries \"schema\":3"; else bad "N29: journal lines without \"schema\":3"; fi

echo "-- rotation: rename the journal, SIGHUP"
docker exec "$HOST" mv "$JLOG" "$JLOG.1"
OLD29=$(docker exec "$HOST" stat -c %s "$JLOG.1" | tr -d '[:space:]')
docker exec "$HOST" pkill -HUP -x tmb-broker
if n29_wait "$JLOG" '"event":"reload"'; then ok "N29: SIGHUP after the rename -> new $JLOG with the reload event"; else bad "N29: no new journal file after SIGHUP"; fi
run_client "$SBX" tmb exec --root -- /usr/bin/id -u
assert_rc     "N29: request after the rotation -> exit 0" 0
assert_out_eq "N29: stdout '0'" "0"
if n29_wait "$JLOG" '"event":"exec_exit"'; then ok "N29: the request's events are in the new file"; else bad "N29: the request's events are not in the new file"; fi
if [ "$(docker exec "$HOST" stat -c %s "$JLOG.1" | tr -d '[:space:]')" = "$OLD29" ]; then ok "N29: the renamed file did not grow ($OLD29 bytes)"; else bad "N29: the renamed file grew after the reopen"; fi

echo "-- the log directory becomes unwritable and the journal is gone, SIGHUP"
docker exec "$HOST" sh -c "rm -f $JLOG && chmod 0500 /var/log/tmb"
docker exec "$HOST" pkill -HUP -x tmb-broker
if n29_wait "$JERR" '"event":"audit_unavailable"'; then ok "N29: failed reopen -> audit_unavailable on the broker's stderr"; else bad "N29: no audit_unavailable on the broker's stderr"; fi
docker exec "$HOST" rm -f /tmp/n29-marker
run_client "$SBX" tmb exec --root -- /usr/bin/touch /tmp/n29-marker
assert_rc      "N29: request while the journal is unavailable -> exit 125" 125
assert_err_has "N29: deny reason audit_unavailable" "audit_unavailable"
host_absent    "N29: the command did not run" /tmp/n29-marker
host_absent    "N29: no journal file appeared" "$JLOG"
echo "-- broker stderr --"; docker exec "$HOST" cat "$JERR" | sed 's/^/  | /'
if docker exec "$HOST" grep -q 'journal unavailable.*permission denied' "$JERR"; then ok "N29: broker stderr names the reason (permission denied)"; else bad "N29: broker stderr lacks the reason"; fi

echo "-- write access back, SIGHUP"
docker exec "$HOST" chmod 0755 /var/log/tmb
docker exec "$HOST" pkill -HUP -x tmb-broker
if n29_wait "$JLOG" '"event":"reload"'; then ok "N29: SIGHUP with write access -> journal reopened"; else bad "N29: journal not reopened after write access came back"; fi
if docker exec "$HOST" grep -q 'accepting requests again' "$JERR"; then ok "N29: broker stderr says it accepts requests again"; else bad "N29: no recovery line on the broker's stderr"; fi
run_client "$SBX" tmb exec --root -- /usr/bin/id -u
assert_rc     "N29: request after the recovery -> exit 0" 0
assert_out_eq "N29: stdout '0'" "0"
if [ "$(n29_unschema "$JLOG")" = "0" ] && [ "$(n29_unschema "$JLOG.1")" = "0" ] && [ "$(n29_unschema "$JERR")" = "0" ]; then ok "N29: every line in both journal files and the stderr reserve carries \"schema\":3"; else bad "N29: a line without \"schema\":3"; fi
stop_broker
start_broker mock-approve 10
state_dump

# -----------------------------------------------------------------------------
# Signed decision (ADR 0006, ADR 0007): a fake trusted signer drives the
# machine mode of `tmb approve` the way the Mac signer does over SSH. Its
# P-256 keys are generated on the runner into $TD (wiped by the cleanup
# trap): no private key enters an image, the broker config carries only the
# public keys. The fake signer signs the base64-decoded `payload` of
# `tmb approve --list --json` with openssl (DER ECDSA over SHA-256 of the raw
# bytes) and sends the decision object on stdin to `tmb approve --decide`.
SIG=$TD/signer
SIG_HOST=tmb-n-host
mkdir -p "$SIG"
signer_key() { # signer_key NAME -> $SIG/NAME.pem (private), NAME.spki (base64 SPKI), NAME.fp
  openssl ecparam -name prime256v1 -genkey -noout -out "$SIG/$1.pem" 2>/dev/null
  openssl pkey -in "$SIG/$1.pem" -pubout -outform DER -out "$SIG/$1.der" 2>/dev/null
  openssl base64 -A -in "$SIG/$1.der" >"$SIG/$1.spki"
  openssl dgst -sha256 -hex "$SIG/$1.der" | awk '{print $NF}' >"$SIG/$1.fp"
}
fp_of() { cat "$SIG/$1.fp"; }
signed_config() { # signed_config FILE REQUIRED WAIT KEY... -> broker config in host-sim with these approver keys
  local f=$1 req=$2 wait=$3 keys="" n
  shift 3
  for n in "$@"; do keys+="${keys:+, }{\"name\": \"$n\", \"class\": \"mac-se\", \"public_key\": \"$(cat "$SIG/$n.spki")\"}"; done
  docker exec "$HOST" cat /etc/tmb/config.json \
    | sed -e "s#\"approval_wait_seconds\": 300#\"approval_wait_seconds\": $wait#" \
          -e "s#\"approval_default\": \"queue\"#\"approval_default\": \"queue\", \"host_id\": \"$SIG_HOST\", \"require_signed_decision\": true, \"required_signatures\": $req, \"approver_keys\": [$keys]#" \
    | docker exec -i "$HOST" sh -c "cat >$f"
}
start_signed_broker() { # start_signed_broker CONFIG
  stop_broker
  echo "-- starting tmb-broker (mode=queue, signed decisions, config $1)"
  docker exec -d "$HOST" tmb-broker -config "$1" -approval queue -ttl 10
  wait_socket
}
queue_json() { approve_as human --list --json >"$TD/queue.json" 2>"$TD/queue.json.err"; }
wait_queue_json() { # wait_queue_json N -> at least N items in $TD/queue.json
  local _
  for _ in $(seq 1 150); do
    queue_json
    [ "$(jq '.items | length' "$TD/queue.json" 2>/dev/null)" -ge "$1" ] 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}
item_by_argv() { # item_by_argv ARG1 -> id of the queued item whose argv[1] is ARG1
  jq -r --arg a "$1" '.items[] | select(.argv[1] == $a) | .id' "$TD/queue.json" | head -1
}
item_field() { # item_field ID FIELD
  jq -r --arg id "$1" --arg f "$2" '.items[] | select(.id == $id) | .[$f] | tostring' "$TD/queue.json"
}
save_payload() { # save_payload ID FILE -> the exact payload bytes of the item
  item_field "$1" payload | openssl base64 -d -A >"$2"
}
forge_payload() { # forge_payload IN OUT PERL-SUBST -> the payload with its JSON part edited
  { printf 'tmb-approval-v1\0'; tail -c +17 "$1" | perl -pe "$3"; } >"$2"
}
sign_file() { openssl dgst -sha256 -sign "$SIG/$1.pem" "$2" | openssl base64 -A; } # sign_file KEY FILE
decision() { # decision OUT ID HASH approve|deny [SIGNATURE FP] -> the decide object on stdin of tmb approve
  if [ $# -ge 6 ]; then
    printf '{"item_id":"%s","item_hash":"%s","decision":"%s","signature":"%s","approver_key":"%s"}\n' "$2" "$3" "$4" "$5" "$6" >"$1"
  else
    printf '{"item_id":"%s","item_hash":"%s","decision":"%s"}\n' "$2" "$3" "$4" >"$1"
  fi
}
signed_decision() { # signed_decision OUT ID KEY [PAYLOAD-FILE] -> approve of item ID signed by KEY over PAYLOAD-FILE (default: the item's own payload)
  local pf=${4:-$TD/sd-$2.bin}
  [ -n "${4:-}" ] || save_payload "$2" "$pf"
  decision "$1" "$2" "$(item_field "$2" hash)" approve "$(sign_file "$3" "$pf")" "$(fp_of "$3")"
}
decide() { # decide FILE -> tmb approve --decide as the approver, decision object from FILE
  echo "-- decide: $(sed 's/"signature":"[^"]*"/"signature":"<der>"/' "$1")"
  docker exec -i -u human -e TMB_APPROVE_SOCK="$APPROVE_SOCK" "$HOST" tmb approve --decide <"$1" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
}
journal_count() { # journal_count PATTERN... -> journal lines matching every pattern
  local f=$TD/journal.jsonl p
  docker exec "$HOST" cat /var/log/tmb/broker.log >"$f" 2>/dev/null
  for p in "$@"; do grep -F -- "$p" "$f" >"$f.tmp"; mv "$f.tmp" "$f"; done
  wc -l <"$f" | tr -d '[:space:]'
}
signer_key alice
signer_key bob
signer_key mallory
echo "-- fake signer keys: alice=$(fp_of alice) bob=$(fp_of bob) mallory=$(fp_of mallory) (mallory is in no config)"
signed_config /tmp/signed-1.json 1 30 alice bob
signed_config /tmp/signed-short.json 1 2 alice
signed_config /tmp/signed-2.json 2 30 alice bob

log "SCENARIO N31: a valid signature over the item's payload runs the command"
start_signed_broker /tmp/signed-1.json
docker exec "$HOST" tmb-broker identity --config /tmp/signed-1.json >"$TD/identity.out" 2>&1
sed 's/^/  | /' "$TD/identity.out"
HOSTKEY31=$(sed -n 's/^host_key \([0-9a-f]\{64\}\)$/\1/p' "$TD/identity.out")
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n31.out" 2>"$TD/n31.err" &
CLI31=$!
if wait_queue_json 1; then ok "N31: request waits in the queue"; else bad "N31: request never reached the queue"; fi
jq -c '.items[] | {id, short_code, host_id, host_key, challenge, deadline, token_ttl_seconds}' "$TD/queue.json" | sed 's/^/  | /'
ID31=$(item_by_argv -u)
H31=$(item_field "$ID31" hash)
save_payload "$ID31" "$TD/n31.bin"
if [ "$(head -c 16 "$TD/n31.bin" | tr '\0' '@')" = "tmb-approval-v1@" ]; then ok "N31: payload carries the tmb-approval-v1 domain prefix"; else bad "N31: payload lacks the domain prefix"; fi
P31=$(tail -c +17 "$TD/n31.bin")
if [ "$(jq -r '.host_id' <<<"$P31")" = "$SIG_HOST" ] && [ "$(item_field "$ID31" host_id)" = "$SIG_HOST" ]; then ok "N31: payload and item name host_id $SIG_HOST"; else bad "N31: host_id in payload/item is not $SIG_HOST"; fi
if [ -n "$HOSTKEY31" ] && [ "$(jq -r '.host_key' <<<"$P31")" = "$HOSTKEY31" ]; then ok "N31: payload host_key is the broker identity key (tmb-broker identity)"; else bad "N31: payload host_key '$(jq -r '.host_key' <<<"$P31")' differs from identity '$HOSTKEY31'"; fi
if [ "$(jq -r '.item_id' <<<"$P31")" = "$ID31" ] && [ "$(jq -r '.challenge' <<<"$P31")" = "$(item_field "$ID31" challenge)" ]; then ok "N31: payload binds the item id and its challenge"; else bad "N31: payload item_id/challenge differ from the item"; fi
if [ "$(item_field "$ID31" short_code)" != "null" ] && [ -n "$(item_field "$ID31" short_code)" ]; then ok "N31: item carries a short code"; else bad "N31: item has no short code"; fi
signed_decision "$TD/n31.dec" "$ID31" alice "$TD/n31.bin"
decide "$TD/n31.dec"
assert_rc     "N31: signed approve by alice -> exit 0" 0
assert_out_eq "N31: answer frame decided/approve" '{"type":"decided","detail":"approve"}'
wait $CLI31; RUNC=$?
OUT_FILE=$TD/n31.out; ERR_FILE=$TD/n31.err; show_io
assert_rc     "N31: approved client -> exit 0" 0
assert_out_eq "N31: approved client stdout '0'" "0"
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
if [ "$(journal_count '"event":"approval"' "\"hash\":\"$H31\"" '"decision":"approve"' "$(fp_of alice)")" = 1 ]; then ok "N31: JSONL approval names alice's key"; else bad "N31: JSONL approval with alice's key missing"; fi
if [ "$(journal_count '"event":"exec_exit"' "\"token\":\"$ID31\"")" = 1 ]; then ok "N31: the command ran once (exec_exit for the item)"; else bad "N31: exec_exit for the item missing"; fi
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N32: a signature over another item, host or challenge is refused"
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n32a.out" 2>"$TD/n32a.err" &
CLI32A=$!
wait_queue_json 1 || bad "N32: first request never queued"
docker exec "$SBX" tmb exec --root -- /usr/bin/id -G >"$TD/n32b.out" 2>"$TD/n32b.err" &
CLI32B=$!
if wait_queue_json 2; then ok "N32: two requests wait in the queue"; else bad "N32: the queue never listed two requests"; fi
ID32A=$(item_by_argv -u)
ID32B=$(item_by_argv -G)
R32=$(journal_count '"event":"decision_rejected"' '"reason":"signature_invalid"')
echo "-- foreign item: alice signs item A's payload, the decision names item B"
save_payload "$ID32A" "$TD/n32a.bin"
signed_decision "$TD/n32-item.dec" "$ID32B" alice "$TD/n32a.bin"
decide "$TD/n32-item.dec"
assert_rc      "N32: signature over another item -> exit 125" 125
assert_out_has "N32: foreign item refused with signature_invalid" '"reason":"signature_invalid"'
echo "-- foreign host: item B's payload with another host_id"
save_payload "$ID32B" "$TD/n32b.bin"
forge_payload "$TD/n32b.bin" "$TD/n32-host.bin" "s/\"host_id\":\"$SIG_HOST\"/\"host_id\":\"other-host\"/"
if tail -c +17 "$TD/n32-host.bin" | grep -q '"host_id":"other-host"' && [ "$(wc -c <"$TD/n32-host.bin")" = "$(wc -c <"$TD/n32b.bin")" ]; then ok "N32: forged payload names host other-host"; else bad "N32: host forgery did not apply"; fi
signed_decision "$TD/n32-host.dec" "$ID32B" alice "$TD/n32-host.bin"
decide "$TD/n32-host.dec"
assert_rc      "N32: signature for another host -> exit 125" 125
assert_out_has "N32: foreign host refused with signature_invalid" '"reason":"signature_invalid"'
echo "-- foreign challenge: item B's payload with item A's challenge"
CH32A=$(item_field "$ID32A" challenge)
CH32B=$(item_field "$ID32B" challenge)
forge_payload "$TD/n32b.bin" "$TD/n32-ch.bin" "s/\"challenge\":\"$CH32B\"/\"challenge\":\"$CH32A\"/"
if tail -c +17 "$TD/n32-ch.bin" | grep -q "\"challenge\":\"$CH32A\"" && [ "$(wc -c <"$TD/n32-ch.bin")" = "$(wc -c <"$TD/n32b.bin")" ]; then ok "N32: forged payload carries another challenge"; else bad "N32: challenge forgery did not apply"; fi
signed_decision "$TD/n32-ch.dec" "$ID32B" alice "$TD/n32-ch.bin"
decide "$TD/n32-ch.dec"
assert_rc      "N32: signature over another challenge -> exit 125" 125
assert_out_has "N32: foreign challenge refused with signature_invalid" '"reason":"signature_invalid"'
if [ "$(journal_count '"event":"decision_rejected"' '"reason":"signature_invalid"')" -ge $((R32+3)) ]; then ok "N32: three JSONL decision_rejected with signature_invalid"; else bad "N32: JSONL decision_rejected signature_invalid missing"; fi
queue_json
if [ "$(jq '.items | length' "$TD/queue.json")" = 2 ]; then ok "N32: both items still wait after the refusals"; else bad "N32: refused decisions changed the queue"; fi
signed_decision "$TD/n32-ok.dec" "$ID32B" alice
decide "$TD/n32-ok.dec"
assert_rc "N32: item B's own payload signed -> exit 0" 0
wait $CLI32B; RUNC=$?
OUT_FILE=$TD/n32b.out; ERR_FILE=$TD/n32b.err; show_io
assert_rc "N32: item B ran after the valid signature" 0
OUT_FILE=$TD/n32-no.out; ERR_FILE=$TD/n32-no.err
approve_as human --no "$ID32A" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc "N32: unsigned deny is accepted under require_signed_decision" 0
wait $CLI32A; RUNC=$?
OUT_FILE=$TD/n32a.out; ERR_FILE=$TD/n32a.err; show_io
assert_rc      "N32: item A denied -> exit 125" 125
assert_err_has "N32: deny reason approval_denied_by_human" "approval_denied_by_human"
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N33: a signature presented after the item's deadline does not run anything"
# approval_wait_seconds is 2 here, so the deadline in the payload is 2 s after
# queueing. The fake signer signs in time and presents the signature after
# the deadline: the item has left the queue and the command never runs. A
# decision that reaches an item still queued past its deadline
# (decision_expired) is covered by TestSignedDecideRejections.
start_signed_broker /tmp/signed-short.json
docker exec "$HOST" rm -f /tmp/n33-marker
docker exec "$SBX" tmb exec --root -- /usr/bin/touch /tmp/n33-marker >"$TD/n33.out" 2>"$TD/n33.err" &
CLI33=$!
if wait_queue_json 1; then ok "N33: request waits in the queue"; else bad "N33: request never reached the queue"; fi
ID33=$(item_by_argv /tmp/n33-marker)
H33=$(item_field "$ID33" hash)
save_payload "$ID33" "$TD/n33.bin"
D33=$(tail -c +17 "$TD/n33.bin" | jq -r '.deadline - .queued_at')
if [ "$D33" = 2000 ]; then ok "N33: payload deadline is queued_at + 2000 ms"; else bad "N33: payload deadline - queued_at = $D33 ms, want 2000"; fi
signed_decision "$TD/n33.dec" "$ID33" alice "$TD/n33.bin"
wait $CLI33; RUNC=$?
OUT_FILE=$TD/n33.out; ERR_FILE=$TD/n33.err; show_io
assert_rc      "N33: undecided until the deadline -> exit 125" 125
assert_err_has "N33: deny reason approval_timeout" "approval_timeout"
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
decide "$TD/n33.dec"
assert_rc      "N33: signature presented after the deadline -> exit 1" 1
assert_out_has "N33: the item is gone (no_such_item)" '"reason":"no_such_item"'
host_absent    "N33: marker never created" /tmp/n33-marker
if [ "$(journal_count '"event":"approval"' "\"hash\":\"$H33\"" '"decision":"approve"')" = 0 ]; then ok "N33: no JSONL approve for the expired item"; else bad "N33: JSONL approve logged for the expired item"; fi
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N34: a key not in approver_keys is refused"
start_signed_broker /tmp/signed-1.json
docker exec "$HOST" rm -f /tmp/n34-marker
docker exec "$SBX" tmb exec --root -- /usr/bin/touch /tmp/n34-marker >"$TD/n34.out" 2>"$TD/n34.err" &
CLI34=$!
wait_queue_json 1 || bad "N34: request never reached the queue"
ID34=$(item_by_argv /tmp/n34-marker)
signed_decision "$TD/n34.dec" "$ID34" mallory
decide "$TD/n34.dec"
assert_rc      "N34: signature by mallory (no config entry) -> exit 125" 125
assert_out_has "N34: refused with approver_key_unknown" '"reason":"approver_key_unknown"'
echo "-- mallory's signature under alice's key fingerprint"
decision "$TD/n34-claim.dec" "$ID34" "$(item_field "$ID34" hash)" approve "$(sign_file mallory "$TD/sd-$ID34.bin")" "$(fp_of alice)"
decide "$TD/n34-claim.dec"
assert_rc      "N34: mallory's signature claiming alice's key -> exit 125" 125
assert_out_has "N34: refused with signature_invalid" '"reason":"signature_invalid"'
if [ "$(journal_count '"event":"decision_rejected"' '"reason":"approver_key_unknown"' "$(fp_of mallory)")" -ge 1 ]; then ok "N34: JSONL decision_rejected names mallory's key"; else bad "N34: JSONL decision_rejected approver_key_unknown missing"; fi
approve_as human --no "$ID34" >/dev/null 2>&1
wait $CLI34; RUNC=$?
OUT_FILE=$TD/n34.out; ERR_FILE=$TD/n34.err; show_io
assert_rc   "N34: request denied afterwards -> exit 125" 125
host_absent "N34: marker never created" /tmp/n34-marker
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N35: an unsigned approve under require_signed_decision is refused"
docker exec "$HOST" rm -f /tmp/n35-marker
docker exec "$SBX" tmb exec --root -- /usr/bin/touch /tmp/n35-marker >"$TD/n35.out" 2>"$TD/n35.err" &
CLI35=$!
wait_queue_json 1 || bad "N35: request never reached the queue"
ID35=$(item_by_argv /tmp/n35-marker)
OUT_FILE=$TD/n35y.out; ERR_FILE=$TD/n35y.err
approve_as human --yes "$ID35" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "N35: tmb approve --yes (unsigned) -> exit 125" 125
assert_err_has "N35: refused with signature_required" "signature_required"
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
decision "$TD/n35.dec" "$ID35" "$(item_field "$ID35" hash)" approve
decide "$TD/n35.dec"
assert_rc      "N35: machine-mode approve without a signature -> exit 125" 125
assert_out_has "N35: refused with signature_required" '"reason":"signature_required"'
queue_json
if [ "$(item_field "$ID35" id)" = "$ID35" ]; then ok "N35: the item still waits after the refusals"; else bad "N35: the item left the queue"; fi
decision "$TD/n35-deny.dec" "$ID35" "$(item_field "$ID35" hash)" deny
decide "$TD/n35-deny.dec"
assert_rc     "N35: machine-mode unsigned deny -> exit 0" 0
assert_out_eq "N35: answer frame decided/deny" '{"type":"decided","detail":"deny"}'
wait $CLI35; RUNC=$?
OUT_FILE=$TD/n35.out; ERR_FILE=$TD/n35.err; show_io
assert_rc      "N35: denied client -> exit 125" 125
assert_err_has "N35: deny reason approval_denied_by_human" "approval_denied_by_human"
host_absent    "N35: marker never created" /tmp/n35-marker
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
if [ "$(journal_count '"event":"decision_rejected"' "\"item\":\"$ID35\"" '"reason":"signature_required"')" = 2 ]; then ok "N35: two JSONL decision_rejected with signature_required"; else bad "N35: JSONL decision_rejected signature_required count wrong"; fi
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N36: a used signature does not approve again"
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n36a.out" 2>"$TD/n36a.err" &
CLI36A=$!
wait_queue_json 1 || bad "N36: first request never queued"
ID36=$(item_by_argv -u)
signed_decision "$TD/n36.dec" "$ID36" alice
decide "$TD/n36.dec"
assert_rc "N36: first signed approve -> exit 0" 0
wait $CLI36A; RUNC=$?
OUT_FILE=$TD/n36a.out; ERR_FILE=$TD/n36a.err; show_io
assert_rc "N36: first request ran" 0
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
decide "$TD/n36.dec"
assert_rc      "N36: the same decision again -> exit 1" 1
assert_out_has "N36: replay refused, the item is already decided" '"reason":"already_decided"'
echo "-- the same command again: a new item with a new challenge"
docker exec "$HOST" rm -f /tmp/n36-marker
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n36b.out" 2>"$TD/n36b.err" &
CLI36B=$!
wait_queue_json 1 || bad "N36: second request never queued"
ID36B=$(item_by_argv -u)
if [ -n "$ID36B" ] && [ "$ID36B" != "$ID36" ]; then ok "N36: the repeated command is a new item ($ID36B)"; else bad "N36: no new item for the repeated command"; fi
decision "$TD/n36-replay.dec" "$ID36B" "$(item_field "$ID36B" hash)" approve "$(jq -r .signature "$TD/n36.dec")" "$(fp_of alice)"
decide "$TD/n36-replay.dec"
assert_rc      "N36: the old signature on the new item -> exit 125" 125
assert_out_has "N36: refused with signature_invalid" '"reason":"signature_invalid"'
approve_as human --no "$ID36B" >/dev/null 2>&1
wait $CLI36B; RUNC=$?
OUT_FILE=$TD/n36b.out; ERR_FILE=$TD/n36b.err; show_io
assert_rc "N36: the new item was not approved by the replay (denied, exit 125)" 125
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
if [ "$(journal_count '"event":"exec_start"' "\"token\":\"$ID36\"")" = 1 ] && [ "$(journal_count '"event":"exec_start"' "\"token\":\"$ID36B\"")" = 0 ]; then ok "N36: exactly one exec_start, for the first item only"; else bad "N36: exec_start counts wrong"; fi
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N37: required_signatures 2 needs two different keys"
start_signed_broker /tmp/signed-2.json
docker exec "$SBX" tmb exec --root -- /usr/bin/id -u >"$TD/n37.out" 2>"$TD/n37.err" &
CLI37=$!
wait_queue_json 1 || bad "N37: request never reached the queue"
ID37=$(item_by_argv -u)
H37=$(item_field "$ID37" hash)
if [ "$(item_field "$ID37" signatures_required)" = 2 ]; then ok "N37: the item asks for 2 signatures"; else bad "N37: signatures_required '$(item_field "$ID37" signatures_required)', want 2"; fi
signed_decision "$TD/n37-a.dec" "$ID37" alice
decide "$TD/n37-a.dec"
assert_rc      "N37: alice signs -> exit 0" 0
assert_out_has "N37: answer frame recorded" '"type":"recorded"'
assert_out_has "N37: 1 of 2 signatures" "1 of 2"
queue_json
if [ "$(item_field "$ID37" signatures)" = 1 ]; then ok "N37: the item still waits with 1 signature"; else bad "N37: queue shows signatures '$(item_field "$ID37" signatures)', want 1"; fi
if kill -0 "$CLI37" 2>/dev/null; then ok "N37: the client still waits after one signature"; else bad "N37: the client finished after one signature"; fi
decide "$TD/n37-a.dec"
assert_rc      "N37: alice signs again -> exit 125" 125
assert_out_has "N37: refused with signature_duplicate" '"reason":"signature_duplicate"'
signed_decision "$TD/n37-b.dec" "$ID37" bob
decide "$TD/n37-b.dec"
assert_rc     "N37: bob signs -> exit 0" 0
assert_out_eq "N37: answer frame decided/approve" '{"type":"decided","detail":"approve"}'
wait $CLI37; RUNC=$?
OUT_FILE=$TD/n37.out; ERR_FILE=$TD/n37.err; show_io
assert_rc     "N37: approved client -> exit 0" 0
assert_out_eq "N37: approved client stdout '0'" "0"
OUT_FILE=$TD/last.out; ERR_FILE=$TD/last.err
if [ "$(journal_count '"event":"signature_recorded"' "\"item\":\"$ID37\"" "$(fp_of alice)")" = 1 ]; then ok "N37: JSONL signature_recorded for alice"; else bad "N37: JSONL signature_recorded for alice missing"; fi
if [ "$(journal_count '"event":"approval"' "\"hash\":\"$H37\"" "$(fp_of alice)" "$(fp_of bob)")" = 1 ]; then ok "N37: JSONL approval lists both keys"; else bad "N37: JSONL approval lacks one of the keys"; fi
stop_broker
start_broker mock-approve 10
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N3a: mock-deny -> deny, nothing runs"
stop_broker
start_broker mock-deny "$TTL"
docker exec "$HOST" rm -f /tmp/n3a-marker
run_client "$SBX" tmb exec --root -- /usr/bin/touch /tmp/n3a-marker
assert_rc      "N3a: mock-deny -> exit 125" 125
assert_err_has "N3a: deny reason approval_denied_by_mode" "approval_denied_by_mode"
host_absent    "N3a: marker file never created" /tmp/n3a-marker
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N3b: mock-timeout (ttl=1s) -> deny after timeout, nothing runs"
stop_broker
start_broker mock-timeout 1
docker exec "$HOST" rm -f /tmp/n3b-marker
run_client "$SBX" tmb exec --root -- /usr/bin/touch /tmp/n3b-marker
assert_rc      "N3b: mock-timeout -> exit 125" 125
assert_err_has "N3b: deny reason approval_timeout" "approval_timeout"
host_absent    "N3b: marker file never created" /tmp/n3b-marker
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N8: identical replay request AFTER host-sim container restart -> deny"
stop_broker
start_broker mock-approve "$TTL"
cat >"$TD/n8.json" <<'EOF'
{"type":"exec","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"nonce":"n8-replay-nonce-0008"}
EOF
run_client_json tmb debug raw "$TD/n8.json"
assert_rc     "N8: first run of request (fixed nonce) -> exit 0" 0
assert_out_eq "N8: first run stdout '0'" "0"

echo "-- docker restart $HOST (true container restart; claim store lives in named volume)"
docker restart "$HOST" >/dev/null
start_broker mock-approve "$TTL"

run_client_json tmb debug raw "$TD/n8.json"
assert_rc      "N8: byte-identical replay after restart -> exit 125" 125
assert_err_has "N8: deny reason token_consumed_replay (persistent claim store)" "token_consumed_replay"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N9: broker killed -> agent path FAILS CLOSED; human sudo untouched"

echo "-- killing broker with SIGKILL (stale socket left behind on purpose)"
docker exec "$HOST" pkill -KILL -x tmb-broker
sleep 0.3
run_client "$SBX" tmb exec --root -- /usr/bin/id -u
assert_rc      "N9: broker dead -> client exits 3 (fail closed)" 3
assert_err_has "N9: client says FAIL CLOSED, nothing executed" "FAIL CLOSED"

echo "-- human password sudo in host-sim still works, uid=0"
OUT_FILE=$TD/sudo.out; ERR_FILE=$TD/sudo.err
docker exec -u human "$HOST" sh -c 'echo human | sudo -S id' >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?
show_io
assert_rc      "N9: sudo -S id exit 0" 0
assert_out_has "N9: sudo -S id returns uid=0(root)" "uid=0(root)"

echo "-- /etc/sudo.conf Plugin lines (must be 0) and sudoers.d (stock)"
docker exec "$HOST" sh -c 'echo "Plugin lines in /etc/sudo.conf: $(grep -c "^Plugin" /etc/sudo.conf; true)"; ls -l /etc/sudoers.d' | sed 's/^/  | /'
PLUGIN_N=$(docker exec "$HOST" sh -c 'grep -c "^Plugin" /etc/sudo.conf; true' | tr -d '[:space:]')
if [ "$PLUGIN_N" = "0" ]; then ok "N9: /etc/sudo.conf has ZERO Plugin lines (no TMB sudo plugin)"; else bad "N9: /etc/sudo.conf has $PLUGIN_N Plugin lines"; fi
state_dump

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
echo "RESULT: GREEN - all scenarios behaved exactly as designed"
echo "(full broker JSONL evidence was captured per-scenario above; containers+volumes are wiped by the cleanup trap)"
sleep 1
exit 0
