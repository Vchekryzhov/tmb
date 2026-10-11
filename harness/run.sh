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
cd "$(dirname "$0")"

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

cleanup() {
  echo "=== cleanup ==="
  exec 9>&- 2>/dev/null
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
  local jsonf=${@: -1}
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
  local i
  for i in $(seq 1 150); do
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
  local i
  for i in $(seq 1 150); do
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
docker build -q -f images/Dockerfile.host -t "$IMG_HOST" .. || { echo "FATAL: host image build failed"; exit 1; }
echo "-- building $IMG_SBX"
docker build -q -f images/Dockerfile.sandbox -t "$IMG_SBX" .. || { echo "FATAL: sandbox image build failed"; exit 1; }

echo "-- starting host-sim (root, broker host, normal human sudo present)"
docker run -d --name "$HOST" \
  -v "$SOCK_VOL":/run/tmb \
  -v "$STATE_VOL":/var/lib/tmb-proto \
  "$IMG_HOST" >/dev/null || { echo "FATAL: host-sim run failed"; exit 1; }
echo "-- starting sandbox-sim (uid 4242, --network none, no docker.sock, no host mounts)"
docker run -d --name "$SBX" \
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
  local i n
  for i in $(seq 1 150); do
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
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"env":{"LANG":"C.UTF-8"},"nonce":"n1-nonce-fixed-000001"}
EOF
cat >"$TD/n1-b.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-G"],"cwd":"/tmp","uid":0,"env":{"LANG":"C.UTF-8"},"nonce":"n1-nonce-fixed-000001"}
EOF
run_client_json tmb approve "$TD/n1-a.json"
assert_rc "N1: approve phase ok" 0
T1=$(token_of)
echo "-- token from approve: ${T1:-<none>}"
if [ -n "$T1" ]; then ok "N1: got one-shot token $T1"; else bad "N1: no token parsed"; fi
run_client_json tmb claim --token "$T1" "$TD/n1-b.json"
assert_rc      "N1: claim with same token but different argv -> exit 125" 125
assert_err_has "N1: deny reason token_binding_mismatch" "token_binding_mismatch"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO N2: token/nonce REPLAY (same token, same request, twice) -> deny 2nd"
cat >"$TD/n2.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"env":{"LANG":"C.UTF-8"},"nonce":"n2-nonce-fixed-000002"}
EOF
run_client_json tmb approve "$TD/n2.json"
assert_rc "N2: approve phase ok" 0
T2=$(token_of)
run_client_json tmb claim --token "$T2" "$TD/n2.json"
assert_rc     "N2: first claim executes, exit 0" 0
assert_out_eq "N2: first claim stdout '0'" "0"
run_client_json tmb claim --token "$T2" "$TD/n2.json"
assert_rc      "N2: replay claim -> exit 125" 125
assert_err_has "N2: deny reason token_consumed_replay" "token_consumed_replay"
state_dump

# -----------------------------------------------------------------------------
log "SCENARIO TTL: token claimed AFTER expiry -> deny, nothing runs (ttl=${TTL}s, no 60s sleeps)"
docker exec "$HOST" rm -f /tmp/ttl-marker
cat >"$TD/ttl.json" <<'EOF'
{"type":"approve","executable":"/usr/bin/touch","argv":["/usr/bin/touch","/tmp/ttl-marker"],"cwd":"/tmp","uid":0,"env":{"LANG":"C.UTF-8"},"nonce":"ttl-nonce-fixed-0003"}
EOF
run_client_json tmb approve "$TD/ttl.json"
assert_rc "TTL: approve phase ok" 0
TT=$(token_of)
echo "-- sleeping $((TTL+2))s to let the token expire (ttl=$TTL s)"
sleep $((TTL+2))
run_client_json tmb claim --token "$TT" "$TD/ttl.json"
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
assert_out_has  "N5a: child env has allowlisted LANG" "LANG=C.UTF-8"
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
run_client_json tmb raw "$TD/n6.json"
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
{"type":"approve","executable":"/usr/bin/id","argv":["/usr/bin/id","-u"],"cwd":"/tmp","uid":0,"env":{"LANG":"C.UTF-8"},"nonce":"n10-nonce-fixed-000010"}
EOF
run_client_json tmb approve "$TD/n10.json"
assert_rc "N10: approve phase ok (requester uid 4242)" 0
T10=$(token_of)
echo "-- token from approve: ${T10:-<none>}"
if [ -n "$T10" ]; then ok "N10: got one-shot token $T10"; else bad "N10: no token parsed"; fi
docker exec -i -u 4343:4242 "$SBX" tmb claim --token "$T10" --json - <"$TD/n10.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
assert_rc      "N10: claim under OTHER allowlisted uid 4343 -> exit 125" 125
assert_err_has "N10: deny reason requester_mismatch" "requester_mismatch"
docker exec -i "$SBX" tmb claim --token "$T10" --json - <"$TD/n10.json" >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
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
{"type":"approve","executable":"/tmp/n11/prog","argv":["/tmp/n11/prog","A"],"cwd":"/tmp","uid":0,"env":{"LANG":"C.UTF-8"},"nonce":"n11-nonce-fixed-000011"}
EOF
run_client_json tmb approve "$TD/n11.json"
assert_rc "N11: approve phase ok" 0
T11=$(token_of)
if [ -n "$T11" ]; then ok "N11: got one-shot token $T11"; else bad "N11: no token parsed"; fi
echo "-- arming in-window swapper (SIGSTOP broker at claim-file creation)"
docker exec "$HOST" sh -c '
  BEFORE=0
  for f in /var/lib/tmb-proto/claims/*; do [ -e "$f" ] && BEFORE=$((BEFORE+1)); done
  BPID=$(pgrep -x tmb-broker)
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
run_client_json tmb claim --token "$T11" "$TD/n11.json"
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
{"type":"approve","executable":"/bin/ls","argv":["/bin/ls"],"cwd":"/tmp/n12-dir","uid":0,"env":{"LANG":"C.UTF-8"},"nonce":"n12-nonce-fixed-000012"}
EOF
run_client_json tmb approve "$TD/n12.json"
assert_rc "N12: approve phase ok" 0
T12=$(token_of)
if [ -n "$T12" ]; then ok "N12: got one-shot token $T12"; else bad "N12: no token parsed"; fi
docker exec "$HOST" sh -c 'mv /tmp/n12-dir /tmp/n12-dir.old && mkdir /tmp/n12-dir && touch /tmp/n12-dir/new-marker'
if docker exec "$HOST" test -e /tmp/n12-dir.old/old-marker; then ok "N12: cwd really replaced (old dir moved aside, new inode at the same path)"; else bad "N12: cwd replacement did not happen"; fi
run_client_json tmb claim --token "$T12" "$TD/n12.json"
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
run_client_json tmb raw "$TD/n8.json"
assert_rc     "N8: first run of request (fixed nonce) -> exit 0" 0
assert_out_eq "N8: first run stdout '0'" "0"

echo "-- docker restart $HOST (true container restart; claim store lives in named volume)"
docker restart "$HOST" >/dev/null
start_broker mock-approve "$TTL"

run_client_json tmb raw "$TD/n8.json"
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
