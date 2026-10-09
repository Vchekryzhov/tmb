#!/usr/bin/env bash
# PROTOTYPE runner - throwaway PoC, not production.
#
# run-openshell.sh: ticket #8 - raises the FULL OpenShell topology from
# scratch on macOS + Docker Desktop:
#
#   Mac (gateway, native binary, :17670)
#    -> Docker Desktop VM
#        -> host-sim container (tmb-broker, TLS listener :17600 published
#           on ALL interfaces of the VM)
#        -> supervisor container (host-networked, per sandbox)
#        -> sandbox container (opencode image + static tmb client, NET=none,
#           deny-by-default egress, ONE network rule:
#           protocol: tcp + tls: skip -> host.openshell.internal:17600)
#
# host.openshell.internal resolves (via the supervisor's policy DNS) to the
# VM loopback pinned by the docker driver from grpc_endpoint; the published
# broker port answers there. See README-PROTOTYPE.md for the full story and
# the deviations (sandbox is created WITHOUT a policy and the single rule is
# hot-added immediately after - `sandbox create --policy` hits an upstream
# 0.1.3 spawn failure on Docker Desktop; deny-by-default holds throughout).
#
# Prerequisites verified in O0: openshell 0.1.3, Docker Desktop host
# networking ON + ECI OFF, opencode base image pinned by digest, gateway
# Connected. The gateway's docker grpc_endpoint must be an IPv4/localhost
# value (https://127.0.0.1:17671) so the driver pins host.openshell.internal;
# ensure_gateway_reach() patches ~/.config/openshell/gateway.toml (backup
# kept) and restarts the brew service, then manages a tiny socat forwarder
# (VM loopback :17671 -> host.docker.internal:17670 -> Mac gateway).
#
# Everything is logged to last-openshell-run.log (tee'd). Certificates are
# generated per run into a temp dir; the CA key never enters any image.
# Idempotent: pre-clean removes leftovers from previous runs first.

set -u
cd "$(dirname "$0")"

# ---------------------------------------------------------------- pins ----
OPENSHELL_VERSION=0.1.3
# linux/arm64 manifest digest of ghcr.io/anomalyco/opencode:latest,
# resolved 2026-10-09 via `docker manifest inspect` (index -> arm64 entry).
# Keep in sync with harness/images/Dockerfile.opensbx (FROM line).
OPENCODE_IMAGE_REF=ghcr.io/anomalyco/opencode@sha256:6911572e4a9b3ead5e4086b40e2c98bd82075dae617aff679767f358cf8f374e

SERVER_NAME=host.openshell.internal
TLS_PORT=17600                 # broker TLS listener (published on 0.0.0.0 of the VM)
GW_REACH_PORT=17671            # VM-loopback forwarder port -> Mac gateway :17670
TTL=3

RUNID=$(date +%s)-$$
HOST=tmb-osh-host
# openshell caps sandbox names at 19 chars: "tmb8-" + base36(epoch) +
# 3-char base36 pid tail fits with room for the -r1/-r2 retry suffixes.
to36() { local n=$1 d="0123456789abcdefghijklmnopqrstuvwxyz" out=""; while [ "$n" -gt 0 ]; do out="${d:$((n%36)):1}$out"; n=$((n/36)); done; printf '%s' "$out"; }
SBX=tmb8-$(to36 "$(date +%s)")$(to36 $$ | tail -c 4 | sed 's/^/p/')
GWREACH=tmb-osh-gwreach
IMG_HOST=tmb-poc/host-sim                    # same Dockerfile.host as run-pair.sh
IMG_SBX_BASE=tmb-osh-sbx-base                # opencode + openssl + tmb (cacheable)
IMG_SBX=tmb-osh-sbx:$RUNID                   # + per-run certs (removed on cleanup)
IMG_GWREACH=tmb-osh-gwreach-img              # socat forwarder (cacheable)
SOCK_VOL=tmb-osh-sock-$RUNID-wipe-me
STATE_VOL=tmb-osh-state-$RUNID-wipe-me
TD=$(mktemp -d /tmp/tmb-osh.XXXXXX)
LOG=last-openshell-run.log
GATEWAY_TOML="$HOME/.config/openshell/gateway.toml"

PASS=0
FAIL=0
ROWS=()
SBX_CREATED=""

exec > >(tee "$LOG") 2>&1

cleanup() {
  echo "=== cleanup ==="
  if [ -n "$SBX_CREATED" ]; then
    timeout 60 openshell sandbox delete "$SBX_CREATED" >/dev/null 2>&1 \
      && echo "-- sandbox $SBX_CREATED deleted" || echo "-- WARN: sandbox $SBX_CREATED not deleted (already gone?)"
  fi
  docker rm -f "$HOST" >/dev/null 2>&1 && echo "-- container $HOST removed"
  docker volume rm -f "$SOCK_VOL" "$STATE_VOL" >/dev/null 2>&1
  docker rmi "$IMG_SBX" >/dev/null 2>&1 && echo "-- image $IMG_SBX removed (per-run certs gone)"
  # The forwarder is part of the raised topology: remove the container so
  # `docker ps` is clean; its image and the gateway.toml endpoint stay (the
  # next run - and ticket #9 - re-ensure them in ensure_gateway_reach).
  docker rm -f "$GWREACH" >/dev/null 2>&1 && echo "-- forwarder $GWREACH removed"
  rm -rf "$TD"
}
trap cleanup EXIT

log() { printf '\n================================================================\n== %s\n================================================================\n' "$*"; }

ok()  { PASS=$((PASS+1)); ROWS+=("PASS | $1"); printf 'CHECK PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); ROWS+=("FAIL | $1"); printf 'CHECK FAIL: %s\n' "$1"; }

fatal() { echo "FATAL: $*"; exit 1; }

# retry CMD... : up to 3 attempts with a pause (transient docker/network)
retry() {
  local i rc
  for i in 1 2 3; do
    "$@"; rc=$?
    [ $rc -eq 0 ] && return 0
    echo "-- retry $i/3 failed (rc=$rc), pausing before next attempt"
    sleep 3
  done
  return $rc
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

# sbx_exec CMD... : `openshell sandbox exec <sbx> --` (the O-series seam)
sbx_exec() {
  timeout 90 openshell sandbox exec "$SBX" --no-login-shell -- "$@" \
    >"$OUT_FILE" 2>"$ERR_FILE"; RUNC=$?; show_io
}

# =============================================================================
log "TMB OPENSHELL RUNNER: ticket #8 topology ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
docker version --format 'docker {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})' || fatal "docker not reachable"
command -v openssl >/dev/null || fatal "openssl is required on the harness host"
command -v python3 >/dev/null || fatal "python3 is required (Docker Desktop settings + policy merge)"
echo "workdir: $(pwd), cert dir: $TD (temp, never committed), run id: $RUNID"

# -----------------------------------------------------------------------------
log "STAGE 0: pre-clean leftovers from previous runs"

for s in $(timeout 30 openshell sandbox list -o json 2>/dev/null \
           | python3 -c 'import json,sys
try:
    for x in json.load(sys.stdin):
        n = x.get("name","")
        if n.startswith("tmb8-") or n.startswith("tmb-osh-sbx-"): print(n)
except Exception:
    pass'); do
  echo "-- deleting stale sandbox $s"
  timeout 60 openshell sandbox delete "$s" >/dev/null 2>&1
done
docker rm -f "$HOST" "$GWREACH" >/dev/null 2>&1

# -----------------------------------------------------------------------------
log "STAGE 1: O0 prerequisites (any failure aborts the run)"

echo "-- O0: openshell version pin"
OSV=$(openshell --version 2>/dev/null | awk '{print $2}')
if [ "$OSV" = "$OPENSHELL_VERSION" ]; then
  ok "O0: openshell version == $OPENSHELL_VERSION"
else
  bad "O0: openshell version is '$OSV', want $OPENSHELL_VERSION"; fatal "version pin failed"
fi

echo "-- O0: Docker Desktop settings (host networking ON, ECI OFF)"
DD_SETTINGS="$HOME/Library/Group Containers/group.com.docker/settings-store.json"
python3 - "$DD_SETTINGS" <<'PYEOF' || fatal "Docker Desktop settings check failed (see above)"
import json, sys, os
path = os.path.expanduser(sys.argv[1])
try:
    d = json.load(open(path))
except FileNotFoundError:
    print(f"FATAL: {path} not found - is this Docker Desktop?"); sys.exit(1)
host_net = d.get("HostNetworkingEnabled", False)   # Docker default is false
eci = d.get("EnhancedContainerIsolation", False)   # Docker default is false
errs = []
if host_net is not True:
    errs.append("HostNetworkingEnabled is not true (Settings > Resources > Network > Host networking)")
if eci is not False:
    errs.append("EnhancedContainerIsolation is true (must be OFF for OpenShell sandboxes)")
if errs:
    for e in errs: print(f"FATAL: {e}")
    sys.exit(1)
print("settings ok: HostNetworkingEnabled=true, EnhancedContainerIsolation=false")
PYEOF
ok "O0: Docker Desktop host networking ON, ECI OFF"

echo "-- O0: opencode base image pinned by digest, present locally"
if docker image inspect "$OPENCODE_IMAGE_REF" >/dev/null 2>&1; then
  ok "O0: local image matches $OPENCODE_IMAGE_REF"
else
  echo "-- pulling pinned base image (was not cached)..."
  retry docker pull -q "$OPENCODE_IMAGE_REF" \
    && ok "O0: pulled $OPENCODE_IMAGE_REF" \
    || { bad "O0: cannot obtain $OPENCODE_IMAGE_REF"; fatal "base image pin failed"; }
fi
docker image inspect "$OPENCODE_IMAGE_REF" --format 'base: {{.Os}}/{{.Architecture}}' | sed 's/^/  | /'

echo "-- O0: stdlib-only dependency surface (go list -m all in src/)"
GOLIST=$(retry docker run --rm -e GOCACHE=/tmp/gocache \
  -v "$(cd .. && pwd)/src":/src:ro -w /src golang:1.23-alpine go list -m all 2>/dev/null)
echo "$GOLIST" | sed 's/^/  | /'
if [ "$(echo "$GOLIST" | tr -d '[:space:]')" = "tmb-poc" ]; then
  ok "O0: go list -m all -> only tmb-poc (stdlib only)"
else
  bad "O0: go list -m all -> '$GOLIST' (want only tmb-poc)"; fatal "dependency surface grew"
fi

# -----------------------------------------------------------------------------
log "STAGE 2: gateway reach (host.openshell.internal pin + VM-loopback forwarder)"

# The docker driver pins host.openshell.internal from the supervisor
# grpc_endpoint ONLY when it is an IPv4/localhost value; with the native Mac
# gateway that endpoint must be a VM-loopback forwarder back to the Mac.
ensure_gateway_reach() {
  # forwarder image + container (VM loopback :GW_REACH_PORT -> Mac gateway)
  docker image inspect "$IMG_GWREACH" >/dev/null 2>&1 \
    || retry docker build -q -t "$IMG_GWREACH" - <<'EOF' || return 1
FROM alpine:3.19
RUN apk add --no-cache socat
ENTRYPOINT ["socat","-d","-d","TCP-LISTEN:17671,bind=127.0.0.1,fork,reuseaddr","TCP:host.docker.internal:17670"]
EOF
  docker rm -f "$GWREACH" >/dev/null 2>&1
  docker run -d --name "$GWREACH" --network host --cap-drop ALL \
    --security-opt no-new-privileges:true "$IMG_GWREACH" >/dev/null || return 1
  # docker Desktop proxies host-networked listeners to the Mac loopback, so
  # the gateway itself must NOT collide with :17670 on the Mac - it does not
  # (it binds *:17670 and the forwarder listens on :17671 inside the VM).
  if ! grep -q 'grpc_endpoint = "https://127.0.0.1:'"$GW_REACH_PORT"'"' "$GATEWAY_TOML" 2>/dev/null; then
    echo "-- patching $GATEWAY_TOML grpc_endpoint -> https://127.0.0.1:$GW_REACH_PORT (backup kept)"
    cp "$GATEWAY_TOML" "$GATEWAY_TOML.pre-tmb8.bak" 2>/dev/null || true
    python3 - "$GATEWAY_TOML" "$GW_REACH_PORT" <<'PYEOF' || return 1
import sys, re
path, port = sys.argv[1], sys.argv[2]
s = open(path).read()
new = f'grpc_endpoint = "https://127.0.0.1:{port}"'
if "grpc_endpoint" in s:
    s = re.sub(r'grpc_endpoint\s*=\s*"[^"]*"', new, s, count=1)
else:
    s += f"\n[openshell.drivers.docker]\n{new}\n"
open(path, "w").write(s)
PYEOF
    brew services restart openshell >/dev/null 2>&1 || return 1
  fi
  # wait for Connected
  local i
  for i in $(seq 1 12); do
    timeout 30 openshell status 2>/dev/null | grep -q "Status: Connected" && return 0
    sleep 5
  done
  return 1
}

if ensure_gateway_reach; then
  ok "GW: gateway Connected via https://127.0.0.1:$GW_REACH_PORT (forwarder $GWREACH up)"
else
  bad "GW: gateway reach setup failed"
  fatal "gateway not reachable through the VM-loopback forwarder; see README-PROTOTYPE.md (Дверь в VM)"
fi

# -----------------------------------------------------------------------------
log "STAGE 3: harness CA + server + client certs into $TD (run-pair recipe)"

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
  -subj "/CN=TMB OpenShell Harness CA" \
  -config "$TD/openssl.cnf" -extensions v3_ca >/dev/null 2>&1 \
  || fatal "CA generation failed"

openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -keyout "$TD/server.key" -out "$TD/server.csr" \
  -subj "/CN=$SERVER_NAME" -config "$TD/openssl.cnf" >/dev/null 2>&1
openssl x509 -req -sha256 -days 2 -in "$TD/server.csr" \
  -CA "$TD/ca.crt" -CAkey "$TD/ca.key" -CAcreateserial \
  -out "$TD/server.crt" -extfile "$TD/openssl.cnf" -extensions ext_server >/dev/null 2>&1 \
  || fatal "server certificate failed"

openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -keyout "$TD/client1.key" -out "$TD/client1.csr" \
  -subj "/CN=tmb-osh-client1" -config "$TD/openssl.cnf" >/dev/null 2>&1
openssl x509 -req -sha256 -days 2 -in "$TD/client1.csr" \
  -CA "$TD/ca.crt" -CAkey "$TD/ca.key" -CAcreateserial \
  -out "$TD/client1.crt" -extfile "$TD/openssl.cnf" -extensions ext_client >/dev/null 2>&1 \
  || fatal "client1 certificate failed"

fp_of() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 \
    | sed -n 's/^.*Fingerprint=//p' | tr -d ':' | tr 'A-F' 'a-f'
}
FP1=$(fp_of "$TD/client1.crt")
echo "-- fp1=$FP1 (the ONLY allowlisted requester identity)"
[ "${#FP1}" = 64 ] || fatal "fingerprint must be 64 hex chars"

cat > "$TD/config-osh.json" <<EOF
{
  "_comment": "generated by run-openshell.sh into a temp dir; never committed",
  "socket_path": "/run/tmb/tmb.sock",
  "state_dir": "/var/lib/tmb-proto",
  "log_path": "/var/log/tmb/broker.log",
  "pid_file": "/var/run/tmb-broker.pid",
  "allowed_requester_uids": [4242],
  "allowed_requester_fps": ["$FP1"],
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
    "/usr/bin/tcsh", "/usr/bin/csh", "/bin/csh", "/usr/bin/busybox"
  ],
  "token_ttl_seconds": $TTL,
  "approval_default": "mock-approve",
  "tls_addr": ":$TLS_PORT",
  "tls_ca_file": "/etc/tmb/certs/ca.crt",
  "tls_cert_file": "/etc/tmb/certs/server.crt",
  "tls_key_file": "/etc/tmb/certs/server.key"
}
EOF

# ca.key stays 0600 on the host and is never mounted or baked anywhere;
# the sandbox image gets ONLY ca.crt + client1.crt + client1.key (see STAGE 4).
chmod 644 "$TD/ca.crt" "$TD/server.crt" "$TD/server.key" \
  "$TD/client1.crt" "$TD/client1.key" "$TD/config-osh.json"
chmod 600 "$TD/ca.key"

# -----------------------------------------------------------------------------
log "STAGE 4: images"

echo "-- host-sim image (existing images/Dockerfile.host, context: repo root)"
retry docker build -q -f images/Dockerfile.host -t "$IMG_HOST" .. \
  || fatal "host image build failed"

echo "-- sandbox base image (opencode@$OPENCODE_IMAGE_REF + openssl + tmb)"
retry docker build -q -f images/Dockerfile.opensbx -t "$IMG_SBX_BASE" .. \
  || fatal "sandbox base image build failed"

echo "-- per-run cert layer (context: $TD; the ONLY place certs enter an image)"
cat > "$TD/Dockerfile.certs" <<EOF
FROM $IMG_SBX_BASE
USER root
COPY ca.crt client1.crt client1.key /usr/share/tmb/certs/
RUN chmod 0644 /usr/share/tmb/certs/ca.crt /usr/share/tmb/certs/client1.crt /usr/share/tmb/certs/client1.key
USER sandbox
EOF
retry docker build -q -f "$TD/Dockerfile.certs" -t "$IMG_SBX" "$TD" \
  || fatal "sandbox cert layer build failed"

echo "-- O0: sandbox image has sh, id, test, openssl (run refuses to start without them)"
TOOLS_OK=1
for tool in sh id test openssl; do
  if docker run --rm --entrypoint sh "$IMG_SBX" -c "command -v $tool" >/dev/null 2>&1; then
    ok "O0: sandbox image has $tool"
  else
    bad "O0: sandbox image lacks $tool"; TOOLS_OK=0
  fi
done
[ "$TOOLS_OK" = 1 ] || fatal "O0 tool check failed"
docker run --rm --entrypoint sh "$IMG_SBX" -c 'command -v tmb && tmb -h >/dev/null 2>&1 && echo "  | tmb client: $(tmb -h 2>&1 | head -1)"' | sed 's/^/  | /'

# -----------------------------------------------------------------------------
log "STAGE 5: topology up (host-sim broker + sandbox + single rule)"

echo "-- host-sim: broker host, TLS port $TLS_PORT published on ALL VM interfaces"
retry docker run -d --name "$HOST" \
  -p "${TLS_PORT}:${TLS_PORT}" \
  -v "$SOCK_VOL":/run/tmb \
  -v "$STATE_VOL":/var/lib/tmb-proto \
  -v "$TD/ca.crt":/etc/tmb/certs/ca.crt:ro \
  -v "$TD/server.crt":/etc/tmb/certs/server.crt:ro \
  -v "$TD/server.key":/etc/tmb/certs/server.key:ro \
  -v "$TD/config-osh.json":/etc/tmb/config-osh.json:ro \
  "$IMG_HOST" >/dev/null || fatal "host-sim run failed"

echo "-- broker: TLS listener (mock-approve, ttl=${TTL}s)"
docker exec -d "$HOST" tmb-broker -approval mock-approve -ttl "$TTL" -config /etc/tmb/config-osh.json

broker_log_count() { docker exec "$HOST" sh -c "grep -c '$1' /var/log/tmb/broker.log" 2>/dev/null | tr -d '[:space:]'; }
wait_broker_log_count() {
  local i pat=$1 want=$2
  for i in $(seq 1 150); do
    [ "$(broker_log_count "$pat")" -ge "$want" ] 2>/dev/null && return 0
    sleep 0.1
  done
  echo "FATAL: broker.log never reached $want x '$pat'"; docker exec "$HOST" sh -c 'tail -5 /var/log/tmb/broker.log' 2>/dev/null; return 1
}
wait_broker_log_count '"event":"tls_listen"' 1 || fatal "broker TLS listener never came up"
ok "TOP: broker logged tls_listen on :$TLS_PORT"
docker exec "$HOST" grep '"event":"tls_listen"' /var/log/tmb/broker.log | tail -1 | sed 's/^/  | /'

echo "-- sandbox: create (block mode; the single rule is hot-added next - see README deviations)"
#  NOTE: `sandbox create --policy <file>` hits an upstream OpenShell 0.1.3
#  failure on Docker Desktop (workload spawn EACCES in proxy mode), so the
#  sandbox is created with the deny-by-default builtin policy and the ONE
#  rule is applied live via `openshell policy set` (hot-add is the ADR 0003
#  anticipated path: "TCP-endpoint добавляется в живую песочницу").
sandbox_create() { # $1 = name ; rc 0 on Ready
  local name=$1 i
  timeout 120 openshell sandbox create --name "$name" \
    --from "$IMG_SBX" \
    --env "TMB_ADDR=$SERVER_NAME:$TLS_PORT" \
    --env "TMB_CA=/usr/share/tmb/certs/ca.crt" \
    --env "TMB_CERT=/usr/share/tmb/certs/client1.crt" \
    --env "TMB_KEY=/usr/share/tmb/certs/client1.key" \
    --detach -- sleep infinity >"$TD/create.out" 2>&1 || { sed 's/^/  | /' "$TD/create.out"; return 1; }
  for i in $(seq 1 40); do
    timeout 30 openshell sandbox get "$name" -o json 2>/dev/null \
      | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(1)
raise SystemExit(0 if any(c.get("type")=="Ready" and c.get("status")=="True" for c in d.get("conditions",[])) else 1)' && return 0
    sleep 1
  done
  echo "-- sandbox $name never reached Ready; last status:"; timeout 30 openshell logs "$name" -n 12 --source all 2>/dev/null | sed 's/^/  | /' | tail -8
  timeout 60 openshell sandbox delete "$name" >/dev/null 2>&1
  return 1
}

SBX_TRIES="$SBX ${SBX}-r1 ${SBX}-r2"
SBX_CREATED=""
for cand in $SBX_TRIES; do
  echo "-- create attempt: $cand"
  if sandbox_create "$cand"; then SBX_CREATED="$cand"; SBX="$cand"; break; fi
  echo "-- attempt $cand failed; retrying with a fresh name"
done
[ -n "$SBX_CREATED" ] || fatal "sandbox never reached Ready (3 attempts)"
ok "TOP: sandbox $SBX Ready (opencode image, uid 1000, NET=none)"
timeout 30 openshell sandbox exec "$SBX" --no-login-shell -- id | sed 's/^/  | /'

echo "-- sandbox policy: hot-add the SINGLE rule (protocol: tcp + tls: skip)"
#  Merge into the live policy (preserving the runtime filesystem policy) and
#  apply with `policy set` - a full replacement that would otherwise be
#  rejected for removing filesystem paths. JSON is valid YAML, so the merged
#  document is emitted as JSON.
timeout 30 openshell policy get "$SBX" --full -o json > "$TD/policy-live.json" 2>/dev/null || fatal "policy get failed"
python3 - "$TD/policy-live.json" "$TD/policy-tmb.json" "$TLS_PORT" <<'PYEOF' || fatal "policy merge failed"
import json, sys
src, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
doc = json.load(open(src))["policy"]
doc["network_policies"] = {
    "tmb": {
        "endpoints": [{
            "host": "host.openshell.internal",
            "port": port,
            "protocol": "tcp",
            "tls": "skip",
        }],
        "binaries": [{"path": "/usr/local/bin/tmb"}],
    }
}
json.dump(doc, open(dst, "w"), indent=1)
PYEOF
timeout 90 openshell policy set "$SBX" --policy "$TD/policy-tmb.json" --wait >/dev/null 2>&1 \
  || fatal "policy set failed"

echo "-- verify effective policy: exactly one rule, tcp + tls skip, binary tmb"
timeout 30 openshell policy get "$SBX" --full -o json > "$TD/policy-eff.json" 2>/dev/null
python3 - "$TD/policy-eff.json" "$TLS_PORT" <<'PYEOF' && ok "TOP: effective policy = single rule tcp+tls:skip -> $SERVER_NAME:$TLS_PORT (binary /usr/local/bin/tmb)" || bad "TOP: effective policy shape unexpected (see above)"
import json, sys
doc = json.load(open(sys.argv[1]))["policy"]
port = int(sys.argv[2])
np = doc.get("network_policies", {})
assert list(np.keys()) == ["tmb"], f"rules: {list(np.keys())}"
e = np["tmb"]["endpoints"]
assert len(e) == 1 and e[0].get("host") == "host.openshell.internal", e
assert e[0].get("port") == port and e[0].get("protocol") == "tcp", e
assert e[0].get("tls") == "skip", e
assert np["tmb"]["binaries"] == [{"path": "/usr/local/bin/tmb"}], np["tmb"]
PYEOF
echo "-- effective network policy:"
python3 -c 'import json; print(json.dumps(json.load(open("'"$TD"'/policy-eff.json"))["policy"]["network_policies"], indent=1))' | sed 's/^/  | /'

# -----------------------------------------------------------------------------
log "SCENARIO O2a: tmb exec over mTLS from the sandbox, mock-approve"

sbx_exec tmb exec --root -- /usr/bin/id -u
assert_rc    "O2a: exit code 0" 0
assert_out_eq "O2a: stdout is exactly '0'" "0"
echo "-- broker JSONL (request..exec_exit) for the O2a call:"
docker exec "$HOST" grep -E '"event":"(request|approval|claim|exec_start|exec_exit)"' /var/log/tmb/broker.log 2>/dev/null | tail -5 | sed 's/^/  | /'

# -----------------------------------------------------------------------------
log "SCENARIO O3: host isolation from inside the sandbox"

sbx_exec id -u
if [ "$RUNC" = "0" ] && [ "$(cat "$OUT_FILE" 2>/dev/null)" != "0" ] && [ -n "$(cat "$OUT_FILE" 2>/dev/null)" ]; then
  ok "O3: sbx-exec id -u != 0 (uid $(cat "$OUT_FILE" 2>/dev/null))"
else
  bad "O3: sbx-exec id -u is 0 or failed (rc=$RUNC, stdout='$(cat "$OUT_FILE" 2>/dev/null)')"
fi

sbx_exec sh -c 'command -v sudo && sudo -n true'
if [ "$RUNC" != "0" ]; then
  ok "O3: sudo path absent or no passwordless sudo (rc=$RUNC)"
else
  bad "O3: command -v sudo && sudo -n true returned 0"
fi

sbx_exec test -e /run/tmb/tmb.sock
assert_rc "O3: test -e /run/tmb/tmb.sock -> exit 1 (socket absent)" 1

sbx_exec sh -c 'mount | grep -c " /run/tmb " || true'
if [ "$(cat "$OUT_FILE" 2>/dev/null)" = "0" ]; then
  ok "O3: no /run/tmb mount inside the sandbox (mount|grep -c -> 0)"
else
  bad "O3: /run/tmb mount count is '$(cat "$OUT_FILE" 2>/dev/null)', want 0"
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
echo "RESULT: GREEN - sandbox reaches the broker through exactly one rule; host stays isolated"
echo "(certs were generated into $TD and wiped by the cleanup trap; per-run image removed; CA key never entered any image)"
sleep 1
exit 0
