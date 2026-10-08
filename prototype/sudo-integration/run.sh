#!/usr/bin/env bash
# PROTOTYPE (THROWAWAY) one-command runner for the TMB sudo integration
# question (issue #1). Builds the test image, runs the full scenario matrix
# inside a disposable UNPRIVILEGED container, restarts it to prove crash
# resilience of permission redemption, then removes everything it created.
# Idempotent: safe to run repeatedly. See README-PROTOTYPE.md and VERDICT.md.
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="tmb-proto:sudo-integration"
CONTAINER="tmb-proto-container-wipe-me"
VOLUME="tmb-proto-state-wipe-me"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> [1/6] building image $IMAGE (ubuntu:24.04, arm64)"
docker build -q -t "$IMAGE" .

echo "==> [2/6] fresh state volume + disposable unprivileged container"
cleanup   # idempotent: drop leftovers from any previous run
: > last-run.log
docker volume create "$VOLUME" >/dev/null
docker run -d --name "$CONTAINER" --hostname tmbproto \
  --volume "$VOLUME:/var/lib/tmb-proto" \
  "$IMAGE" >/dev/null
echo "    container: $CONTAINER (no --privileged, no docker.sock, no host path mounts)"

echo "==> [3/6] scenario matrix, phase 1 (fresh container)"
docker exec "$CONTAINER" /usr/local/tmb/bin/run-matrix phase1 2>&1 | tee -a last-run.log

echo "==> [4/6] docker restart $CONTAINER (crash resilience)"
docker restart "$CONTAINER" >/dev/null

echo "==> [5/6] scenario matrix, phase 2 (same container after restart, persisted volume)"
docker exec "$CONTAINER" /usr/local/tmb/bin/run-matrix phase2 2>&1 | tee -a last-run.log

echo "==> [6/6] cleanup (container + state volume removed; image kept for fast re-run)"
cleanup
trap - EXIT

echo
echo "ALL SCENARIOS PASSED - full log: $(pwd)/last-run.log"
echo "To also remove the image: docker rmi $IMAGE"
