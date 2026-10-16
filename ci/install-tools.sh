#!/usr/bin/env bash
# Installs the pinned CI tools into $1 (default out/ci/bin):
#   - Go tools are built from their own pinned module in ci/tools/<name>
#     (go.sum verified, GOFLAGS=-mod=readonly), never `go install @latest`;
#   - binary tools are downloaded from ci/tools.lock and verified by SHA-256
#     before they are unpacked or executed.
# Nothing is cached between CI runs.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${1:-$ROOT/out/ci/bin}
mkdir -p "$BIN"
BIN=$(cd "$BIN" && pwd)

case "$(uname -s)" in Linux) OS=linux ;; Darwin) OS=darwin ;; *) echo "unsupported OS" >&2; exit 2 ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; arm64|aarch64) ARCH=arm64 ;; *) echo "unsupported arch" >&2; exit 2 ;; esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# tmbci: the CI checker itself, stdlib-only module ci/
(cd "$ROOT/ci" && GOFLAGS=-mod=readonly CGO_ENABLED=0 go build -trimpath -o "$BIN/tmbci" ./cmd/tmbci)

for dir in "$ROOT"/ci/tools/*/; do
  name=$(basename "$dir")
  pkg=$(sed -n 's/^tool[[:space:]]\{1,\}\([^[:space:]]*\)$/\1/p' "$dir/go.mod")
  [ -n "$pkg" ] || { echo "ci/tools/$name: no single tool directive" >&2; exit 2; }
  (cd "$dir" && GOFLAGS=-mod=readonly CGO_ENABLED=0 go build -trimpath -o "$BIN/$name" "$pkg")
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
found=0
while read -r name version os arch url sum inner; do
  case "$name" in ''|'#'*) continue ;; esac
  [ "$os" = "$OS" ] && [ "$arch" = "$ARCH" ] || continue
  found=$((found + 1))
  file="$TMP/$(basename "$url")"
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$file" "$url"
  got=$(sha256 "$file")
  if [ "$got" != "$sum" ]; then
    echo "CHECKSUM MISMATCH for $name $version: got $got want $sum" >&2
    exit 1
  fi
  case "$file" in
    *.tar.gz) tar -xzf "$file" -C "$TMP" ;;
    *.tar.xz) tar -xJf "$file" -C "$TMP" ;;
  esac
  if [ "$inner" = "-" ]; then install -m 0755 "$file" "$BIN/$name"; else install -m 0755 "$TMP/$inner" "$BIN/$name"; fi
  echo "$name $version sha256:$sum" >> "$TMP/installed.txt"
done < "$ROOT/ci/tools.lock"
[ "$found" -gt 0 ] || { echo "ci/tools.lock has no entries for $OS/$ARCH" >&2; exit 2; }
cat "$TMP/installed.txt"
