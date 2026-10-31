#!/usr/bin/env bash
# Build and test the signer package. With Xcode (CI runners) this is plain
# `swift build` and `swift test`. With only the Command Line Tools, Swift
# Testing ships outside the default search paths, so the framework and its
# interop library are added explicitly.
set -euo pipefail
cd "$(dirname "$0")/.."

extra=()
dev=$(xcode-select -p 2>/dev/null || true)
if [[ "$dev" == */CommandLineTools ]]; then
  fw="$dev/Library/Developer/Frameworks"
  lib="$dev/Library/Developer/usr/lib"
  extra=(-Xswiftc -F -Xswiftc "$fw" -Xlinker -rpath -Xlinker "$fw" -Xlinker -rpath -Xlinker "$lib")
fi

swift build "$@"
swift test ${extra[@]+"${extra[@]}"} "$@"
