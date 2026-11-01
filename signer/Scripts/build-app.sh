#!/usr/bin/env bash
# Build the menu bar app as a signed bundle: swift build of the TMBSigner
# product, then OUTDIR/TMBSigner.app with Info.plist, signed with the
# hardened runtime and signer/App/TMBSigner.entitlements (ADR 0007 R5).
#
#   build-app.sh [OUTDIR]   default OUTDIR: signer/.build/app
#
# Signing is ad hoc ("-") unless TMB_SIGNER_IDENTITY names a codesign
# identity. No Xcode project and no xcodebuild: SwiftPM plus codesign.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$here/.build/app"}
identity=${TMB_SIGNER_IDENTITY:--}

cd "$here"
swift build -c release --product TMBSigner
bin=$(swift build -c release --product TMBSigner --show-bin-path)/TMBSigner

app="$out/TMBSigner.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp "$here/App/Info.plist" "$app/Contents/Info.plist"
cp "$bin" "$app/Contents/MacOS/TMBSigner"
plutil -lint "$app/Contents/Info.plist" >/dev/null
codesign --force --sign "$identity" --options runtime --timestamp=none \
  --entitlements "$here/App/TMBSigner.entitlements" "$app"
codesign --verify --strict --verbose=1 "$app"
echo "$app"
