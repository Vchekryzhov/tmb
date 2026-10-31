#!/usr/bin/env bash
# TMB CI entrypoint: the same commands run locally and in GitHub Actions.
#
#   ci/run.sh tools                 build tmbci and install pinned tools
#   ci/run.sh lint                  format, vet, staticcheck, module, shell, workflows, Dockerfiles, docs
#   ci/run.sh test <label> [race]   all Go tests, no cache, JSON + JUnit
#   ci/run.sh ci-selftest           tests of tmbci itself (negative/positive gate fixtures)
#   ci/run.sh coverage [base-ref]   whole-module coverage vs the merge-base, diff coverage, targets
#   ci/run.sh security              gosec + govulncheck (source and tests)
#   ci/run.sh build                 cross-builds, reproducibility, checksums, build info, govulncheck on binaries
#   ci/run.sh fuzz <short|long>     fuzz registry, corpus, bounded fuzzing per target
#   ci/run.sh secrets <range|full> [base-ref]   gitleaks over a commit range + tree, or full history
#   ci/run.sh harness               N-series + docker-pair on Linux, verified against ci/scenarios
#   ci/run.sh images                build harness images, Trivy vulns/misconfig, SBOM and licenses
#   ci/run.sh images-opensbx        OpenShell sandbox image (arm64 Docker host only): Trivy vulns, SBOM, licenses
#   ci/run.sh manifest              security manifest against executed tests and scenarios
#   ci/run.sh stress                repeated shuffled security tests under the race detector
#   ci/run.sh mutation              security mutation checks in a temporary copy
#   ci/run.sh bench                 benchmark report (no numeric gate)
#   ci/run.sh links-external        external documentation links
#   ci/run.sh gate <event>          ci-gate over every result
#   ci/run.sh openshell             full acceptance (phase B): run-all.sh on the dedicated Mac, all three logs verified
#   ci/run.sh vm                    VM proof (local only, Lima on a Mac): harness/run-vm.sh, last-vm-run.log verified
#   ci/run.sh dist                  release files in out/dist: deb/rpm, tmb tar.gz, CycloneDX SBOMs, SHA256SUMS (version: TMB_VERSION or git)
#   ci/run.sh package               dist + a second build compared byte for byte + deb/rpm install tests in containers
#   ci/run.sh local                 lint + test + ci-selftest + coverage + security + build + fuzz short
#
# Every check writes out/ci/results/<check>.json (see tmbci). A check that
# cannot run records ERROR; nothing is skipped silently.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${TMB_CI_OUT:-$ROOT/out/ci}
RESULTS=$OUT/results
REPORTS=$OUT/reports
BIN=$OUT/bin
SRC=$ROOT/src
DIST=${TMB_DIST:-$ROOT/out/dist}
mkdir -p "$RESULTS" "$REPORTS"
export PATH="$BIN:$PATH"
export TMB_CI_SHA=${TMB_CI_SHA:-$(git -C "$ROOT" rev-parse HEAD)}
export TMB_CI_RUN_ID=${TMB_CI_RUN_ID:-local}
export GOFLAGS=-mod=readonly
export CGO_ENABLED=${CGO_ENABLED:-0}

log() { printf '\n== %s\n' "$*"; }

# result CHECK STATUS REASON [summary-file]
result() {
  local args=(result -check "$1" -status "$2" -reason "$3" -out "$RESULTS")
  [ -n "${4:-}" ] && [ -s "${4:-}" ] && args+=(-summary-file "$4")
  "$BIN/tmbci" "${args[@]}"
}

# by_rc CHECK RC LOG FINDINGS_RCS: 0 PASS, a findings rc FAIL, anything else ERROR.
by_rc() {
  local check=$1 rc=$2 logf=$3 findings=$4
  if [ "$rc" = 0 ]; then
    result "$check" PASS "clean" "$logf"
  elif [[ " $findings " == *" $rc "* ]]; then
    result "$check" FAIL "findings (rc=$rc)" "$logf"
  else
    result "$check" ERROR "tool error (rc=$rc)" "$logf"
  fi
}

need_tmbci() {
  [ -x "$BIN/tmbci" ] || { echo "run 'ci/run.sh tools' first" >&2; exit 2; }
}

go_version() { go env GOVERSION; }

cmd_tools() {
  "$ROOT/ci/install-tools.sh" "$BIN"
}

cmd_lint() {
  need_tmbci
  local L=$REPORTS/lint
  mkdir -p "$L"
  local gv a; gv=$(go_version)

  log "gofmt"
  (cd "$ROOT" && gofmt -l src ci) >"$L/gofmt.txt" 2>&1
  local rc=$?
  if [ $rc -ne 0 ]; then result lint/gofmt ERROR "gofmt rc=$rc" "$L/gofmt.txt"
  elif [ -s "$L/gofmt.txt" ]; then result lint/gofmt FAIL "unformatted files" "$L/gofmt.txt"
  else result lint/gofmt PASS "all files formatted"; fi

  log "go vet (linux, darwin; product and CI module)"
  : >"$L/vet.txt"
  rc=0
  for os in linux darwin; do
    (cd "$SRC" && GOOS=$os go vet ./...) >>"$L/vet.txt" 2>&1 || rc=1
  done
  (cd "$ROOT/ci" && go vet ./...) >>"$L/vet.txt" 2>&1 || rc=1
  by_rc lint/vet $rc "$L/vet.txt" "1"

  log "staticcheck (product for linux and darwin, CI module)"
  rc=0
  local sreports=()
  for os in linux darwin; do
    (cd "$SRC" && GOOS=$os staticcheck -f json ./...) >"$L/staticcheck-$os.json" 2>"$L/staticcheck-$os.log"
    a=$?; [ $a -le 1 ] || rc=$a
    sreports+=(-report "$L/staticcheck-$os.json")
  done
  (cd "$ROOT/ci" && staticcheck -f json ./...) >"$L/staticcheck-ci.json" 2>"$L/staticcheck-ci.log"
  a=$?; [ $a -le 1 ] || rc=$a
  sreports+=(-report "$L/staticcheck-ci.json")
  if [ $rc -ne 0 ]; then result lint/staticcheck ERROR "staticcheck rc=$rc" "$L/staticcheck-linux.log"
  else "$BIN/tmbci" scan -check lint/staticcheck -scanner staticcheck "${sreports[@]}" -exceptions "$ROOT/ci/exceptions.json" \
         -root "$ROOT/" -strict-unused -out "$RESULTS"; fi

  log "module metadata and stdlib-only contract"
  : >"$L/module.txt"
  rc=0
  for m in src ci; do
    (cd "$ROOT/$m" && go mod tidy -diff) >>"$L/module.txt" 2>&1 || { echo "$m: go mod tidy would change go.mod/go.sum" >>"$L/module.txt"; rc=1; }
    if grep -q '^require' "$ROOT/$m/go.mod" || [ -e "$ROOT/$m/go.sum" ]; then
      echo "$m: must stay stdlib-only (no require, no go.sum)" >>"$L/module.txt"; rc=1
    fi
  done
  deps=$(cd "$SRC" && go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... | grep -v '^tmb-poc' || true)
  if [ -n "$deps" ]; then echo "non-stdlib imports: $deps" >>"$L/module.txt"; rc=1; fi
  git -C "$ROOT" diff --exit-code -- src/go.mod ci/go.mod >>"$L/module.txt" 2>&1 || rc=1
  by_rc lint/module $rc "$L/module.txt" "1"

  log "Go toolchain pin consistency"
  "$ROOT/ci/check-pins.sh" >"$L/pins.txt" 2>&1
  by_rc lint/pins $? "$L/pins.txt" "1"

  log "bash -n + ShellCheck"
  : >"$L/shell.txt"
  rc=0
  local scripts=() dockerfiles=() l
  while IFS= read -r l; do scripts+=("$l"); done < <(cd "$ROOT" && git ls-files '*.sh')
  for s in "${scripts[@]}"; do bash -n "$ROOT/$s" >>"$L/shell.txt" 2>&1 || rc=1; done
  if [ $rc -ne 0 ]; then
    result lint/bash-syntax FAIL "bash -n failed" "$L/shell.txt"
  else
    result lint/bash-syntax PASS "${#scripts[@]} scripts parse"
  fi
  (cd "$ROOT" && shellcheck --severity=style --format=gcc "${scripts[@]}") >"$L/shellcheck.txt" 2>&1
  by_rc lint/shellcheck $? "$L/shellcheck.txt" "1"

  log "actionlint + zizmor"
  (cd "$ROOT" && actionlint -shellcheck "$BIN/shellcheck" -no-color) >"$L/actionlint.txt" 2>&1
  by_rc lint/actionlint $? "$L/actionlint.txt" "1"
  (cd "$ROOT" && zizmor --offline --no-progress --format plain --persona regular .github) >"$L/zizmor.txt" 2>&1
  rc=$?
  # zizmor: 0 clean, 10-14 findings by severity, other codes are tool errors
  if [ $rc -ge 10 ] && [ $rc -le 14 ]; then rc=1; elif [ $rc -eq 1 ]; then rc=3; fi
  by_rc lint/zizmor $rc "$L/zizmor.txt" "1"

  log "Hadolint"
  while IFS= read -r l; do dockerfiles+=("$l"); done < <(cd "$ROOT" && git ls-files 'harness/images/Dockerfile.*' 'packaging/test/Dockerfile.*')
  (cd "$ROOT" && hadolint --no-color "${dockerfiles[@]}") >"$L/hadolint.txt" 2>&1
  by_rc lint/hadolint $? "$L/hadolint.txt" "1"

  log "exceptions"
  "$BIN/tmbci" exceptions-lint -check lint/exceptions -exceptions "$ROOT/ci/exceptions.json" -out "$RESULTS"

  log "local documentation links"
  "$ROOT/ci/check-links.sh" local >"$L/links.txt" 2>&1
  by_rc lint/doc-links $? "$L/links.txt" "1"
  echo "go: $gv"
}

# env_report FILE: CPU/OS/compiler of this cell
env_report() {
  {
    echo "go: $(go_version)"
    echo "goos/goarch: $(go env GOOS)/$(go env GOARCH)"
    echo "uname: $(uname -srm)"
    if [ -r /proc/cpuinfo ]; then grep -m1 -E 'model name|Model' /proc/cpuinfo || true; echo "cpus: $(nproc)"; fi
    if command -v sysctl >/dev/null 2>&1; then sysctl -n machdep.cpu.brand_string 2>/dev/null || true; fi
    [ -r /etc/os-release ] && grep PRETTY_NAME /etc/os-release
    command -v sw_vers >/dev/null && sw_vers | tr '\n' ' ' && echo
  } >"$1" 2>&1
}

cmd_test() {
  need_tmbci
  local label=${1:?label}; local race=${2:-}
  local T=$REPORTS/test/$label
  mkdir -p "$T"
  env_report "$T/env.txt"
  local flags=(-count=1 -timeout=10m -json)
  if [ "$race" = race ]; then flags+=(-race); fi
  log "go test ${flags[*]} ./... ($label)"
  (cd "$SRC" && CGO_ENABLED=$([ "$race" = race ] && echo 1 || echo 0) go test "${flags[@]}" ./...) >"$T/test.json" 2>"$T/stderr.txt"
  echo "go test rc=$?" >>"$T/stderr.txt"
  "$BIN/tmbci" gotest -check "test/$label" -json "$T/test.json" -junit "$T/junit.xml" \
    -tool "go=$(go_version)" -out "$RESULTS"
}

cmd_ci_selftest() {
  need_tmbci
  local T=$REPORTS/ci-selftest
  mkdir -p "$T"
  (cd "$ROOT/ci" && go test -count=1 -timeout=5m -json ./...) >"$T/test.json" 2>"$T/stderr.txt"
  "$BIN/tmbci" gotest -check ci/selftest -json "$T/test.json" -junit "$T/junit.xml" -out "$RESULTS"
}

# profile DIR OUTFILE META: whole-module atomic profile of the tree in DIR/src
profile() {
  local dir=$1 out=$2 meta=$3
  (cd "$dir/src" && CGO_ENABLED=1 go test -count=1 -timeout=10m -race -covermode=atomic -coverpkg=./... -coverprofile="$out" ./... >"$out.log" 2>&1)
  local rc=$?
  printf '{"goos":"%s","goarch":"%s","go":"%s","mode":"atomic","sha":"%s"}\n' \
    "$(go env GOOS)" "$(go env GOARCH)" "$(go_version)" "$(git -C "$dir" rev-parse HEAD)" >"$meta"
  return $rc
}

cmd_coverage() {
  need_tmbci
  local base_ref=${1:-origin/main}
  local C=$REPORTS/coverage
  rm -rf "$C"; mkdir -p "$C"
  log "head profile"
  profile "$ROOT" "$C/head.cov" "$C/head.meta.json" || echo "head go test failed; see head.cov.log (the test check reports it)"
  (cd "$SRC" && go list ./...) >"$C/packages.txt"
  (cd "$SRC" && go tool cover -func="$C/head.cov") >"$C/head.func.txt" 2>&1
  (cd "$SRC" && go tool cover -html="$C/head.cov" -o "$C/head.html") 2>/dev/null

  local base; base=$(git -C "$ROOT" merge-base "$base_ref" HEAD 2>/dev/null)
  local args=(coverage -head "$C/head.cov" -head-meta "$C/head.meta.json" -packages "$C/packages.txt"
              -policy "$ROOT/ci/coverage-policy.json" -module tmb-poc=src -diff "$C/diff.patch" -out "$RESULTS")
  if [ -z "$base" ]; then
    echo "no merge-base with $base_ref" >"$C/diff.patch"
    for c in coverage/compare coverage/diff coverage/targets; do result "$c" ERROR "no merge-base with $base_ref"; done
    return
  fi
  echo "$base" >"$C/base.sha"
  git -C "$ROOT" diff -U0 -M --no-color "$base" HEAD -- 'src/*.go' ':(exclude)src/**/*_test.go' ':(exclude)src/*_test.go' >"$C/diff.patch"
  if git -C "$ROOT" cat-file -e "$base:src/go.mod" 2>/dev/null; then
    log "base profile at merge-base $base"
    local WT; WT=$(mktemp -d)
    git -C "$ROOT" worktree add --detach "$WT/base" "$base" >/dev/null 2>&1
    local base_ok=1
    profile "$WT/base" "$C/base.cov" "$C/base.meta.json" || base_ok=0
    git -C "$ROOT" worktree remove --force "$WT/base" >/dev/null 2>&1; rm -rf "$WT"
    if [ $base_ok -eq 0 ]; then
      # a partial base profile would weaken "no decrease"; refuse to compare
      result coverage/compare ERROR "base tests failed at $base; no comparable base" "$C/base.cov.log"
      args+=(-skip-compare)
    else
      args+=(-base "$C/base.cov" -base-meta "$C/base.meta.json")
    fi
  else
    args+=(-bootstrap "merge-base $base has no product module (src/go.mod)")
  fi
  "$BIN/tmbci" "${args[@]}"
}

cmd_security() {
  need_tmbci
  local S=$REPORTS/security
  mkdir -p "$S"
  log "gosec (all packages incl. tests, linux and darwin builds)"
  local rc=0 os
  for os in linux darwin; do
    (cd "$SRC" && GOOS=$os gosec -quiet -tests -fmt json -out "$S/gosec-$os.json" -no-fail ./...) >>"$S/gosec.log" 2>&1 || rc=$?
  done
  if [ $rc -ne 0 ]; then result security/gosec ERROR "gosec rc=$rc" "$S/gosec.log"
  else "$BIN/tmbci" scan -check security/gosec -scanner gosec -report "$S/gosec-linux.json" -report "$S/gosec-darwin.json" -exceptions "$ROOT/ci/exceptions.json" \
         -root "$ROOT/" -strict-unused -tool "gosec=$(sed -n 's/.*securego\/gosec\/v2 \(v[^ ]*\).*/\1/p' "$ROOT/ci/tools/gosec/go.mod")" -out "$RESULTS"; fi

  log "govulncheck (source incl. tests, symbol level)"
  (cd "$SRC" && govulncheck -test -format json ./...) >"$S/govulncheck-source.json" 2>"$S/govulncheck-source.log"
  rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 3 ]; then result security/govulncheck-source ERROR "govulncheck rc=$rc (online DB required)" "$S/govulncheck-source.log"
  else "$BIN/tmbci" scan -check security/govulncheck-source -scanner govulncheck -report "$S/govulncheck-source.json" \
         -exceptions "$ROOT/ci/exceptions.json" -tool "govulncheck=$(govulncheck -version 2>/dev/null | sed -n 's/^Scanner: //p')" -out "$RESULTS"; fi
}

# build_one OUTDIR GOOS GOARCH PKG NAME
build_one() {
  (cd "$SRC" && GOOS=$2 GOARCH=$3 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-buildid=' -o "$1/$5-$2-$3" "./cmd/$4")
}

cmd_build() {
  need_tmbci
  local B=$REPORTS/build
  rm -rf "$B"; mkdir -p "$B"
  local targets=("tmb linux amd64" "tmb linux arm64" "tmb-broker linux amd64" "tmb-broker linux arm64" "tmb darwin arm64")
  local rc=0 a
  log "two clean builds per target (Mac: client only, no privileged Mac broker is claimed)"
  for round in a b; do
    mkdir -p "$B/$round"
    for t in "${targets[@]}"; do
      read -r name os arch <<<"$t"
      GOCACHE=$(mktemp -d) build_one "$B/$round" "$os" "$arch" "$name" "$name" >>"$B/build.log" 2>&1 || rc=1
    done
  done
  if [ $rc -ne 0 ]; then result build/binaries FAIL "build failed" "$B/build.log"; return; fi
  result build/binaries PASS "${#targets[@]} binaries (tmb, tmb-broker linux amd64/arm64; tmb darwin arm64)"

  (cd "$B/a" && sha256sum_all) >"$B/SHA256SUMS"
  (cd "$B/b" && sha256sum_all) >"$B/SHA256SUMS.second"
  if diff -u "$B/SHA256SUMS" "$B/SHA256SUMS.second" >"$B/repro.diff"; then
    result build/reproducible PASS "two clean builds are byte-identical (Go binaries only; images are not claimed reproducible)" "$B/SHA256SUMS"
  else
    result build/reproducible FAIL "builds differ" "$B/repro.diff"
  fi
  { echo "tested_sha: $TMB_CI_SHA"; echo "go: $(go_version)"; echo; for f in "$B"/a/*; do go version -m "$f"; echo; done; } >"$B/build-manifest.txt"

  log "govulncheck on built binaries"
  : >"$B/govulncheck-binaries.json"
  local worst=0
  for f in "$B"/a/*; do
    govulncheck -mode binary -format json "$f" >"$B/govulncheck-$(basename "$f").json" 2>>"$B/govulncheck-binaries.log"
    a=$?; [ $a -ne 0 ] && [ $a -ne 3 ] && worst=$a
    "$BIN/tmbci" scan -check "security/govulncheck-binary-$(basename "$f")" -scanner govulncheck -report "$B/govulncheck-$(basename "$f").json" \
      -exceptions "$ROOT/ci/exceptions.json" -out "$RESULTS" >/dev/null || true
  done
  if [ $worst -ne 0 ]; then result security/govulncheck-binaries ERROR "govulncheck rc=$worst" "$B/govulncheck-binaries.log"
  else
    # collapse per-binary results into one required check
    local bad; bad=$(grep -l '"status": "\(FAIL\|ERROR\)"' "$RESULTS"/security__govulncheck-binary-*.json 2>/dev/null | wc -l | tr -d ' ')
    if [ "$bad" = 0 ]; then result security/govulncheck-binaries PASS "no reachable vulnerabilities in ${#targets[@]} binaries"
    else result security/govulncheck-binaries FAIL "$bad binaries with findings (see security/govulncheck-binary-*)"; fi
  fi
}

sha256sum_all() { for f in *; do if command -v sha256sum >/dev/null; then sha256sum "$f"; else shasum -a 256 "$f"; fi; done; }

# dist_version: TMB_VERSION (the release tag), else the v* tag on HEAD, else
# v0.0.0-dev+<sha12>. Same commit, same version: the build stays reproducible.
dist_version() {
  local v=${TMB_VERSION:-}
  [ -n "$v" ] || v=$(git -C "$ROOT" describe --tags --exact-match --match 'v*' HEAD 2>/dev/null) \
    || v="v0.0.0-dev+$(git -C "$ROOT" rev-parse --short=12 HEAD)"
  if ! [[ $v =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?(\+[0-9A-Za-z.]+)?$ ]]; then
    echo "version $v is not vMAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]" >&2
    return 1
  fi
  echo "$v"
}

# pkg_version VERSION: the version nfpm writes into deb and rpm (semver
# pre-release with ~ so it sorts before the release, release 1):
# v0.0.0-dev+abc gives 0.0.0~dev+abc-1, v1.2.3 gives 1.2.3-1.
pkg_version() {
  local v=${1#v} core rest
  core=${v%%[-+]*}; rest=${v#"$core"}
  [[ $rest == -* ]] && rest="~${rest#-}"
  echo "$core$rest-1"
}

DIST_TARGETS=("tmb linux amd64" "tmb linux arm64" "tmb darwin arm64" "tmb-broker linux amd64" "tmb-broker linux arm64")

# dist_build OUTDIR VERSION LOG: binaries (version in buildinfo), deb and rpm
# of tmb-broker and tmb for amd64/arm64, tmb tar.gz for linux/amd64,
# linux/arm64, darwin/arm64, a CycloneDX SBOM next to each (<file>.cdx.json),
# SHA256SUMS. File mtimes in packages and
# archives are the commit time (SOURCE_DATE_EPOCH).
dist_build() {
  local out=$1 ver=$2 logf=$3 stage epoch t name os arch p pkgv f a
  stage=$(mktemp -d)
  epoch=$(git -C "$ROOT" log -1 --format=%ct HEAD)
  rm -rf "$out"; mkdir -p "$out" "$stage/bin" "$stage/build"
  cp -R "$ROOT/packaging" "$stage/packaging"
  for t in "${DIST_TARGETS[@]}"; do
    read -r name os arch <<<"$t"
    (cd "$SRC" && GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags="-buildid= -X tmb-poc/internal/buildinfo.Version=$ver" -o "$stage/build/$name-$os-$arch" "./cmd/$name") >>"$logf" 2>&1 \
      || { rm -rf "$stage"; return 1; }
  done
  pkgv=$(pkg_version "$ver")
  local sbomcmd=("$BIN/tmbci" sbom -version "$ver" -mtime "$epoch" -supplier "TMB" -url "https://github.com/Vchekryzhov/tmb")
  for arch in amd64 arm64; do
    for name in tmb-broker tmb; do
      cp "$stage/build/$name-linux-$arch" "$stage/bin/$name"
      for p in deb rpm; do
        (cd "$stage" && TMB_VERSION=$ver TMB_ARCH=$arch SOURCE_DATE_EPOCH=$epoch \
          nfpm package -f "packaging/$name.nfpm.yaml" -p "$p" -t "$out/") >>"$logf" 2>&1 \
          || { rm -rf "$stage"; return 1; }
        if [ "$p" = deb ]; then f="${name}_${pkgv}_${arch}.deb"; a=$arch
        else a=$([ "$arch" = amd64 ] && echo x86_64 || echo aarch64); f="${name}-${pkgv}.${a}.rpm"; fi
        "${sbomcmd[@]}" -file-out "$out/$f.cdx.json" -artifact "$out/$f" -type "$p" -name "$name" -pkg-version "$pkgv" -arch "$a" \
          -binary "/usr/bin/$name=$stage/build/$name-linux-$arch" >>"$logf" 2>&1 || { rm -rf "$stage"; return 1; }
      done
    done
  done
  for t in "linux amd64" "linux arm64" "darwin arm64"; do
    read -r os arch <<<"$t"
    f="tmb_${ver#v}_${os}_${arch}.tar.gz"
    "$BIN/tmbci" archive -file-out "$out/$f" -mtime "$epoch" \
      -file "tmb=$stage/build/tmb-$os-$arch" >>"$logf" 2>&1 || { rm -rf "$stage"; return 1; }
    "${sbomcmd[@]}" -file-out "$out/$f.cdx.json" -artifact "$out/$f" -type archive -name tmb -pkg-version "${ver#v}" -os "$os" -arch "$arch" \
      -binary "tmb=$stage/build/tmb-$os-$arch" >>"$logf" 2>&1 || { rm -rf "$stage"; return 1; }
  done
  (cd "$out" && sha256sum_all) >"$stage/SHA256SUMS" && mv "$stage/SHA256SUMS" "$out/SHA256SUMS"
  rm -rf "$stage"
}

# dist_tools: tmbci from this tree and nfpm at the ci/tools.lock version
# (installed and checksum-verified when missing or different), so a clean
# checkout needs only Go, git and curl for `ci/run.sh dist`.
dist_tools() {
  local want
  want=$(awk '$1 == "nfpm" {print $2; exit}' "$ROOT/ci/tools.lock")
  if [ -x "$BIN/nfpm" ] && "$BIN/nfpm" --version 2>&1 | grep -qE "^GitVersion:[[:space:]]+v?$want\$"; then
    (cd "$ROOT/ci" && GOFLAGS=-mod=readonly CGO_ENABLED=0 go build -trimpath -o "$BIN/tmbci" ./cmd/tmbci)
  else
    "$ROOT/ci/install-tools.sh" "$BIN" nfpm
  fi
}

cmd_dist() {
  dist_tools || { echo "installing tmbci/nfpm failed" >&2; exit 2; }
  local D=$REPORTS/dist ver
  mkdir -p "$D"; : >"$D/dist.log"; rm -f "$D/version.txt"
  ver=$(dist_version 2>>"$D/dist.log") || { result package/dist ERROR "bad version" "$D/dist.log"; return; }
  log "dist $ver into $DIST"
  if dist_build "$DIST" "$ver" "$D/dist.log"; then
    echo "$ver" >"$D/version.txt"
    result package/dist PASS "$ver: $(grep -c . "$DIST/SHA256SUMS") files (deb, rpm, tar.gz, CycloneDX SBOMs) in ${DIST#"$ROOT"/}" "$DIST/SHA256SUMS"
  else
    result package/dist FAIL "build failed" "$D/dist.log"
  fi
}

# install_test KIND DISTRO VERSION ARCH: build the install-test image of
# packaging/test/Dockerfile.DISTRO. The packages are copied in (no mounts),
# installed and checked during the build; nothing runs privileged.
install_test() {
  local kind=$1 distro=$2 ver=$3 arch=$4 ctx tag rc
  ctx=$(mktemp -d)
  mkdir -p "$ctx/dist"
  cp "$DIST"/*."$kind" "$ctx/dist/"
  cp "$ROOT/packaging/test/check-install.sh" "$ctx/"
  tag="tmb-pkg-test/$distro:${TMB_CI_RUN_ID}-${TMB_CI_SHA:0:12}"
  docker build --no-cache --progress=plain -f "$ROOT/packaging/test/Dockerfile.$distro" \
    --build-arg "TMB_VERSION=$ver" --build-arg "TMB_ARCH=$arch" -t "$tag" "$ctx" >"$REPORTS/package/$distro.log" 2>&1
  rc=$?
  docker image rm -f "$tag" >/dev/null 2>&1
  rm -rf "$ctx"
  grep -oE '(CHECK (PASS|FAIL)|RESULT:) .*' "$REPORTS/package/$distro.log" >"$REPORTS/package/$distro.checks"
  # 0 green, 1 a check failed, 2 the image did not get as far as the checks
  if grep -q '^RESULT: GREEN' "$REPORTS/package/$distro.checks" && [ $rc -eq 0 ]; then return 0; fi
  grep -q '^RESULT: RED' "$REPORTS/package/$distro.checks" && return 1
  return 2
}

# install_result CHECK RC LABEL SUMMARY
install_result() {
  case $2 in
    0) result "$1" PASS "$3" "$4" ;;
    1) result "$1" FAIL "failed checks in $3" "$4" ;;
    *) result "$1" ERROR "test image did not reach the checks (base image, package mirror or docker)" "${4%.checks}.log" ;;
  esac
}

cmd_package() {
  local P=$REPORTS/package ver arch
  rm -rf "$P"; mkdir -p "$P"
  cmd_dist
  [ -s "$REPORTS/dist/version.txt" ] || {
    for c in package/reproducible package/deb-ubuntu package/rpm-fedora; do result $c NOT_RUN "dist failed"; done
    return
  }
  ver=$(cat "$REPORTS/dist/version.txt")
  log "second clean dist build (fresh GOCACHE) for byte comparison"
  local gocache rc2=0
  gocache=$(mktemp -d)
  GOCACHE=$gocache dist_build "$P/second" "$ver" "$P/second.log" || rc2=$?
  rm -rf "$gocache"
  if [ $rc2 -eq 0 ]; then
    if diff -u "$DIST/SHA256SUMS" "$P/second/SHA256SUMS" >"$P/repro.diff"; then
      result package/reproducible PASS "two clean builds give byte-identical binaries, packages and archives" "$DIST/SHA256SUMS"
    else
      result package/reproducible FAIL "builds differ" "$P/repro.diff"
    fi
  else
    result package/reproducible ERROR "second build failed" "$P/second.log"
  fi
  rm -rf "$P/second"
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; *) arch=arm64 ;; esac
  if ! docker info >/dev/null 2>&1; then
    result package/deb-ubuntu ERROR "docker unavailable"; result package/rpm-fedora ERROR "docker unavailable"; return
  fi
  local rc
  log "deb install test in Ubuntu ($arch)"
  install_test deb ubuntu "$ver" "$arch"; rc=$?
  install_result package/deb-ubuntu $rc "Ubuntu 24.04: deb installed and checked on $arch, metadata of both arches" "$P/ubuntu.checks"
  log "rpm install test in Fedora ($arch)"
  install_test rpm fedora "$ver" "$arch"; rc=$?
  install_result package/rpm-fedora $rc "Fedora 44: rpm installed and checked on $arch, metadata of both arches" "$P/fedora.checks"
}

cmd_fuzz() {
  need_tmbci
  local mode=${1:-short}
  local F=$REPORTS/fuzz
  mkdir -p "$F"
  local per total
  if [ "$mode" = long ]; then per=300; total=900; else per=30; total=180; fi
  (cd "$SRC" && go test -list '^Fuzz' ./...) >"$F/list.txt" 2>&1
  "$BIN/tmbci" fuzz -check "fuzz/registry" -registry "$ROOT/ci/fuzz-targets.json" -list "$F/list.txt" -targets-out "$F/targets.txt" -out "$RESULTS"
  local rc=$?
  [ $rc -eq 2 ] && { result "fuzz/$mode" ERROR "fuzz registry unreadable"; return; }
  local n; n=$(wc -l <"$F/targets.txt" | tr -d ' ')
  if [ "$n" = 0 ]; then
    result "fuzz/$mode" NOT_APPLICABLE "no fuzz target exists yet: required targets are GAPs in ci/fuzz-targets.json (#15)"
    return
  fi
  # corpus runs as part of every go test; this is the bounded mutation phase
  [ $((per * n)) -gt "$total" ] && per=$((total / n))
  [ "$per" -ge 1 ] || { result "fuzz/$mode" ERROR "$n targets do not fit the ${total}s budget"; return; }
  local failed=0
  : >"$F/fuzz.log"
  while read -r pkg name; do
    log "fuzz $pkg $name for ${per}s"
    (cd "$SRC" && go test -run '^$' -fuzz "^${name}\$" -fuzztime "${per}s" -parallel 2 "$pkg") >>"$F/fuzz.log" 2>&1 || failed=$((failed + 1))
  done <"$F/targets.txt"
  # failing inputs land in testdata/fuzz/<Target>/; collect them for the artifact
  (cd "$SRC" && git ls-files --others --exclude-standard -- '**/testdata/fuzz/**') >"$F/new-corpus.txt"
  if [ -s "$F/new-corpus.txt" ]; then mkdir -p "$F/corpus"; (cd "$SRC" && tar -cf - -T "$F/new-corpus.txt" | tar -xf - -C "$F/corpus"); fi
  if [ $failed -gt 0 ]; then result "fuzz/$mode" FAIL "$failed target(s) found failing inputs (artifact fuzz-corpus)" "$F/new-corpus.txt"
  else result "fuzz/$mode" PASS "$n target(s), ${per}s each"; fi
}

cmd_secrets() {
  need_tmbci
  local mode=${1:-range} base_ref=${2:-origin/main}
  local S=$REPORTS/secrets
  mkdir -p "$S"
  local cfg=(--config "$ROOT/ci/gitleaks.toml")
  local rc
  if [ "$mode" = full ]; then
    log "gitleaks: full history"
    (cd "$ROOT" && gitleaks git "${cfg[@]}" --redact --no-banner --exit-code 1 --report-format json --report-path "$S/history.json" .) >"$S/history.log" 2>&1
    rc=$?
    if [ $rc -gt 1 ]; then result secrets/history ERROR "gitleaks rc=$rc" "$S/history.log"
    else "$BIN/tmbci" scan -check secrets/history -scanner gitleaks -report "$S/history.json" -exceptions "$ROOT/ci/exceptions.json" -out "$RESULTS"; fi
  else
    local base; base=$(git -C "$ROOT" merge-base "$base_ref" HEAD 2>/dev/null)
    if [ -z "$base" ]; then result secrets/range ERROR "no merge-base with $base_ref"
    else
      log "gitleaks: commits $base..HEAD"
      (cd "$ROOT" && gitleaks git "${cfg[@]}" --redact --no-banner --exit-code 1 --log-opts="$base..HEAD" --report-format json --report-path "$S/range.json" .) >"$S/range.log" 2>&1
      rc=$?
      if [ $rc -gt 1 ]; then result secrets/range ERROR "gitleaks rc=$rc" "$S/range.log"
      else "$BIN/tmbci" scan -check secrets/range -scanner gitleaks -report "$S/range.json" -exceptions "$ROOT/ci/exceptions.json" -out "$RESULTS"; fi
    fi
  fi
  log "gitleaks: current tree (tracked files of the tested commit, no build output)"
  local tree; tree=$(mktemp -d)
  git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$tree"
  (cd "$tree" && gitleaks dir "${cfg[@]}" --redact --no-banner --exit-code 1 --report-format json --report-path "$S/tree.json" .) >"$S/tree.log" 2>&1
  rc=$?
  rm -rf "$tree"
  if [ $rc -gt 1 ]; then result secrets/tree ERROR "gitleaks rc=$rc" "$S/tree.log"
  else "$BIN/tmbci" scan -check secrets/tree -scanner gitleaks -report "$S/tree.json" -exceptions "$ROOT/ci/exceptions.json" -out "$RESULTS"; fi
}

# assert_no_keys DIR CHECK: private keys must never reach an artifact
assert_no_keys() {
  if grep -rlE -- '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' "$1" >"$1/.keyscan" 2>/dev/null; then
    result "$2" ERROR "private key material found in reports; artifacts withheld" "$1/.keyscan"
    find "$1" -type f ! -name .keyscan -delete
    return 1
  fi
  rm -f "$1/.keyscan"
}

cmd_harness() {
  need_tmbci
  local H=$REPORTS/harness
  rm -rf "$H"; mkdir -p "$H"
  docker info >/dev/null 2>&1 || { result harness/n-series ERROR "docker unavailable"; result harness/pair ERROR "docker unavailable"; return; }
  local since; since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  # leftover logs from an earlier run must not be accepted
  rm -f "$ROOT/harness/last-run.log" "$ROOT/harness/last-pair-run.log"
  log "run-pair.sh (re-runs run.sh as its STAGE 4)"
  bash "$ROOT/harness/run-pair.sh" >"$H/pair.console" 2>&1
  local rc=$?
  cp "$ROOT/harness/last-run.log" "$H/n-series.log" 2>/dev/null
  cp "$ROOT/harness/last-pair-run.log" "$H/pair.log" 2>/dev/null
  # run.sh's own exit code is asserted by pair's REGRESSION check; its log's
  # summary/verdict are verified here, so rc 0 is passed only when it was green
  local nrc=1
  grep -q '^RESULT: GREEN' "$H/n-series.log" 2>/dev/null && nrc=0
  "$BIN/tmbci" harness -check harness/n-series -log "$H/n-series.log" -registry "$ROOT/ci/scenarios/n-series.txt" \
    -rc $nrc -since "$since" -scenarios-out "$H/scenarios-n.json" -out "$RESULTS"
  "$BIN/tmbci" harness -check harness/pair -log "$H/pair.log" -registry "$ROOT/ci/scenarios/pair.txt" \
    -rc $rc -since "$since" -scenarios-out "$H/scenarios-pair.json" -out "$RESULTS"
  local leftovers; leftovers=$(docker ps -aq --filter name='^tmb-' | wc -l | tr -d ' ')
  if [ "$leftovers" = 0 ]; then result harness/cleanup PASS "no tmb-* containers left"
  else docker ps -a --filter name='^tmb-' >"$H/leftovers.txt"; result harness/cleanup FAIL "$leftovers tmb-* containers left after the run" "$H/leftovers.txt"; fi
  assert_no_keys "$H" harness/artifact-hygiene && result harness/artifact-hygiene PASS "no private key material in harness reports"
}

cmd_images() {
  need_tmbci
  local I=$REPORTS/images
  mkdir -p "$I"
  docker info >/dev/null 2>&1 || { for c in images/build images/trivy-db images/vulns images/sbom images/config; do result $c ERROR "docker unavailable"; done; return; }
  local tag=${TMB_CI_RUN_ID}-${TMB_CI_SHA:0:12}
  local rc=0
  for img in host sandbox; do
    docker build -q -f "$ROOT/harness/images/Dockerfile.$img" -t "tmb-ci/$img:$tag" "$ROOT" >>"$I/build.log" 2>&1 || rc=1
  done
  if [ $rc -ne 0 ]; then
    result images/build FAIL "image build failed" "$I/build.log"
    for c in images/trivy-db images/vulns images/sbom; do result $c NOT_RUN "images did not build"; done
  else
    result images/build PASS "tmb-ci/host and tmb-ci/sandbox built"
    export TRIVY_CACHE_DIR; TRIVY_CACHE_DIR=$(mktemp -d)   # fresh DB every run, never a stale cache
    trivy image --download-db-only --no-progress >"$I/trivy-db.log" 2>&1
    trivy version --format json >"$I/trivy-version.json" 2>>"$I/trivy-db.log"
    if "$BIN/tmbci" trivy-db -check images/trivy-db -version-json "$I/trivy-version.json" -out "$RESULTS"; then
      : >"$I/vulns.log"
      local worst=PASS sbom=0
      for img in host sandbox; do
        trivy image --skip-db-update --no-progress --scanners vuln --format json -o "$I/trivy-$img.json" "tmb-ci/$img:$tag" >>"$I/vulns.log" 2>&1 || worst=ERROR
        trivy image --skip-db-update --no-progress --scanners vuln,license --format cyclonedx -o "$I/sbom-$img.cdx.json" "tmb-ci/$img:$tag" >>"$I/sbom.log" 2>&1 || sbom=1
        trivy image --skip-db-update --no-progress --scanners license --format table -o "$I/licenses-$img.txt" "tmb-ci/$img:$tag" >>"$I/sbom.log" 2>&1 || sbom=1
        [ -s "$I/sbom-$img.cdx.json" ] || sbom=1
        "$BIN/tmbci" scan -check "images/vulns-$img" -scanner trivy -report "$I/trivy-$img.json" -exceptions "$ROOT/ci/exceptions.json" \
          -tool "trivy=$(trivy --version | sed -n 's/^Version: //p')" -out "$RESULTS" >>"$I/vulns.log" || [ "$worst" = ERROR ] || worst=FAIL
      done
      case $worst in
        PASS) result images/vulns PASS "no unexcepted HIGH/CRITICAL in host/sandbox images" ;;
        *) result images/vulns "$worst" "see images/vulns-host and images/vulns-sandbox" "$I/vulns.log" ;;
      esac
      if [ $sbom -eq 0 ]; then result images/sbom PASS "CycloneDX SBOM and license tables for host/sandbox"
      else result images/sbom ERROR "SBOM or license report missing" "$I/sbom.log"; fi
    else
      result images/vulns ERROR "vulnerability DB not fresh; no scan accepted"
      result images/sbom NOT_RUN "vulnerability DB not fresh"
    fi
  fi
  if ! trivy config --format json -o "$I/trivy-config.json" "$ROOT/harness/images" >"$I/config.log" 2>&1; then
    result images/config ERROR "trivy config failed" "$I/config.log"
  else "$BIN/tmbci" scan -check images/config -scanner trivy -report "$I/trivy-config.json" -exceptions "$ROOT/ci/exceptions.json" -out "$RESULTS"; fi
  docker image rm -f "tmb-ci/host:$tag" "tmb-ci/sandbox:$tag" >/dev/null 2>&1
}

# Dockerfile.opensbx starts from the linux/arm64-only opencode image (the
# OpenShell rig runs on a Mac arm64), so it is built and scanned on an arm64
# Docker host: the images-opensbx job runs on an arm64 runner. Same Trivy
# rules as cmd_images: fresh DB, HIGH/CRITICAL block, exceptions in
# ci/exceptions.json.
cmd_images_opensbx() {
  need_tmbci
  local I=$REPORTS/images-opensbx c
  local checks=(images/opensbx-build images/opensbx-trivy-db images/opensbx-vulns images/opensbx-sbom)
  rm -rf "$I"; mkdir -p "$I"
  docker info >/dev/null 2>&1 || { for c in "${checks[@]}"; do result "$c" ERROR "docker unavailable"; done; return; }
  local darch; darch=$(docker info -f '{{.Architecture}}' 2>/dev/null)
  case $darch in aarch64|arm64) ;; *)
    for c in "${checks[@]}"; do result "$c" ERROR "docker host is ${darch:-unknown}; the opensbx base image is linux/arm64 only"; done; return ;;
  esac
  local img=tmb-ci/opensbx:${TMB_CI_RUN_ID}-${TMB_CI_SHA:0:12}
  if ! docker build -q -f "$ROOT/harness/images/Dockerfile.opensbx" -t "$img" "$ROOT" >"$I/build.log" 2>&1; then
    result images/opensbx-build FAIL "image build failed" "$I/build.log"
    for c in "${checks[@]:1}"; do result "$c" NOT_RUN "image did not build"; done
    return
  fi
  result images/opensbx-build PASS "tmb-ci/opensbx built (linux/arm64)"
  export TRIVY_CACHE_DIR; TRIVY_CACHE_DIR=$(mktemp -d)   # fresh DB every run, never a stale cache
  trivy image --download-db-only --no-progress >"$I/trivy-db.log" 2>&1
  trivy version --format json >"$I/trivy-version.json" 2>>"$I/trivy-db.log"
  if "$BIN/tmbci" trivy-db -check images/opensbx-trivy-db -version-json "$I/trivy-version.json" -out "$RESULTS"; then
    if trivy image --skip-db-update --no-progress --scanners vuln --format json -o "$I/trivy-opensbx.json" "$img" >"$I/vulns.log" 2>&1; then
      "$BIN/tmbci" scan -check images/opensbx-vulns -scanner trivy -report "$I/trivy-opensbx.json" -exceptions "$ROOT/ci/exceptions.json" \
        -tool "trivy=$(trivy --version | sed -n 's/^Version: //p')" -out "$RESULTS"
    else result images/opensbx-vulns ERROR "trivy image failed" "$I/vulns.log"; fi
    local sbom=0
    trivy image --skip-db-update --no-progress --scanners vuln,license --format cyclonedx -o "$I/sbom-opensbx.cdx.json" "$img" >"$I/sbom.log" 2>&1 || sbom=1
    trivy image --skip-db-update --no-progress --scanners license --format table -o "$I/licenses-opensbx.txt" "$img" >>"$I/sbom.log" 2>&1 || sbom=1
    [ -s "$I/sbom-opensbx.cdx.json" ] || sbom=1
    if [ $sbom -eq 0 ]; then result images/opensbx-sbom PASS "CycloneDX SBOM and license table for opensbx"
    else result images/opensbx-sbom ERROR "SBOM or license report missing" "$I/sbom.log"; fi
  else
    result images/opensbx-vulns ERROR "vulnerability DB not fresh; no scan accepted"
    result images/opensbx-sbom NOT_RUN "vulnerability DB not fresh"
  fi
  docker image rm -f "$img" >/dev/null 2>&1
}

cmd_manifest() {
  need_tmbci
  local args=(manifest -check security/manifest -manifest "$ROOT/ci/security-manifest.json" -out "$RESULTS")
  local f
  for f in "$REPORTS"/test/linux-amd64-*/test.json; do [ -f "$f" ] && args+=(-tests "$f"); done
  for f in "$REPORTS"/harness/scenarios-*.json; do [ -f "$f" ] && args+=(-scenarios "$f"); done
  "$BIN/tmbci" "${args[@]}"
}

cmd_stress() {
  need_tmbci
  local T=$REPORTS/stress
  mkdir -p "$T"
  (cd "$SRC" && CGO_ENABLED=1 go test -count=20 -shuffle=on -race -timeout=30m -json ./...) >"$T/test.json" 2>"$T/stderr.txt"
  "$BIN/tmbci" gotest -check stress/race-shuffle -json "$T/test.json" -junit "$T/junit.xml" -out "$RESULTS"
}

cmd_mutation() {
  need_tmbci
  "$ROOT/ci/mutation.sh" "$REPORTS/mutation" >"$REPORTS/mutation.log" 2>&1
  local rc=$?
  case $rc in
    0) result security/mutation PASS "every security mutant was killed" "$REPORTS/mutation/summary.txt" ;;
    1) result security/mutation FAIL "surviving security mutants (product tests insensitive); tracked in #15" "$REPORTS/mutation/summary.txt" ;;
    *) result security/mutation ERROR "mutation harness error rc=$rc" "$REPORTS/mutation.log" ;;
  esac
}

cmd_bench() {
  need_tmbci
  local Bn=$REPORTS/bench
  mkdir -p "$Bn"
  env_report "$Bn/env.txt"
  local n; n=$(cd "$SRC" && go test -list '^Benchmark' ./... 2>/dev/null | grep -c '^Benchmark' || true)
  if [ "${n:-0}" = 0 ]; then
    result perf/bench NOT_APPLICABLE "the product declares no benchmarks yet; nothing to report"
    return
  fi
  (cd "$SRC" && go test -run '^$' -bench . -benchmem -count=5 ./...) >"$Bn/bench.txt" 2>&1
  by_rc perf/bench $? "$Bn/bench.txt" "1"
}

cmd_badges() {
  need_tmbci
  local mode=${1:?tools|results}
  case $mode in
    tools) "$BIN/tmbci" badges -mode tools -dir "$ROOT/docs/badges" -go-version "$ROOT/.go-version" -tools-lock "$ROOT/ci/tools.lock" -tools-dir "$ROOT/ci/tools" ;;
    results) "$BIN/tmbci" badges -mode results -dir "$ROOT/docs/badges" -results "${2:-$RESULTS}" ;;
    *) echo "usage: ci/run.sh badges tools|results [results-dir]" >&2; return 2 ;;
  esac
}

cmd_links_external() {
  need_tmbci
  "$ROOT/ci/check-links.sh" external >"$REPORTS/links-external.txt" 2>&1
  case $? in
    0) result docs/external-links PASS "all external links answered" ;;
    1) result docs/external-links FAIL "broken external links" "$REPORTS/links-external.txt" ;;
    *) result docs/external-links UNAVAILABLE "network errors; link state unknown" "$REPORTS/links-external.txt" ;;
  esac
}

cmd_openshell() {
  need_tmbci
  local O=$REPORTS/openshell
  rm -rf "$O"; mkdir -p "$O"
  local since; since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  rm -f "$ROOT"/harness/last-{,pair-,openshell-,full-}run.log   # not last-vm-run.log: the VM proof is its own run
  log "run-all.sh: N-series + docker-pair + OpenShell rig"
  bash "$ROOT/harness/run-all.sh" >"$O/console.log" 2>&1
  local rc=$?
  cp "$ROOT/harness/last-run.log" "$O/n-series.log" 2>/dev/null
  cp "$ROOT/harness/last-pair-run.log" "$O/pair.log" 2>/dev/null
  cp "$ROOT/harness/last-openshell-run.log" "$O/openshell.log" 2>/dev/null
  local n p
  n=1; grep -q '^RESULT: GREEN' "$O/n-series.log" 2>/dev/null && n=0
  p=1; grep -q '^RESULT: GREEN' "$O/pair.log" 2>/dev/null && p=0
  local orc=1; grep -q '^RESULT: GREEN' "$O/openshell.log" 2>/dev/null && orc=0
  "$BIN/tmbci" harness -check openshell/n-series -log "$O/n-series.log" -registry "$ROOT/ci/scenarios/n-series.txt" -rc $n -since "$since" -out "$RESULTS"
  "$BIN/tmbci" harness -check openshell/pair -log "$O/pair.log" -registry "$ROOT/ci/scenarios/pair.txt" -rc $p -since "$since" -out "$RESULTS"
  # O4 dropped/recreated prints CHECK WARN: the verifier turns it into NOT_PROVEN
  "$BIN/tmbci" harness -check openshell/rig -log "$O/openshell.log" -registry "$ROOT/ci/scenarios/openshell.txt" -rc $orc -since "$since" -out "$RESULTS"
  echo "run-all.sh rc=$rc" >>"$O/console.log"
  if [ $rc -eq 0 ]; then result openshell/runner-exit PASS "run-all.sh exited 0"
  else result openshell/runner-exit FAIL "run-all.sh exited $rc" "$O/console.log"; fi
  assert_no_keys "$O" openshell/artifact-hygiene && result openshell/artifact-hygiene PASS "no private key material in acceptance reports"
}

# VM proof (#45): Lima on a Mac, so local only; CI checks the committed
# harness/last-vm-run.log against ci/scenarios/v-series.txt in ci-selftest.
cmd_vm() {
  need_tmbci
  local V=$REPORTS/vm
  rm -rf "$V"; mkdir -p "$V"
  command -v limactl >/dev/null || { result vm/v-series ERROR "limactl not found (Lima is required)"; return; }
  local since; since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  rm -f "$ROOT/harness/last-vm-run.log"
  log "run-vm.sh: V-series in a throwaway Lima VM"
  bash "$ROOT/harness/run-vm.sh" >"$V/console.log" 2>&1
  local rc=$?
  cp "$ROOT/harness/last-vm-run.log" "$V/vm.log" 2>/dev/null
  "$BIN/tmbci" harness -check vm/v-series -log "$V/vm.log" -registry "$ROOT/ci/scenarios/v-series.txt" -rc $rc -since "$since" -out "$RESULTS"
  if limactl list -q 2>/dev/null | grep -qx "${TMB_VM_NAME:-tmb-vm}" && [ "${TMB_VM_KEEP:-0}" != 1 ]; then
    result vm/cleanup FAIL "VM ${TMB_VM_NAME:-tmb-vm} left after the run"
  else result vm/cleanup PASS "no VM left (or TMB_VM_KEEP=1)"; fi
  assert_no_keys "$V" vm/artifact-hygiene && result vm/artifact-hygiene PASS "no private key material in VM reports"
}

cmd_gate() {
  need_tmbci
  "$BIN/tmbci" gate -requirements "$ROOT/ci/required-checks.json" -event "${1:?event}" -results "$RESULTS" -summary "$OUT/gate-summary.md"
}

cmd_local() {
  cmd_lint; cmd_test "$(go env GOOS)-$(go env GOARCH)-local"; cmd_ci_selftest; cmd_coverage; cmd_security; cmd_build; cmd_fuzz short
  echo; echo "results in $RESULTS"; grep -h '"status"' "$RESULTS"/*.json | sort | uniq -c
}

# The command exits 1 when any check it recorded is not PASS/NOT_APPLICABLE,
# so the job conclusion matches its results (ci-gate checks both).
MARK=$(mktemp)
worst_of_run() {
  local bad
  bad=$(find "$RESULTS" -name '*.json' -newer "$MARK" -exec grep -lE '"status": "(FAIL|ERROR|NOT_RUN|UNAVAILABLE)"' {} + 2>/dev/null)
  rm -f "$MARK"
  if [ -n "$bad" ]; then
    echo "not green:"
    local f; for f in $bad; do echo "  ${f##*/}"; done
    exit 1
  fi
}

cmd=${1:-}
shift || true
case "$cmd" in
  tools) rm -f "$MARK"; cmd_tools "$@"; exit $? ;;
  lint) cmd_lint ;;
  test) cmd_test "$@" ;;
  ci-selftest) cmd_ci_selftest ;;
  coverage) cmd_coverage "$@" ;;
  security) cmd_security ;;
  build) cmd_build ;;
  dist) cmd_dist ;;
  package) cmd_package ;;
  fuzz) cmd_fuzz "$@" ;;
  secrets) cmd_secrets "$@" ;;
  harness) cmd_harness ;;
  images) cmd_images ;;
  images-opensbx) cmd_images_opensbx ;;
  manifest) cmd_manifest ;;
  stress) cmd_stress ;;
  mutation) cmd_mutation ;;
  bench) cmd_bench ;;
  links-external) cmd_links_external ;;
  badges) rm -f "$MARK"; cmd_badges "$@"; exit $? ;;
  gate) rm -f "$MARK"; cmd_gate "$@"; exit $? ;;
  openshell) cmd_openshell ;;
  vm) cmd_vm ;;
  local) cmd_local ;;
  *) rm -f "$MARK"; sed -n '2,29p' "$0"; exit 2 ;;
esac
worst_of_run
