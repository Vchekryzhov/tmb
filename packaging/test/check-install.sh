#!/usr/bin/env bash
# Install test of the TMB packages inside a disposable Ubuntu (deb) or Fedora
# (rpm) image build (ci/run.sh package). systemd is not running here: the
# test checks package contents, modes, versions, the unit's static validity
# and removal, never the service's behaviour.
#
#   check-install.sh deb|rpm VERSION NATIVE_ARCH     packages in /dist
#
# Prints CHECK PASS|FAIL lines and ends with RESULT: GREEN or RESULT: RED.
set -uo pipefail
kind=${1:?deb|rpm} ver=${2:?version tag} arch=${3:?amd64|arm64}
fails=0
pass() { echo "CHECK PASS $1"; }
fail() { echo "CHECK FAIL $1"; fails=$((fails + 1)); }
check() { local name=$1; shift; if "$@" >/tmp/check.out 2>&1; then pass "$name"; else fail "$name: $(tr '\n' ' ' </tmp/check.out | cut -c1-300)"; fi; }
# eq NAME GOT WANT
eq() { if [ "$2" = "$3" ]; then pass "$1 = $3"; else fail "$1 = '$2', want '$3'"; fi; }

# package version: the tag without v, a pre-release joined with ~ (sorts
# before the release), package release 1
pkgver=${ver#v}
case "$pkgver" in *-*) pkgver="${pkgver%%-*}~${pkgver#*-}" ;; esac
other=amd64; [ "$arch" = amd64 ] && other=arm64
if [ "$kind" = deb ]; then
  darch() { echo "$1"; }
  pkgfile() { echo "/dist/${1}_${pkgver}-1_$(darch "$2").deb"; }
else
  darch() { if [ "$1" = amd64 ]; then echo x86_64; else echo aarch64; fi; }
  pkgfile() { echo "/dist/${1}-${pkgver}-1.$(darch "$2").rpm"; }
fi

echo "== metadata of every $kind (both architectures, nothing installed yet)"
for a in amd64 arm64; do
  for p in tmb-broker tmb; do
    f=$(pkgfile "$p" "$a")
    if [ ! -f "$f" ]; then fail "$f exists"; continue; fi
    if [ "$kind" = deb ]; then
      eq "$p/$a Package" "$(dpkg-deb -f "$f" Package)" "$p"
      eq "$p/$a Architecture" "$(dpkg-deb -f "$f" Architecture)" "$a"
      eq "$p/$a Version" "$(dpkg-deb -f "$f" Version)" "$pkgver-1"
      files=$(dpkg-deb -c "$f" | awk '{print $6}' | sed 's|^\./|/|')
    else
      eq "$p/$a name arch version" "$(rpm -qp --qf '%{NAME} %{ARCH} %{VERSION}-%{RELEASE}' "$f")" "$p $(darch "$a") $pkgver-1"
      files=$(rpm -qlp "$f")
    fi
    if [ "$p" = tmb-broker ]; then
      for want in /usr/bin/tmb-broker /usr/lib/systemd/system/tmb-broker.service /etc/tmb/config.json.example \
                  /etc/logrotate.d/tmb-broker /usr/lib/tmpfiles.d/tmb.conf /var/lib/tmb /var/log/tmb; do
        if grep -qx "$want/\?" <<<"$files"; then pass "$p/$a ships $want"; else fail "$p/$a ships $want"; fi
      done
      if grep -qx '/etc/tmb/config.json' <<<"$files"; then fail "$p/$a must not ship /etc/tmb/config.json"; else pass "$p/$a ships no config.json"; fi
    else
      if grep -qx /usr/bin/tmb <<<"$files"; then pass "$p/$a ships /usr/bin/tmb"; else fail "$p/$a ships /usr/bin/tmb"; fi
    fi
  done
done
echo "(other architecture $other: metadata only; its binaries do not run here)"

echo "== install ($arch)"
if [ "$kind" = deb ]; then
  check "dpkg -i tmb-broker tmb" dpkg -i "$(pkgfile tmb-broker "$arch")" "$(pkgfile tmb "$arch")"
else
  check "rpm -i tmb-broker tmb" rpm -i "$(pkgfile tmb-broker "$arch")" "$(pkgfile tmb "$arch")"
fi
eq "tmb-broker -version" "$(/usr/bin/tmb-broker -version 2>&1)" "tmb-broker $ver"
eq "tmb version" "$(/usr/bin/tmb version 2>&1)" "tmb $ver"

# mode owner:group of a path
mo() { stat -c '%a %U:%G' "$1" 2>&1; }
eq "/usr/bin/tmb-broker mode" "$(mo /usr/bin/tmb-broker)" "755 root:root"
eq "/usr/bin/tmb mode" "$(mo /usr/bin/tmb)" "755 root:root"
eq "unit mode" "$(mo /usr/lib/systemd/system/tmb-broker.service)" "644 root:root"
eq "config example mode" "$(mo /etc/tmb/config.json.example)" "644 root:root"
eq "logrotate mode" "$(mo /etc/logrotate.d/tmb-broker)" "644 root:root"
eq "tmpfiles mode" "$(mo /usr/lib/tmpfiles.d/tmb.conf)" "644 root:root"
eq "/var/lib/tmb" "$(mo /var/lib/tmb)" "700 root:root"
eq "/var/log/tmb" "$(mo /var/log/tmb)" "750 root:root"
check "no /etc/tmb/config.json after install" test ! -e /etc/tmb/config.json

echo "== config example"
check "example sets allowed_cwd_roots [\"/tmp\"]" grep -q '"allowed_cwd_roots": \["/tmp"\]' /etc/tmb/config.json.example
check "example sets approval_default queue" grep -q '"approval_default": "queue"' /etc/tmb/config.json.example

echo "== systemd unit (static)"
unit=/usr/lib/systemd/system/tmb-broker.service
for d in 'Type=simple' 'User=root' 'RuntimeDirectory=tmb' 'StateDirectory=tmb' 'LogsDirectory=tmb' \
         'Restart=on-failure' 'KillMode=process' "ExecReload=/bin/kill -HUP \$MAINPID" \
         'ExecStart=/usr/bin/tmb-broker -config /etc/tmb/config.json'; do
  if grep -qxF "$d" "$unit"; then pass "unit has $d"; else fail "unit has $d"; fi
done
check "unit ExecStartPre requires /etc/tmb/config.json" grep -q '^ExecStartPre=.*test -f /etc/tmb/config.json' "$unit"
for d in ProtectSystem PrivateTmp ProtectHome; do
  if grep -q "^$d=" "$unit"; then fail "unit must not set $d"; else pass "unit has no $d"; fi
done
if command -v systemd-analyze >/dev/null; then
  # no running systemd: verify loads the unit offline and checks its syntax
  # and the executables it names
  check "systemd-analyze verify tmb-broker.service" systemd-analyze verify "$unit"
else
  fail "systemd-analyze not installed in the test image"
fi

echo "== tmpfiles.d and logrotate configs"
if command -v systemd-tmpfiles >/dev/null; then
  check "systemd-tmpfiles --create tmb.conf" systemd-tmpfiles --create /usr/lib/tmpfiles.d/tmb.conf
  eq "/run/tmb" "$(mo /run/tmb)" "755 root:root"
else
  fail "systemd-tmpfiles not installed in the test image"
fi
if command -v logrotate >/dev/null; then
  mkdir -p /var/lib/logrotate
  echo '{"schema":1,"event":"broker_start"}' >/var/log/tmb/journal.jsonl
  # -d: parse and plan the rotation without doing it
  check "logrotate -d accepts /etc/logrotate.d/tmb-broker" logrotate -d /etc/logrotate.d/tmb-broker
  check "logrotate config names postrotate systemctl reload" grep -q 'systemctl reload tmb-broker.service' /etc/logrotate.d/tmb-broker
else
  fail "logrotate not installed in the test image"
fi

echo "== removal keeps config, state and journal"
echo '{}' >/etc/tmb/config.json
echo state >/var/lib/tmb/marker
echo '{"schema":1}' >>/var/log/tmb/journal.jsonl
if [ "$kind" = deb ]; then
  check "dpkg -r tmb-broker tmb" dpkg -r tmb-broker tmb
else
  check "rpm -e tmb-broker tmb" rpm -e tmb-broker tmb
fi
check "binary removed" test ! -e /usr/bin/tmb-broker
check "client removed" test ! -e /usr/bin/tmb
check "unit removed" test ! -e /usr/lib/systemd/system/tmb-broker.service
check "config.json kept" test -s /etc/tmb/config.json
check "state kept" test -s /var/lib/tmb/marker
check "journal kept" test -s /var/log/tmb/journal.jsonl

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: GREEN ($kind, $arch, $ver)"; exit 0; fi
echo "RESULT: RED ($fails failed checks)"
exit 1
