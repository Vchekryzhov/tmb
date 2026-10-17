#!/bin/sh
# tmb-broker postinstall (deb: configure [old-version]; rpm: 1 install, 2 upgrade).
# Never enables or starts the service: it needs /etc/tmb/config.json first.
set -e
upgrade=0
case "${1:-}" in
  configure) if [ -n "${2:-}" ]; then upgrade=1; fi ;;
  [2-9]) upgrade=1 ;;
esac
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/tmb.conf || true
  # an upgrade restarts a running broker; KillMode=process keeps approved commands
  if [ "$upgrade" = 1 ]; then systemctl try-restart tmb-broker.service || true; fi
fi
exit 0
