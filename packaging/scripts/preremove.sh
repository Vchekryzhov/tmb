#!/bin/sh
# tmb-broker preremove (deb: remove | upgrade ...; rpm: 0 erase, 1 upgrade).
# Stops the broker only when the package goes away, not on upgrade;
# KillMode=process lets approved commands that already run finish.
set -e
case "${1:-}" in
  remove|0)
    if [ -d /run/systemd/system ]; then
      systemctl stop tmb-broker.service || true
      systemctl disable tmb-broker.service >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
