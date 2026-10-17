#!/bin/sh
# tmb-broker postremove. /etc/tmb/config.json, /var/lib/tmb and /var/log/tmb
# stay: removing the package never deletes the config, the state or the journal.
set -e
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
exit 0
