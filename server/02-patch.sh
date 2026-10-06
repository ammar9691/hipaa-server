#!/bin/bash
# Phase 2a: apply all pending updates and turn on automatic security updates. No reboot here.
set -uo pipefail
dnf -y -q upgrade 2>&1 | tail -3
dnf -y -q install dnf-automatic 2>&1 | tail -2
mkdir -p /etc/dnf/dnf5-plugins
ls /etc/dnf/automatic.conf /etc/dnf/dnf5-plugins/automatic.conf /usr/share/dnf5/dnf5-plugins/automatic.conf 2>/dev/null
systemctl list-unit-files 'dnf*automatic*' --no-legend
echo "pending updates now: $(dnf -q check-update 2>/dev/null | grep -c .)"
echo "running kernel: $(uname -r)"
echo "newest kernel:  $(rpm -q kernel --last | head -1)"
dnf needs-restarting -r 2>&1 | tail -2
df -h / | tail -1
