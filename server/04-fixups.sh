#!/bin/bash
# Phase 3b: close what the first hardening pass left open.
set -uo pipefail

echo "== firewall: drop services nobody asked for"
firewall-cmd -q --permanent --remove-service=cockpit --remove-service=dhcpv6-client
firewall-cmd -q --reload
echo "services: $(firewall-cmd --list-services)"

echo "== package manager still healthy after gpgcheck changes"
grep -E 'gpgcheck' /etc/dnf/dnf.conf
dnf -q makecache 2>&1 | tail -2; echo "makecache rc=$?"

echo "== fail2ban (EPEL key imported first, local package signature checks are now enforced)"
if ! rpm -q fail2ban-server &>/dev/null; then
  rpm --import https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-10
  dnf -y -q install https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm 2>&1 | tail -1
  dnf -y -q install fail2ban-server fail2ban-firewalld 2>&1 | tail -2
fi
if rpm -q fail2ban-server &>/dev/null; then
  cat > /etc/fail2ban/jail.local <<'JAIL'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
JAIL
  systemctl enable --now fail2ban
  fail2ban-client status sshd 2>&1 | head -4
else
  echo "fail2ban STILL NOT INSTALLED"
fi

echo "== listening / users"
ss -tlnp | awk 'NR>1{print $4, $6}'
grep -c . /etc/audit/rules.d/*.rules | tail -5
