#!/bin/bash
# Phase 3: OS hardening against the SCAP Security Guide HIPAA profile, plus the items
# the profile does not cover (firewall, idle timeouts, file integrity, brute-force blocking).
# Run as root. Safe to re-run. Does not reboot.
set -uo pipefail
STAMP=$(date +%Y%m%d)
EVID=/root/hipaa-evidence
DS=/usr/share/xml/scap/ssg/content/ssg-rhel10-ds.xml
PROFILE=xccdf_org.ssgproject.content_profile_hipaa
ADMIN_USER=${ADMIN_USER:-ammar}
BK=/root/config-backup-$STAMP

echo "== config backup -> $BK"
mkdir -p "$BK" && chmod 700 "$BK"
cp -a /etc/ssh /etc/audit /etc/sysctl.conf /etc/sysctl.d /etc/login.defs /etc/issue /etc/dnf/automatic.conf "$BK"/ 2>/dev/null

echo "== firewall"
dnf -y -q install firewalld 2>&1 | tail -1
firewall-offline-cmd --add-service=ssh --add-service=http --add-service=https >/dev/null
systemctl enable --now firewalld
echo "services: $(firewall-cmd --list-services)"

echo "== automatic security updates"
sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
systemctl enable --now dnf-automatic.timer
grep -E '^(upgrade_type|apply_updates)' /etc/dnf/automatic.conf

echo "== named admin account"
if ! id "$ADMIN_USER" &>/dev/null; then
  useradd -m -G wheel "$ADMIN_USER"
  install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" /home/"$ADMIN_USER"/.ssh
  install -m 600 -o "$ADMIN_USER" -g "$ADMIN_USER" /home/ec2-user/.ssh/authorized_keys /home/"$ADMIN_USER"/.ssh/authorized_keys
  echo "$ADMIN_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/90-"$ADMIN_USER"
  chmod 440 /etc/sudoers.d/90-"$ADMIN_USER"
  visudo -cf /etc/sudoers.d/90-"$ADMIN_USER"
fi
id "$ADMIN_USER"

echo "== login banner"
cat > /etc/issue <<'BANNER'
This system is for authorized use only. Activity is monitored and logged.
Unauthorized access is prohibited and may be reported to law enforcement.
BANNER
cp /etc/issue /etc/issue.net

echo "== HIPAA profile remediation (oscap)"
oscap xccdf eval --remediate --profile "$PROFILE" \
  --results "$EVID/remediation-results.xml" "$DS" > "$EVID/remediation-stdout.txt" 2>&1
echo "oscap rc=$?"

echo "== ssh extras"
cat > /etc/ssh/sshd_config.d/01-hipaa-extra.conf <<SSHD
# Loaded before 50-redhat.conf, so these values win.
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
AllowUsers ec2-user $ADMIN_USER
SSHD
chmod 600 /etc/ssh/sshd_config.d/01-hipaa-extra.conf
if sshd -t; then systemctl reload sshd && echo "sshd reloaded"; else echo "SSHD CONFIG INVALID, NOT RELOADED"; fi
sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|x11forwarding|maxauthtries|clientaliveinterval|clientalivecountmax|banner|allowusers) '

echo "== shell idle timeout (15 min)"
cat > /etc/profile.d/tmout.sh <<'TMOUT'
readonly TMOUT=900
export TMOUT
TMOUT
chmod 644 /etc/profile.d/tmout.sh

echo "== file integrity (AIDE)"
dnf -y -q install aide 2>&1 | tail -1
if [ ! -f /var/lib/aide/aide.db.gz ]; then
  aide --init >/dev/null 2>&1
  mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi
cat > /etc/systemd/system/aide-check.service <<'UNIT'
[Unit]
Description=AIDE file integrity check

[Service]
Type=oneshot
ExecStart=/usr/sbin/aide --check
SuccessExitStatus=0 1 2 3 4 5 6 7
UNIT
cat > /etc/systemd/system/aide-check.timer <<'UNIT'
[Unit]
Description=Daily AIDE file integrity check

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now aide-check.timer
ls -la /var/lib/aide/

echo "== brute-force blocking (fail2ban from EPEL)"
if ! rpm -q fail2ban-server &>/dev/null; then
  dnf -y -q install https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm 2>&1 | tail -1
  dnf -y -q install fail2ban-server fail2ban-firewalld 2>&1 | tail -1
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
  fail2ban-client status sshd 2>&1 | head -3
else
  echo "fail2ban NOT installed (EPEL unavailable)"
fi

echo "== post-hardening scan"
oscap xccdf eval --profile "$PROFILE" \
  --results "$EVID/post-results.xml" --report "$EVID/post-report.html" "$DS" > "$EVID/post-stdout.txt" 2>&1
echo "oscap rc=$?"
grep -o '<result>[a-z]*</result>' "$EVID/post-results.xml" | sort | uniq -c
echo "-- still failing"
grep -B3 '^Result.*fail' "$EVID/post-stdout.txt" | grep '^Rule' | awk '{print $2}' | sed 's/xccdf_org.ssgproject.content_rule_//'
echo "== state"
getenforce; systemctl is-active firewalld auditd fail2ban dnf-automatic.timer aide-check.timer
df -h / | tail -1
