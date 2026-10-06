#!/bin/bash
# The HIPAA remediation points rsyslog at a placeholder host ("logcollector") that does not exist.
# Remove it; off-server log shipping is handled by the CloudWatch agent instead.
set -uo pipefail
cp -a /etc/rsyslog.conf /etc/rsyslog.conf.bak-$(date +%Y%m%d)
sed -i '/^\*\.\* @@logcollector$/d; /Set \*\.\* @@logcollector/d' /etc/rsyslog.conf
rsyslogd -N1 2>&1 | tail -1
systemctl restart rsyslog && systemctl is-active rsyslog
grep -c logcollector /etc/rsyslog.conf
