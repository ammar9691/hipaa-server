#!/bin/bash
# Phase 1: swap + OpenSCAP baseline scan (HIPAA profile). No hardening yet.
set -uo pipefail
STAMP=20261005
EVID=/root/hipaa-evidence
mkdir -p "$EVID" && chmod 700 "$EVID"

echo "== swap"
if ! swapon --show | grep -q /swapfile; then
  cp -a /etc/fstab /etc/fstab.bak-$STAMP
  dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  restorecon /swapfile
  swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap defaults 0 0' >> /etc/fstab
fi
swapon --show
free -m | sed -n 2,3p

echo "== install scanner"
dnf -y -q install openscap-scanner scap-security-guide 2>&1 | tail -5
rpm -q openscap-scanner scap-security-guide

echo "== content"
ls /usr/share/xml/scap/ssg/content/
DS=$(ls /usr/share/xml/scap/ssg/content/ssg-rhel10-ds.xml 2>/dev/null)
[ -z "$DS" ] && { echo "NO RHEL10 DATASTREAM"; exit 3; }
oscap info "$DS" | grep -A1 -iE 'Title:' | grep -vE '^--$' | paste - - | sed 's/\t/ | /' | head -40

echo "== baseline scan"
if oscap info "$DS" | grep -q 'content_profile_hipaa'; then
  oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_hipaa \
    --results "$EVID/baseline-results.xml" --report "$EVID/baseline-report.html" "$DS" > "$EVID/baseline-stdout.txt" 2>&1
  echo "oscap rc=$?"
  grep -o '<result>[a-z]*</result>' "$EVID/baseline-results.xml" | sort | uniq -c
  echo "-- failed rules"
  grep -B3 '^Result.*fail' "$EVID/baseline-stdout.txt" | grep '^Rule' | awk '{print $2}' | sed 's/xccdf_org.ssgproject.content_rule_//'
else
  echo "NO HIPAA PROFILE IN RHEL10 CONTENT"
fi
df -h / | tail -1
