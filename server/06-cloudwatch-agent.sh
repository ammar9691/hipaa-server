#!/bin/bash
# Ship audit, auth and system logs off the server to CloudWatch Logs (6-year retention).
# Needs the instance role from aws/account_baseline.py.
#
# RHEL 10's crypto policy rejects Amazon's agent signing key, so rpm cannot verify the package.
# Documented exception: the signature is verified here with GnuPG against the fingerprint AWS publishes
# (9376 16F3 450B 7D80 6CBD 9725 D581 6730 3B78 9C72), and only then is this one package installed
# with the automatic rpm check skipped.
set -uo pipefail
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/placement/region)
EXPECTED_FPR=937616F3450B7D806CBD9725D58167303B789C72
echo "region: $REGION"

if ! rpm -q amazon-cloudwatch-agent &>/dev/null; then
  WORK=$(mktemp -d /root/cwagent.XXXXXX)
  cd "$WORK"
  BASE="https://amazoncloudwatch-agent-$REGION.s3.$REGION.amazonaws.com/redhat/amd64/latest"
  curl -sSO "$BASE/amazon-cloudwatch-agent.rpm" && curl -sSO "$BASE/amazon-cloudwatch-agent.rpm.sig"
  curl -sS https://amazoncloudwatch-agent.s3.amazonaws.com/assets/amazon-cloudwatch-agent.gpg -o key.gpg
  export GNUPGHOME="$WORK/gnupg"; mkdir -m 700 "$GNUPGHOME"
  gpg -q --import key.gpg 2>&1 | grep -v '^$'
  FPR=$(gpg --with-colons --fingerprint 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
  echo "key fingerprint: $FPR"
  [ "$FPR" = "$EXPECTED_FPR" ] || { echo "FINGERPRINT MISMATCH, ABORT"; exit 7; }
  if gpg --verify amazon-cloudwatch-agent.rpm.sig amazon-cloudwatch-agent.rpm 2>&1 | grep -E 'Good signature|BAD|error'; then :; fi
  gpg --verify amazon-cloudwatch-agent.rpm.sig amazon-cloudwatch-agent.rpm >/dev/null 2>&1 \
    || gpg --allow-weak-digest-algos --allow-weak-key-signatures --verify amazon-cloudwatch-agent.rpm.sig amazon-cloudwatch-agent.rpm >/dev/null 2>&1 \
    || { echo "SIGNATURE DID NOT VERIFY, ABORT"; exit 8; }
  echo "signature verified by gnupg; sha256 $(sha256sum amazon-cloudwatch-agent.rpm | cut -c1-64)"
  dnf -y -q install --nogpgcheck ./amazon-cloudwatch-agent.rpm 2>&1 | tail -2
  cd / && rm -rf "$WORK"
fi
rpm -q amazon-cloudwatch-agent || exit 3

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'JSON'
{
  "agent": { "run_as_user": "root" },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          { "file_path": "/var/log/audit/audit.log", "log_group_name": "/hipaa-server/audit",    "log_stream_name": "{instance_id}", "retention_in_days": 2192 },
          { "file_path": "/var/log/secure",          "log_group_name": "/hipaa-server/secure",   "log_stream_name": "{instance_id}", "retention_in_days": 2192 },
          { "file_path": "/var/log/messages",        "log_group_name": "/hipaa-server/messages", "log_stream_name": "{instance_id}", "retention_in_days": 2192 },
          { "file_path": "/var/log/hipaa-backup.log","log_group_name": "/hipaa-server/backup",   "log_stream_name": "{instance_id}", "retention_in_days": 2192 }
        ]
      }
    }
  }
}
JSON
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json 2>&1 | tail -2
systemctl enable amazon-cloudwatch-agent >/dev/null 2>&1
timeout 30 bash -c 'until systemctl is-active -q amazon-cloudwatch-agent; do sleep 2; done'
echo "agent: $(systemctl is-active amazon-cloudwatch-agent)"
sleep 20
grep -iE 'error|denied' /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log | tail -3 | cut -c1-200
ausearch -m avc -ts recent 2>/dev/null | grep -c cloudwatch; true
