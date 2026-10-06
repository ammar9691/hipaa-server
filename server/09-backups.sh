#!/bin/bash
# Nightly database + wp-content backup to the private encrypted S3 bucket, plus a restore test that
# proves the dump can actually be loaded. Bucket name comes from BACKUP_BUCKET.
set -uo pipefail
BUCKET=${BACKUP_BUCKET:?set BACKUP_BUCKET}

rpm -q awscli2 &>/dev/null || dnf -y -q install awscli2 2>&1 | tail -1
aws --version

cat > /usr/local/sbin/hipaa-backup.sh <<BK
#!/bin/bash
# Daily backup: MariaDB dump + wp-content -> S3 (server-side encrypted, TLS in transit). Logs to /var/log/hipaa-backup.log
set -euo pipefail
BUCKET=$BUCKET
HOST=\$(hostname -s)
DAY=\$(date -u +%F)
WORK=\$(mktemp -d /root/backup.XXXXXX); trap 'rm -rf "\$WORK"' EXIT
mysqldump --single-transaction --quick --routines --events wordpress | gzip -6 > "\$WORK/wordpress-\$DAY.sql.gz"
tar -czf "\$WORK/wp-content-\$DAY.tar.gz" -C /var/www/wordpress wp-content
cp /var/www/wordpress/wp-config.php "\$WORK/wp-config-\$DAY.php"
sha256sum "\$WORK"/* > "\$WORK/SHA256SUMS-\$DAY.txt"
aws s3 cp "\$WORK" "s3://\$BUCKET/\$HOST/\$DAY/" --recursive --sse AES256 --only-show-errors
echo "\$(date -u +%FT%TZ) OK \$DAY \$(du -sh "\$WORK" | cut -f1) -> s3://\$BUCKET/\$HOST/\$DAY/" >> /var/log/hipaa-backup.log
BK
chmod 700 /usr/local/sbin/hipaa-backup.sh

cat > /usr/local/sbin/hipaa-restore-test.sh <<RT
#!/bin/bash
# Restore test: pull the newest dump from S3, load it into a scratch database, compare table counts, drop it.
set -euo pipefail
BUCKET=$BUCKET
HOST=\$(hostname -s)
DAY=\$(aws s3 ls "s3://\$BUCKET/\$HOST/" | awk '{print \$2}' | tr -d / | sort | tail -1)
WORK=\$(mktemp -d /root/restore.XXXXXX); trap 'rm -rf "\$WORK"' EXIT
aws s3 cp "s3://\$BUCKET/\$HOST/\$DAY/wordpress-\$DAY.sql.gz" "\$WORK/" --only-show-errors
aws s3 cp "s3://\$BUCKET/\$HOST/\$DAY/SHA256SUMS-\$DAY.txt" "\$WORK/" --only-show-errors
(cd "\$WORK" && grep "wordpress-\$DAY.sql.gz" "SHA256SUMS-\$DAY.txt" | sed 's#/root/backup[^/]*/##' | sha256sum -c --quiet)
mysql -e "DROP DATABASE IF EXISTS restoretest; CREATE DATABASE restoretest"
gunzip -c "\$WORK/wordpress-\$DAY.sql.gz" | mysql restoretest
LIVE=\$(mysql -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='wordpress'")
REST=\$(mysql -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='restoretest'")
POSTS=\$(mysql -N -e "SELECT COUNT(*) FROM restoretest.wp_posts")
mysql -e "DROP DATABASE restoretest"
RESULT=FAIL; [ "\$LIVE" = "\$REST" ] && RESULT=OK
echo "\$(date -u +%FT%TZ) RESTORE-TEST \$RESULT backup=\$DAY tables live=\$LIVE restored=\$REST posts=\$POSTS checksum=verified" | tee -a /var/log/hipaa-backup.log
[ "\$RESULT" = OK ]
RT
chmod 700 /usr/local/sbin/hipaa-restore-test.sh

cat > /etc/systemd/system/hipaa-backup.service <<'UNIT'
[Unit]
Description=Nightly HIPAA server backup to S3
After=network-online.target mariadb.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hipaa-backup.sh
UNIT
cat > /etc/systemd/system/hipaa-backup.timer <<'UNIT'
[Unit]
Description=Nightly HIPAA server backup to S3

[Timer]
OnCalendar=*-*-* 02:00:00 UTC
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
UNIT
cat > /etc/systemd/system/hipaa-restore-test.service <<'UNIT'
[Unit]
Description=Weekly restore test of the newest S3 backup
After=network-online.target mariadb.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hipaa-restore-test.sh
UNIT
cat > /etc/systemd/system/hipaa-restore-test.timer <<'UNIT'
[Unit]
Description=Weekly restore test of the newest S3 backup

[Timer]
OnCalendar=Sun *-*-* 04:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT
install -m 600 /dev/null /var/log/hipaa-backup.log 2>/dev/null; touch /var/log/hipaa-backup.log; chmod 600 /var/log/hipaa-backup.log
systemctl daemon-reload
systemctl enable --now hipaa-backup.timer hipaa-restore-test.timer >/dev/null 2>&1
systemctl list-timers --no-pager 'hipaa-*' 'aide*' 'dnf-automatic*' 'certbot*' | head -8

echo "== first backup + restore test now"
/usr/local/sbin/hipaa-backup.sh && tail -1 /var/log/hipaa-backup.log
/usr/local/sbin/hipaa-restore-test.sh
aws s3 ls "s3://$BUCKET/" --recursive --human-readable | tail -5
