# hipaa-server

Scripts and documentation for building a HIPAA-aligned single-server WordPress host on AWS EC2 (RHEL 10). Built once on a real instance in October 2026 and decommissioned with `aws/teardown.py` after the evidence was captured; the before/after OpenSCAP results from that build are summarised in `evidence/SUMMARY.md`.

Result on the reference build: SCAP Security Guide HIPAA profile went from 36 pass / 121 fail to 153 pass / 4 fail, with the 4 written up as exceptions in `docs/COMPLIANCE.md`.

## What it sets up

- Encrypted root volume (swapped in from a snapshot if the instance was launched unencrypted), EBS encryption by default, Elastic IP
- Security group: SSH from one admin IP, 80/443 public; firewalld on the host
- OpenSCAP remediation against the HIPAA profile, plus SSH idle timeout, named admin account, login banner, AIDE, fail2ban, automatic security updates
- CloudTrail (multi-region, log validation), private versioned encrypted S3 buckets, IAM instance role, AWS Backup daily plan
- nginx + PHP-FPM + MariaDB (localhost only) + WordPress with Let's Encrypt, TLS 1.2/1.3, HSTS, security headers; the WordPress install is completed server-side so the install wizard is never public
- Nightly dump + files backup to S3 with SHA-256 manifest, weekly automated restore test

## Layout

```
aws/      boto3 scripts run from the admin machine (encrypt root volume, account baseline, backup lifecycle)
server/   bash scripts streamed to the instance as root, numbered in run order
docs/     COMPLIANCE.md: risk analysis, control mapping, exceptions, incident procedure
evidence/ scan result summary (full HTML reports stay with the server records)
run_script.py  streams a local script to `sudo bash -s` over SSH (paramiko), alias from a servers.json
```

## Run order

1. `aws/encrypt_root_volume.py <instance-id> --size 20 --type t3.small`
2. `server/01-baseline-scan.sh`
3. `server/02-patch.sh`, then `03-harden.sh`, `04-fixups.sh`, `05-rsyslog-fix.sh`, reboot
4. `aws/account_baseline.py <instance-id> <admin-ip>`
5. `server/07-web-stack.sh`
6. `DOMAIN=... ADMIN_EMAIL=... server/08-site-tls.sh` (after the DNS A record exists)
7. `BACKUP_BUCKET=... server/09-backups.sh`, then `aws/backup_lifecycle.py <bucket>`
8. `server/06-cloudwatch-agent.sh` (verifies Amazon's signature with GnuPG, then installs with the rpm check skipped; see the exception in `docs/COMPLIANCE.md`)

AWS credentials are read from a `.env` next to `aws/` (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`). Nothing in this repository contains account IDs, addresses or keys; the `.gitignore` excludes `.env`, `*.pem` and `*.csv`.

## Notes from the build

- Amazon Lightsail is not on the AWS HIPAA-eligible services list; use EC2.
- RHEL 10's default crypto policy rejects some older vendor signing keys (Amazon's CloudWatch agent key among them). With `localpkg_gpgcheck=1` enforced, those packages will not install until the key question is resolved.
- EPEL packages install only after `rpm --import` of the EPEL 10 key, for the same reason.
- The HIPAA profile remediation sets rsyslog to forward to a host called `logcollector`; remove it or point it at a real collector.
- No "HIPAA certified" server exists. The deliverable is the BAA, the safeguards, and the written record.
