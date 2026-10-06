#!/usr/bin/env python3
"""Lifecycle rule for the backups bucket: current objects expire after 35 days, old versions after 7."""
import os, sys
import boto3
HERE = os.path.dirname(os.path.abspath(__file__))
for line in open(os.path.join(HERE, "..", ".env"), encoding="utf-8"):
    if "=" in line and not line.startswith("#"):
        k, v = line.strip().split("=", 1); os.environ.setdefault(k, v)
bucket = sys.argv[1]
boto3.client("s3").put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": [{
    "ID": "expire-backups", "Status": "Enabled", "Filter": {"Prefix": ""},
    "Expiration": {"Days": 35}, "NoncurrentVersionExpiration": {"NoncurrentDays": 7},
    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 2}}]})
print(f"{bucket}: expire after 35 days, old versions after 7")
