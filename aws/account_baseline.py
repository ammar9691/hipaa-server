#!/usr/bin/env python3
"""AWS-side controls for the HIPAA server build. Safe to re-run.

1. Security group: SSH only from one admin IP, 80/443 open.
2. S3: account-level public access block, a CloudTrail bucket and a backups bucket
   (private, versioned, encrypted, TLS-only).
3. CloudTrail: multi-region trail with log file validation.
4. IAM role + instance profile for the server (CloudWatch agent, SSM, write to the backups bucket).
5. AWS Backup: encrypted vault, daily plan with 14-day retention, selection by tag.

Config comes from ../.env. Usage: python account_baseline.py <instance-id> <admin-ip>
"""
import json
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = "hipaa-server"
TAGS = [{"Key": "Project", "Value": PROJECT}]


def load_env(path):
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)


def log(msg):
    print(msg, flush=True)


def ignore(codes, fn, *a, **kw):
    """Run fn, treating the listed AWS error codes as 'already done'."""
    try:
        return fn(*a, **kw)
    except ClientError as e:
        if e.response["Error"]["Code"] in codes:
            return None
        raise


def security_group(ec2, instance_id, admin_ip):
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    sg_id = inst["SecurityGroups"][0]["GroupId"]
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    for perm in sg["IpPermissions"]:
        if perm.get("FromPort") == 22 and any(r["CidrIp"] == "0.0.0.0/0" for r in perm["IpRanges"]):
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    wanted = [(22, f"{admin_ip}/32", "admin ssh"), (80, "0.0.0.0/0", "http"), (443, "0.0.0.0/0", "https")]
    for port, cidr, desc in wanted:
        ignore(["InvalidPermission.Duplicate"], ec2.authorize_security_group_ingress, GroupId=sg_id, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": cidr, "Description": desc}]}])
    ec2.create_tags(Resources=[instance_id], Tags=TAGS)
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    log(f"sg {sg_id}: " + ", ".join(f"{p['FromPort']}<-{[r['CidrIp'] for r in p['IpRanges']]}" for p in sg["IpPermissions"]))


def bucket(s3, name, region, extra_statements=()):
    ignore(["BucketAlreadyOwnedByYou"], s3.create_bucket, Bucket=name,
           CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": True}]})
    arn = f"arn:aws:s3:::{name}"
    statements = [{"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                   "Resource": [arn, f"{arn}/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]
    statements += list(extra_statements)
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": TAGS})
    log(f"bucket {name}: private, versioned, encrypted, TLS-only")


def cloudtrail(account, region, trail_bucket):
    ct = boto3.client("cloudtrail")
    name = f"{PROJECT}-trail"
    ignore(["TrailAlreadyExistsException"], ct.create_trail, Name=name, S3BucketName=trail_bucket,
           IsMultiRegionTrail=True, IncludeGlobalServiceEvents=True, EnableLogFileValidation=True,
           TagsList=TAGS)
    ct.start_logging(Name=name)
    st = ct.get_trail_status(Name=name)
    log(f"cloudtrail {name}: logging={st['IsLogging']} multi-region, log file validation on")


def instance_role(ec2, instance_id, backup_bucket):
    iam = boto3.client("iam")
    name = f"{PROJECT}-ec2"
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    ignore(["EntityAlreadyExists"], iam.create_role, RoleName=name,
           AssumeRolePolicyDocument=json.dumps(trust), Tags=TAGS)
    for arn in ("arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
                "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"):
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
    b = f"arn:aws:s3:::{backup_bucket}"
    iam.put_role_policy(RoleName=name, PolicyName="backups-bucket-write", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": b},
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": f"{b}/*"}]}))
    ignore(["EntityAlreadyExists"], iam.create_instance_profile, InstanceProfileName=name)
    ignore(["LimitExceeded"], iam.add_role_to_instance_profile, InstanceProfileName=name, RoleName=name)
    assoc = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}])["IamInstanceProfileAssociations"]
    if not assoc:
        for _ in range(8):  # a new instance profile takes a few seconds to become visible to EC2
            try:
                ec2.associate_iam_instance_profile(InstanceId=instance_id, IamInstanceProfile={"Name": name})
                break
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidParameterValue":
                    raise
                time.sleep(5)
    log(f"instance profile {name}: attached (CloudWatch agent, SSM, write to {backup_bucket})")


def backups(account, region):
    iam = boto3.client("iam")
    role = "AWSBackupDefaultServiceRole"
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    ignore(["EntityAlreadyExists"], iam.create_role, RoleName=role, Path="/service-role/",
           AssumeRolePolicyDocument=json.dumps(trust))
    for p in ("AWSBackupServiceRolePolicyForBackup", "AWSBackupServiceRolePolicyForRestores"):
        iam.attach_role_policy(RoleName=role, PolicyArn=f"arn:aws:iam::aws:policy/service-role/{p}")
    bk = boto3.client("backup")
    vault = f"{PROJECT}-vault"
    ignore(["AlreadyExistsException"], bk.create_backup_vault, BackupVaultName=vault, BackupVaultTags={"Project": PROJECT})
    plans = [p for p in bk.list_backup_plans()["BackupPlansList"] if p["BackupPlanName"] == f"{PROJECT}-daily"]
    if plans:
        plan_id = plans[0]["BackupPlanId"]
    else:
        plan_id = bk.create_backup_plan(BackupPlan={"BackupPlanName": f"{PROJECT}-daily", "Rules": [{
            "RuleName": "daily-14d", "TargetBackupVaultName": vault,
            "ScheduleExpression": "cron(0 21 * * ? *)", "StartWindowMinutes": 60, "CompletionWindowMinutes": 180,
            "Lifecycle": {"DeleteAfterDays": 14}}]}, BackupPlanTags={"Project": PROJECT})["BackupPlanId"]
    if not bk.list_backup_selections(BackupPlanId=plan_id)["BackupSelectionsList"]:
        for _ in range(6):  # a new role takes a few seconds before Backup can assume it
            try:
                bk.create_backup_selection(BackupPlanId=plan_id, BackupSelection={
                    "SelectionName": "by-project-tag",
                    "IamRoleArn": f"arn:aws:iam::{account}:role/service-role/{role}",
                    "ListOfTags": [{"ConditionType": "STRINGEQUALS", "ConditionKey": "Project", "ConditionValue": PROJECT}]})
                break
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidParameterValueException":
                    raise
                time.sleep(10)
    log(f"aws backup: vault {vault}, daily at 21:00 UTC, 14-day retention, selects tag Project={PROJECT}")


def main():
    instance_id, admin_ip = sys.argv[1], sys.argv[2]
    load_env(os.path.join(HERE, "..", ".env"))
    region = os.environ["AWS_DEFAULT_REGION"]
    account = boto3.client("sts").get_caller_identity()["Account"]
    ec2 = boto3.client("ec2")
    s3 = boto3.client("s3")

    security_group(ec2, instance_id, admin_ip)

    boto3.client("s3control").put_public_access_block(AccountId=account, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    log("s3: account-level public access block on")

    trail_bucket = f"{PROJECT}-cloudtrail-{account}"
    backup_bucket = f"{PROJECT}-backups-{account}"
    t = f"arn:aws:s3:::{trail_bucket}"
    bucket(s3, trail_bucket, region, extra_statements=[
        {"Sid": "CloudTrailAclCheck", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:GetBucketAcl", "Resource": t},
        {"Sid": "CloudTrailWrite", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:PutObject", "Resource": f"{t}/AWSLogs/{account}/*",
         "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}}])
    bucket(s3, backup_bucket, region)

    cloudtrail(account, region, trail_bucket)
    instance_role(ec2, instance_id, backup_bucket)
    backups(account, region)
    log("DONE")


if __name__ == "__main__":
    main()
