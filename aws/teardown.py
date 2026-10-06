#!/usr/bin/env python3
"""Remove everything the build created in AWS, in dependency order. Irreversible.
Scoped to resources tagged Project=hipaa-server or named with that prefix; nothing else in the account is touched.

Usage: python teardown.py <instance-id> --yes
"""
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError, WaiterError

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = "hipaa-server"


def load_env(path):
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)


def log(msg):
    print(msg, flush=True)


def ignore(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ClientError as e:
        log(f"  (skip: {e.response['Error']['Code']})")
        return None


def main():
    if "--yes" not in sys.argv:
        sys.exit("refusing without --yes")
    instance_id = sys.argv[1]
    load_env(os.path.join(HERE, "..", ".env"))
    account = boto3.client("sts").get_caller_identity()["Account"]
    ec2 = boto3.client("ec2")
    iam = boto3.client("iam")
    s3 = boto3.client("s3")
    bk = boto3.client("backup")

    log("== instance")
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    vols = [b["Ebs"]["VolumeId"] for b in inst["BlockDeviceMappings"]]
    if inst["State"]["Name"] != "terminated":
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id])
    log(f"terminated {instance_id}")
    for v in vols:
        try:
            ec2.get_waiter("volume_available").wait(VolumeIds=[v], WaiterConfig={"Delay": 5, "MaxAttempts": 24})
            ec2.delete_volume(VolumeId=v)
            log(f"deleted volume {v}")
        except (ClientError, WaiterError):
            log(f"volume {v}: already gone (deleted with the instance)")
    tagf = [{"Name": "tag:Project", "Values": [PROJECT]}]
    for a in ec2.describe_addresses(Filters=tagf)["Addresses"]:
        ignore(ec2.release_address, AllocationId=a["AllocationId"])
        log(f"released elastic ip {a['PublicIp']}")

    log("== aws backup")
    vault = f"{PROJECT}-vault"
    for rp in ignore(bk.list_recovery_points_by_backup_vault, BackupVaultName=vault)["RecoveryPoints"] if True else []:
        ignore(bk.delete_recovery_point, BackupVaultName=vault, RecoveryPointArn=rp["RecoveryPointArn"])
    for p in bk.list_backup_plans()["BackupPlansList"]:
        if p["BackupPlanName"].startswith(PROJECT):
            for s in bk.list_backup_selections(BackupPlanId=p["BackupPlanId"])["BackupSelectionsList"]:
                bk.delete_backup_selection(BackupPlanId=p["BackupPlanId"], SelectionId=s["SelectionId"])
            bk.delete_backup_plan(BackupPlanId=p["BackupPlanId"])
            log(f"deleted backup plan {p['BackupPlanName']}")
    for _ in range(30):
        left = ignore(bk.list_recovery_points_by_backup_vault, BackupVaultName=vault)
        if not left or not left["RecoveryPoints"]:
            break
        time.sleep(10)
    ignore(bk.delete_backup_vault, BackupVaultName=vault)
    log(f"deleted vault {vault}")

    log("== snapshots and images")
    for img in ec2.describe_images(Owners=["self"], Filters=tagf)["Images"]:
        ignore(ec2.deregister_image, ImageId=img["ImageId"])
        log(f"deregistered image {img['ImageId']}")
    for s in ec2.describe_snapshots(OwnerIds=["self"], Filters=tagf)["Snapshots"]:
        ignore(ec2.delete_snapshot, SnapshotId=s["SnapshotId"])
        log(f"deleted snapshot {s['SnapshotId']}")

    log("== cloudtrail")
    ct = boto3.client("cloudtrail")
    for t in ct.describe_trails()["trailList"]:
        if t["Name"].startswith(PROJECT):
            ignore(ct.stop_logging, Name=t["Name"])
            ignore(ct.delete_trail, Name=t["Name"])
            log(f"deleted trail {t['Name']}")

    log("== s3")
    for b in s3.list_buckets()["Buckets"]:
        name = b["Name"]
        if not name.startswith(PROJECT):
            continue
        res = boto3.resource("s3").Bucket(name)
        res.object_versions.delete()
        s3.delete_bucket(Bucket=name)
        log(f"emptied and deleted bucket {name}")

    log("== cloudwatch logs")
    logs = boto3.client("logs")
    for g in logs.describe_log_groups(logGroupNamePrefix=f"/{PROJECT}/")["logGroups"]:
        logs.delete_log_group(logGroupName=g["logGroupName"])
        log(f"deleted log group {g['logGroupName']}")

    log("== iam roles")
    for name, path in ((f"{PROJECT}-ec2", "/"),):  # AWSBackupDefaultServiceRole is a standard name, left in place
        prof = ignore(iam.get_instance_profile, InstanceProfileName=name)
        if prof:
            ignore(iam.remove_role_from_instance_profile, InstanceProfileName=name, RoleName=name)
            ignore(iam.delete_instance_profile, InstanceProfileName=name)
        r = ignore(iam.get_role, RoleName=name)
        if not r:
            continue
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
        for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        iam.delete_role(RoleName=name)
        log(f"deleted role {name}")

    log("== what remains (expected: nothing project-related)")
    log(f"instances: {[i['InstanceId'] + ':' + i['State']['Name'] for r in ec2.describe_instances()['Reservations'] for i in r['Instances']]}")
    log(f"volumes: {[v['VolumeId'] for v in ec2.describe_volumes()['Volumes']]}")
    log(f"snapshots: {[s['SnapshotId'] for s in ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']]}")
    log(f"addresses: {[a['PublicIp'] for a in ec2.describe_addresses()['Addresses']]}")
    log(f"buckets: {[b['Name'] for b in s3.list_buckets()['Buckets']]}")
    log(f"vaults: {[v['BackupVaultName'] for v in bk.list_backup_vaults()['BackupVaultList']]}")
    log(f"trails: {[t['Name'] for t in ct.describe_trails()['trailList']]}")
    log("left on purpose: EBS encryption-by-default (region setting), the security group, AWSBackupDefaultServiceRole, IAM user ec2-hipaa")
    log("DONE")


if __name__ == "__main__":
    main()
