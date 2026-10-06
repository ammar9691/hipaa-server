#!/usr/bin/env python3
"""Replace an instance's unencrypted root EBS volume with an encrypted copy.

Steps: turn on EBS encryption by default for the region, stop the instance, snapshot the
root volume (kept as the rollback point), copy the snapshot encrypted, build a new volume
from it, swap it in on the same device name, start the instance, attach an Elastic IP.

The old volume and the unencrypted snapshot are left in place. Delete them by hand once
the instance is verified.

Config comes from ../.env (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION).
Usage: python encrypt_root_volume.py <instance-id> [--size GB] [--type INSTANCE_TYPE]
"""
import argparse
import os
import sys

import boto3

HERE = os.path.dirname(os.path.abspath(__file__))


def load_env(path):
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)


def log(msg):
    print(msg, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id")
    ap.add_argument("--size", type=int, help="new root volume size in GB (default: same as old)")
    ap.add_argument("--type", dest="itype", help="change the instance type while it is stopped")
    args = ap.parse_args()

    load_env(os.path.join(HERE, "..", ".env"))
    ec2 = boto3.client("ec2")
    tag = [{"Key": "Project", "Value": "hipaa-server"}]

    inst = ec2.describe_instances(InstanceIds=[args.instance_id])["Reservations"][0]["Instances"][0]
    root_dev = inst["RootDeviceName"]
    az = inst["Placement"]["AvailabilityZone"]
    mapping = next(b for b in inst["BlockDeviceMappings"] if b["DeviceName"] == root_dev)
    old_vol = mapping["Ebs"]["VolumeId"]
    delete_on_term = mapping["Ebs"]["DeleteOnTermination"]
    vol = ec2.describe_volumes(VolumeIds=[old_vol])["Volumes"][0]
    if vol["Encrypted"]:
        log(f"{old_vol} is already encrypted, nothing to do")
        return
    size = max(args.size or vol["Size"], vol["Size"])
    log(f"instance {args.instance_id} az={az} root={root_dev} old_vol={old_vol} {vol['Size']}GB -> {size}GB")

    if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        ec2.enable_ebs_encryption_by_default()
        log("EBS encryption by default: enabled for this region")

    log("stopping instance")
    ec2.stop_instances(InstanceIds=[args.instance_id])
    ec2.get_waiter("instance_stopped").wait(InstanceIds=[args.instance_id])

    if args.itype and args.itype != inst["InstanceType"]:
        ec2.modify_instance_attribute(InstanceId=args.instance_id, InstanceType={"Value": args.itype})
        log(f"instance type: {inst['InstanceType']} -> {args.itype}")

    snap = ec2.create_snapshot(
        VolumeId=old_vol, Description=f"pre-encryption rollback of {old_vol}",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": tag + [{"Key": "Name", "Value": "hipaa-pre-encryption"}]}],
    )["SnapshotId"]
    log(f"snapshot {snap} (unencrypted, rollback point) ...")
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap], WaiterConfig={"Delay": 15, "MaxAttempts": 120})

    region = os.environ["AWS_DEFAULT_REGION"]
    enc_snap = ec2.copy_snapshot(
        SourceSnapshotId=snap, SourceRegion=region, Encrypted=True,
        Description=f"encrypted copy of {snap}",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": tag + [{"Key": "Name", "Value": "hipaa-root-encrypted"}]}],
    )["SnapshotId"]
    log(f"encrypted snapshot {enc_snap} ...")
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[enc_snap], WaiterConfig={"Delay": 15, "MaxAttempts": 120})

    new_vol = ec2.create_volume(
        SnapshotId=enc_snap, AvailabilityZone=az, VolumeType="gp3", Size=size, Encrypted=True,
        TagSpecifications=[{"ResourceType": "volume", "Tags": tag + [{"Key": "Name", "Value": "hipaa-root-encrypted"}]}],
    )["VolumeId"]
    ec2.get_waiter("volume_available").wait(VolumeIds=[new_vol])
    log(f"new volume {new_vol} ready")

    ec2.detach_volume(VolumeId=old_vol, InstanceId=args.instance_id)
    ec2.get_waiter("volume_available").wait(VolumeIds=[old_vol])
    ec2.attach_volume(VolumeId=new_vol, InstanceId=args.instance_id, Device=root_dev)
    ec2.get_waiter("volume_in_use").wait(VolumeIds=[new_vol])
    ec2.modify_instance_attribute(
        InstanceId=args.instance_id,
        BlockDeviceMappings=[{"DeviceName": root_dev, "Ebs": {"DeleteOnTermination": delete_on_term}}],
    )
    ec2.create_tags(Resources=[old_vol], Tags=tag + [{"Key": "Name", "Value": "hipaa-root-OLD-unencrypted"}])
    log(f"swapped: {old_vol} detached (kept), {new_vol} attached as {root_dev}")

    log("starting instance")
    ec2.start_instances(InstanceIds=[args.instance_id])
    ec2.get_waiter("instance_running").wait(InstanceIds=[args.instance_id])

    addrs = ec2.describe_addresses(Filters=[{"Name": "instance-id", "Values": [args.instance_id]}])["Addresses"]
    if addrs:
        ip = addrs[0]["PublicIp"]
    else:
        alloc = ec2.allocate_address(Domain="vpc", TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": tag}])
        ec2.associate_address(AllocationId=alloc["AllocationId"], InstanceId=args.instance_id)
        ip = alloc["PublicIp"]
    ec2.get_waiter("instance_status_ok").wait(InstanceIds=[args.instance_id])
    v = ec2.describe_volumes(VolumeIds=[new_vol])["Volumes"][0]
    log(f"DONE public_ip={ip} new_vol={new_vol} encrypted={v['Encrypted']} kms={v.get('KmsKeyId')}")
    log(f"rollback: snapshot={snap} old_volume={old_vol}")


if __name__ == "__main__":
    sys.exit(main())
