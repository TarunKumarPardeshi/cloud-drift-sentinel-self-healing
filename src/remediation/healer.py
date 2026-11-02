"""Automated remediation engine that reverses unauthorized AWS configuration drift."""

import logging
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("drift.healer")


class CloudHealer:
    def __init__(self, ec2_client=None, s3_client=None):
        self.ec2 = ec2_client
        self.s3 = s3_client

    def revoke_security_group_open_ingress(
        self,
        group_id: str,
        ip_permissions: list
    ) -> str:
        """Revokes open 0.0.0.0/0 ingress rules from the specified security group."""
        revoked_rules = []
        for perm in ip_permissions:
            for ip_range in perm.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")
                if cidr in ["0.0.0.0/0", "::/0"]:
                    from_port = perm.get("FromPort", "ALL")
                    to_port = perm.get("ToPort", "ALL")
                    proto = perm.get("IpProtocol", "ALL")
                    rule_desc = f"{proto}:{from_port}-{to_port} (CIDR: {cidr})"

                    if self.ec2:
                        try:
                            self.ec2.revoke_security_group_ingress(
                                GroupId=group_id,
                                IpPermissions=[perm]
                            )
                            logger.info(f"Successfully revoked illegal ingress rule on {group_id}: {rule_desc}")
                        except ClientError as e:
                            logger.error(f"Failed to revoke rule on {group_id}: {e}")
                            raise
                    revoked_rules.append(rule_desc)

        action_summary = f"Revoked {len(revoked_rules)} open ingress rules: {', '.join(revoked_rules)}"
        return action_summary

    def enforce_s3_block_public_access(self, bucket_name: str) -> str:
        """Restores strict S3 Block Public Access settings on the target bucket."""
        if self.s3:
            try:
                self.s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True
                    }
                )
                logger.info(f"Successfully reapplied BlockPublicAccess to bucket {bucket_name}")
            except ClientError as e:
                logger.error(f"Failed to apply BlockPublicAccess to {bucket_name}: {e}")
                raise

        return f"Enforced full BlockPublicAccess (Acls, Policies, Buckets) on s3://{bucket_name}"
