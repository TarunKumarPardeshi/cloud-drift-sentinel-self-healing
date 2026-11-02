"""AWS Lambda Sentinel: EventBridge handler for real-time drift detection and automated self-healing."""

import json
import logging
import os
from typing import Dict, Any
from src.remediation.healer import CloudHealer
from src.notifications.slack import SlackNotifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("drift.sentinel")


class DriftSentinel:
    def __init__(self, healer: CloudHealer = None, notifier: SlackNotifier = None):
        self.healer = healer or CloudHealer()
        self.notifier = notifier or SlackNotifier(webhook_url=os.getenv("SLACK_WEBHOOK_URL"))

    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates CloudTrail event from EventBridge and triggers self-healing if drifted."""
        detail = event.get("detail", {})
        event_name = detail.get("eventName", "")
        user_identity = detail.get("userIdentity", {}).get("arn", "UnknownPrincipal")
        region = event.get("region", "ca-central-1")

        logger.info(f"Sentinel analyzing CloudTrail event: '{event_name}' by '{user_identity}'")

        # 1. Detect Security Group Open Ingress (e.g. 0.0.0.0/0 port 22/3389)
        if event_name == "AuthorizeSecurityGroupIngress":
            req_params = detail.get("requestParameters", {})
            group_id = req_params.get("groupId", "UnknownSG")
            ip_permissions = req_params.get("ipPermissions", {}).get("items", [])

            # Check if any rule allows 0.0.0.0/0 or ::/0
            has_open_cidr = any(
                ip_range.get("cidrIp") in ["0.0.0.0/0", "::/0"]
                for p in ip_permissions
                for ip_range in p.get("ipRanges", {}).get("items", [])
            )

            if has_open_cidr:
                logger.warning(f"🚨 DRIFT DETECTED: Illegal 0.0.0.0/0 rule added to {group_id}!")
                # Format into standard boto3 shape
                boto_permissions = [
                    {
                        "IpProtocol": p.get("ipProtocol"),
                        "FromPort": p.get("fromPort"),
                        "ToPort": p.get("toPort"),
                        "IpRanges": [{"CidrIp": r.get("cidrIp")} for r in p.get("ipRanges", {}).get("items", [])]
                    }
                    for p in ip_permissions
                ]
                remediation_action = self.healer.revoke_security_group_open_ingress(group_id, boto_permissions)

                # Send Slack Alert
                alert_payload = self.notifier.build_alert_payload(
                    event_name=event_name,
                    user_identity=user_identity,
                    resource_id=group_id,
                    region=region,
                    remediation_action=remediation_action
                )
                return {
                    "action": "REMEDIATED",
                    "resource": group_id,
                    "remediation": remediation_action,
                    "alert_payload": alert_payload
                }

        # 2. Detect S3 Bucket Public Access Alteration
        elif event_name in ["DeletePublicAccessBlock", "PutBucketAcl"]:
            req_params = detail.get("requestParameters", {})
            bucket_name = req_params.get("bucketName", "UnknownBucket")

            logger.warning(f"🚨 DRIFT DETECTED: Public access modification attempted on s3://{bucket_name}!")
            remediation_action = self.healer.enforce_s3_block_public_access(bucket_name)

            alert_payload = self.notifier.build_alert_payload(
                event_name=event_name,
                user_identity=user_identity,
                resource_id=f"s3://{bucket_name}",
                region=region,
                remediation_action=remediation_action
            )
            return {
                "action": "REMEDIATED",
                "resource": bucket_name,
                "remediation": remediation_action,
                "alert_payload": alert_payload
            }

        return {"action": "IGNORED", "reason": "No policy drift detected"}


def lambda_handler(event, context):
    sentinel = DriftSentinel()
    result = sentinel.process_event(event)
    return {"statusCode": 200, "body": json.dumps(result)}
