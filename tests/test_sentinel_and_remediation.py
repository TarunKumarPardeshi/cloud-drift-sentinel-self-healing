from unittest.mock import MagicMock
import pytest
from src.sentinel.handler import DriftSentinel
from src.remediation.healer import CloudHealer
from src.notifications.slack import SlackNotifier


def test_detect_and_remediate_security_group_drift():
    mock_ec2 = MagicMock()
    healer = CloudHealer(ec2_client=mock_ec2)
    notifier = SlackNotifier(webhook_url=None)
    sentinel = DriftSentinel(healer=healer, notifier=notifier)

    mock_eventbridge_event = {
        "region": "ca-central-1",
        "detail": {
            "eventName": "AuthorizeSecurityGroupIngress",
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/developer-manual-change"
            },
            "requestParameters": {
                "groupId": "sg-01a2b3c4d5e6f7g8h",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {
                                "items": [
                                    {"cidrIp": "0.0.0.0/0"}  # Open dangerous CIDR!
                                ]
                            }
                        }
                    ]
                }
            }
        }
    }

    result = sentinel.process_event(mock_eventbridge_event)

    assert result["action"] == "REMEDIATED"
    assert result["resource"] == "sg-01a2b3c4d5e6f7g8h"
    assert "Revoked 1 open ingress rules" in result["remediation"]
    assert mock_ec2.revoke_security_group_ingress.called
    assert "developer-manual-change" in str(result["alert_payload"])


def test_detect_and_remediate_s3_public_access_drift():
    mock_s3 = MagicMock()
    healer = CloudHealer(s3_client=mock_s3)
    notifier = SlackNotifier(webhook_url=None)
    sentinel = DriftSentinel(healer=healer, notifier=notifier)

    mock_eventbridge_event = {
        "region": "ca-central-1",
        "detail": {
            "eventName": "DeletePublicAccessBlock",
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/admin-accidental-click"
            },
            "requestParameters": {
                "bucketName": "confidential-financial-records"
            }
        }
    }

    result = sentinel.process_event(mock_eventbridge_event)

    assert result["action"] == "REMEDIATED"
    assert result["resource"] == "confidential-financial-records"
    assert mock_s3.put_public_access_block.called


def test_safe_event_ignored():
    healer = CloudHealer()
    notifier = SlackNotifier()
    sentinel = DriftSentinel(healer=healer, notifier=notifier)

    safe_event = {
        "detail": {
            "eventName": "DescribeInstances",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/read-only-analyst"}
        }
    }

    result = sentinel.process_event(safe_event)
    assert result["action"] == "IGNORED"
