"""The aws integration: IAM policy simulation for one AWS account."""

from __future__ import annotations

from hallpass.integrations.aws.aws import AWS, AWSConnection

__all__ = ["AWS", "INTEGRATION", "AWSConnection"]

INTEGRATION = AWS()
