"""The aws integration's actions: named aliases for common IAM actions and
raw:<service>:<Action>; and the resources they are simulated against."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource, go_bytes
from hallpass.core.errors import go_quote

__all__ = [
    "ALIASES",
    "ALIAS_LIST",
    "ARN_RE",
    "MAX_ARN_RESOURCE",
    "RAW_ACTION_RE",
    "Alias",
    "arn_field",
    "catalog_actions",
    "match_action",
    "parse_raw",
    "parse_resource",
    "resolve_action",
]


@dataclass(frozen=True)
class Alias:
    """A named action that expands to one IAM action."""

    name: str
    desc: str
    action: str


ALIAS_LIST: tuple[Alias, ...] = (
    Alias("s3.read", "read an object (s3:GetObject)", "s3:GetObject"),
    Alias("s3.write", "write an object (s3:PutObject)", "s3:PutObject"),
    Alias("s3.list", "list a bucket (s3:ListBucket)", "s3:ListBucket"),
    Alias("ec2.stop", "stop an instance (ec2:StopInstances)", "ec2:StopInstances"),
    Alias("ec2.start", "start an instance (ec2:StartInstances)", "ec2:StartInstances"),
    Alias("ec2.terminate", "terminate an instance (ec2:TerminateInstances)", "ec2:TerminateInstances"),
    Alias("lambda.invoke", "invoke a function (lambda:InvokeFunction)", "lambda:InvokeFunction"),
    Alias("iam.passrole", "pass a role to a service (iam:PassRole)", "iam:PassRole"),
    Alias("secretsmanager.read", "read a secret value (secretsmanager:GetSecretValue)", "secretsmanager:GetSecretValue"),
    Alias("ssm.session", "start a Session Manager session (ssm:StartSession)", "ssm:StartSession"),
    Alias("sts.assume", "assume a role (sts:AssumeRole)", "sts:AssumeRole"),
    Alias("rds.delete", "delete a database instance (rds:DeleteDBInstance)", "rds:DeleteDBInstance"),
    Alias("eks.describe", "describe a cluster (eks:DescribeCluster)", "eks:DescribeCluster"),
)

ALIASES: dict[str, Alias] = {a.name: a for a in ALIAS_LIST}

# The part after "raw:": <service>:<Action>, e.g. s3:GetObject or iam:*.
# (Matched with fullmatch: Go's $ never matches before a trailing newline.)
RAW_ACTION_RE = re.compile(r"[a-z0-9-]+:[A-Za-z0-9*]+")

# An ARN in one of the three partitions. The account field is empty or
# exactly 12 digits; the resource part is free-form, at most
# MAX_ARN_RESOURCE bytes (checked apart, as in Go).
ARN_RE = re.compile(r"arn:(aws|aws-us-gov|aws-cn):[a-z0-9-]*:[a-z0-9-]*:([0-9]{12})?:.+")

MAX_ARN_RESOURCE = 2000


def catalog_actions() -> list[Action]:
    acts = [
        Action(
            name="raw:<service>:<Action>",
            pattern=True,
            description="any IAM action, e.g. raw:s3:GetObject, raw:ec2:TerminateInstances, raw:iam:*",
        )
    ]
    acts.extend(Action(name=a.name, description=a.desc) for a in ALIAS_LIST)
    return acts


def match_action(name: str) -> Action | None:
    """Accepts raw:<service>:<Action>."""
    try:
        parse_raw(name)
    except ValueError:
        return None
    return Action(name=name, pattern=True, description="raw IAM action")


def parse_raw(name: str) -> str:
    """The IAM action named by raw:<service>:<Action>; ValueError otherwise."""
    if not name.startswith("raw:"):
        raise ValueError("raw action must be raw:<service>:<Action>, e.g. raw:s3:GetObject")
    rest = name[len("raw:") :]
    if not RAW_ACTION_RE.fullmatch(rest):
        raise ValueError(f"action {go_quote(rest)} after raw: must be <service>:<Action> such as s3:GetObject")
    return rest


def resolve_action(name: str) -> str:
    """Map the caller's action name to one IAM action."""
    if name.startswith("raw:"):
        return parse_raw(name)
    a = ALIASES.get(name)
    if a is None:
        raise ValueError(f"unknown action {go_quote(name)}")
    return a.action


def parse_resource(res: Resource, partition: str) -> str:
    """The resource ARN to simulate against, or "*".

    arn:aws:s3:::bucket/key   the ARN itself (parse_resource splits it at
                              the first colon; the raw string is used)
    all                       every resource ("*")
    """
    if res.type == "all":
        if res.id != "" or res.query:
            raise ValueError('resource "all" takes no id or query')
        return "*"
    if res.type == "arn":
        if res.query:
            raise ValueError("an ARN resource takes no ?query; ARNs are used verbatim")
        arn = res.raw
        if not ARN_RE.fullmatch(arn) or len(go_bytes(arn_field(arn, 5))) > MAX_ARN_RESOURCE:
            raise ValueError(f"resource {go_quote(arn)} is not an ARN of the form arn:<partition>:<service>:<region>:<account>:<resource>")
        p = arn_field(arn, 1)
        if p != partition:
            raise ValueError(f"resource ARN is in partition {p} but the connection is in {partition}")
        return arn
    raise ValueError(f"resource type {go_quote(res.type)}; use an ARN (arn:aws:...) or all")


def arn_field(arn: str, i: int) -> str:
    """The i-th colon-separated field of an ARN (0 = "arn", 1 = partition,
    2 = service, 3 = region, 4 = account, 5 = resource)."""
    parts = arn.split(":", 5)
    if i >= len(parts):
        return ""
    return parts[i]
