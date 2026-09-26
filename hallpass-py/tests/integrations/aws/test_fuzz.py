"""Port of internal/integrations/aws/fuzz_test.go (FuzzParseResource) as a
Hypothesis property test plus its seed corpus. The Go package has no
testdata/fuzz directory, so the f.Add seeds are the whole corpus."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, go_bytes, parse_resource
from hallpass.integrations.aws.actions import ALIASES, ARN_RE, MAX_ARN_RESOURCE, RAW_ACTION_RE, arn_field, resolve_action
from hallpass.integrations.aws.actions import parse_resource as aws_parse_resource
from tests.harness import examples as _examples

SEEDS = [
    ("raw:s3:GetObject", "arn:aws:s3:::bucket/key"),
    ("raw:iam:*", "all"),
    ("raw:s3:GetObject", "arn:aws-cn:s3:::bucket"),
    ("raw:s3:GetObject", "arn:aws:s3:::bucket?x=1"),
    ("raw:s3:Get Object", "all:x"),
    ("raw:s3", "arn:aws:iam::123456789012:role/x"),
]


def parse_resource_invariants(action: str, resource: str) -> None:
    """An accepted resource is "*" or an ARN in the connection's partition;
    parse_raw only yields <service>:<Action>."""
    try:
        act = resolve_action(action)
    except ValueError:
        pass
    else:
        assert RAW_ACTION_RE.fullmatch(act), f"unvalidated action {act!r}"
        if action.startswith("raw:"):
            assert act == action[len("raw:") :], f"raw action {action!r} changed to {act!r}"
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        arn = aws_parse_resource(res, "aws")
    except ValueError:
        return
    if arn == "*":
        assert res.type == "all", f"* from {resource!r}"
        return
    assert ARN_RE.fullmatch(arn) and arn_field(arn, 1) == "aws" and arn == res.raw, f"unvalidated arn {arn!r} from {resource!r}"
    assert len(go_bytes(arn_field(arn, 5))) <= MAX_ARN_RESOURCE, f"resource field too long: {len(arn_field(arn, 5))}"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_resource_seeds(action: str, resource: str) -> None:
    parse_resource_invariants(action, resource)


_ACTIONS = st.one_of(
    st.sampled_from(sorted(ALIASES)),
    st.builds(lambda s: "raw:" + s, st.text(alphabet="abcsz019-:*AGOZ /\n", max_size=30)),
    st.text(max_size=40),
)
_RESOURCES = st.one_of(
    st.builds(
        lambda p, rest: p + rest,
        st.sampled_from(["arn:aws:", "arn:aws-cn:", "arn:aws-us-gov:", "arn:", "all", "all:", "bucket:"]),
        st.text(alphabet="abs3iam:0123456789/*?=x-\n ", max_size=60),
    ),
    st.builds(lambda n: "arn:aws:s3:::" + "k" * n, st.integers(min_value=1990, max_value=2010)),
    st.text(max_size=60),
)


@settings(max_examples=_examples(500), deadline=None)
@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_resource(action: str, resource: str) -> None:
    parse_resource_invariants(action, resource)
