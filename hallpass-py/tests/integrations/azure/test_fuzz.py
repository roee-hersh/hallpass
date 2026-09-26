"""Port of internal/integrations/azure/fuzz_test.go (FuzzParseTarget) as a
Hypothesis property test plus its seed corpus. The Go package has no
testdata/fuzz directory, so the f.Add seeds are the whole corpus."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.integrations.azure.actions import ACTIONS, parse_target

SEEDS = [
    ("vm.read", "subscription:33333333-3333-3333-3333-333333333333"),
    ("vm.read", "resourcegroup:33333333-3333-3333-3333-333333333333/prod"),
    (
        "raw:Microsoft.Compute/virtualMachines/read",
        "resource:/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/web-1",
    ),
    ("data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "managementgroup:corp"),
    ("vm.read", "resource:/subscriptions/x/../y"),
    ("raw:Microsoft.Compute/*", "subscription:x"),
    ("vm.read", "resource:/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/prod/providers/Microsoft.Compute/../.."),
    ("vm.read", "managementgroup:.."),
    ("vm.read", "resourcegroup:33333333-3333-3333-3333-333333333333/rg(1)"),
]


def _contains_any(s: str, chars: str) -> bool:
    return any(c in s for c in chars)


def parse_target_invariants(action: str, resource: str) -> None:
    """An accepted scope is a well-formed ARM scope built from validated,
    escaped segments, and an accepted operation carries no wildcard or path
    metacharacter."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        tg = parse_target(action, res)
    except HallpassError:
        return
    assert not res.query, f"query slipped through {res}"
    op = tg.action.operation
    assert _contains_any(op, "*?#% \\/") != _contains_any(op, "*?#% \\") and "//" not in op, f"unvalidated operation {op!r} from {action!r}"
    for seg in op.split("/"):
        assert seg != "" and seg.strip(".") != "", f"bad segment {seg!r} in operation {op!r}"
    if action.startswith("raw:"):
        assert not tg.action.data and op == action[len("raw:") :], f"raw action {action!r} became {tg.action}"
    if action.startswith("data:"):
        assert tg.action.data and op == action[len("data:") :], f"data action {action!r} became {tg.action}"
    sc = tg.scope
    assert sc.startswith("/") and not sc.endswith("/") and "//" not in sc and "?" not in sc and "#" not in sc, f"malformed scope {sc!r} from {resource!r}"
    for seg in sc[1:].split("/"):
        assert seg != "" and seg.strip(".") != "" and not _contains_any(seg, " \\%?#"), f"bad segment {seg!r} in {sc!r}"
    n = sc.count("/")
    if tg.kind == "subscription":
        assert sc.startswith("/subscriptions/") and n == 2, f"subscription scope {sc!r}"
    elif tg.kind == "resourcegroup":
        assert sc.startswith("/subscriptions/") and n == 4 and "/resourceGroups/" in sc, f"resource group scope {sc!r}"
    elif tg.kind == "resource":
        assert "/providers/" in sc and n >= 8 and n % 2 == 0, f"resource scope {sc!r}"
    elif tg.kind == "managementgroup":
        assert sc.startswith("/providers/Microsoft.Management/managementGroups/") and n == 4, f"management group scope {sc!r}"
    else:
        pytest.fail(f"kind {tg.kind!r}")


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_target_seeds(action: str, resource: str) -> None:
    parse_target_invariants(action, resource)


_SUB = "33333333-3333-3333-3333-333333333333"
_SEG = st.text(alphabet="abcXYZ019._()-/ %?#*\\", max_size=12)
_ACTIONS = st.one_of(
    st.sampled_from(sorted(ACTIONS)),
    st.builds(lambda p, s: p + s, st.sampled_from(["raw:", "data:"]), st.text(alphabet="MicrosoftComputeabc.019/_-*? %#\\", max_size=50)),
    st.builds(lambda p: p + "Microsoft.Compute/virtualMachines/read", st.sampled_from(["raw:", "data:"])),
    st.text(max_size=40),
)
_RESOURCES = st.one_of(
    st.builds(lambda s: "subscription:" + s, st.one_of(st.just(_SUB), st.just(_SUB.upper()), _SEG)),
    st.builds(lambda s: "resourcegroup:" + _SUB + "/" + s, _SEG),
    st.builds(lambda s: "managementgroup:" + s, _SEG),
    st.builds(
        lambda pfx, segs: "resource:" + pfx + "/".join(segs),
        st.sampled_from(
            [
                "/subscriptions/" + _SUB + "/resourceGroups/prod/providers/Microsoft.Compute/",
                "/SUBSCRIPTIONS/" + _SUB + "/resourcegroups/rg(1)/PROVIDERS/Microsoft.Storage/",
                "/subscriptions/" + _SUB + "/",
                "subscriptions/" + _SUB + "/resourceGroups/prod/providers/Microsoft.Compute/",
            ]
        ),
        st.lists(_SEG, max_size=5),
    ),
    st.text(max_size=60),
)


@settings(max_examples=500, deadline=None)
@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_target(action: str, resource: str) -> None:
    parse_target_invariants(action, resource)
