"""Port of internal/integrations/googlecloud/fuzz_test.go.

FuzzParseRef becomes a Hypothesis property with the same invariant; its seed
corpus (the f.Add seeds; the Go package has no testdata/fuzz files) is
replayed as plain cases.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hallpass.core.catalog import ResourceError, parse_resource
from hallpass.core.decision import HallpassError
from hallpass.core.errors import go_lower
from hallpass.integrations.googlecloud.actions import ACTION_INDEX, PERMISSION_RE, PERMISSION_V2_RE, parse_ref, well_formed

SEEDS = [
    ("project.view", "project:acme-prod"),
    ("iam.set", "bucket:acme-data"),
    ("storage.read", "object:acme-data/reports/2026/q1.csv"),
    ("raw:storage.objects.delete", "name://storage.googleapis.com/projects/_/buckets/x"),
    ("raw:iam.googleapis.com/roles.create", "organization:1"),
    ("serviceaccount.actas", "serviceaccount:deployer@acme-prod.iam.gserviceaccount.com"),
    ("gke.access", "cluster:acme-prod/europe-west1/main"),
    ("storage.read", "name://storage.googleapis.com/projects/../x"),
    ("storage.read", "object:acme-data/../x"),
    ("storage.read", "object:acme-data/a/../x"),
    ("storage.read", "object:acme-data/a/.."),
    ("storage.read", "object:acme-data/Q1 2026 (final).pdf"),
    ("secret.read", "secret:123456789012/db-password"),
    ("project.view", "project:acme-prod?x=1"),
    ("raw:storage.objects.get x", "project:acme-prod"),
]


def fuzz_parse_ref(action: str, resource: str) -> None:
    """An accepted question is a permission in the v1 or v2 format and a
    full resource name on a googleapis.com host, both built only from
    validated pieces."""
    try:
        res = parse_resource(resource)
    except ResourceError:
        return
    try:
        q = parse_ref(action, res)
    except HallpassError:
        return
    assert not res.query, f"query slipped through {res}"
    assert PERMISSION_RE.fullmatch(q.permission) or PERMISSION_V2_RE.fullmatch(q.permission), f"unvalidated permission {q.permission!r} from {action!r}"
    if action.startswith("raw:"):
        assert q.permission == action.removeprefix("raw:"), f"raw action {action!r} became {q.permission!r}"
    else:
        assert action in ACTION_INDEX, f"unknown action {action!r} accepted"
    assert well_formed(q.resource), f"unvalidated resource {q.resource!r} from {resource!r}"
    if res.type != "object":
        assert not any(c in q.resource for c in ' \t?#"\\'), f"unexpected characters in {q.resource!r} from {resource!r}"
    if res.type != "name":
        for piece in res.id.split("/"):
            assert go_lower(piece) in go_lower(q.resource), f"resource {resource!r} lost {piece!r} in {q.resource!r}"
    if res.type == "name":
        assert q.resource == res.id, f"name resource {res.id!r} changed to {q.resource!r}"


@pytest.mark.parametrize(("action", "resource"), SEEDS)
def test_fuzz_parse_ref_seeds(action: str, resource: str) -> None:
    fuzz_parse_ref(action, resource)


_ACTIONS = st.one_of(
    st.sampled_from(sorted(ACTION_INDEX)),
    st.builds(lambda p: "raw:" + p, st.from_regex(PERMISSION_RE, fullmatch=True) | st.from_regex(PERMISSION_V2_RE, fullmatch=True) | st.text()),
    st.text(),
)
_TYPES = st.sampled_from(
    ["project", "folder", "organization", "bucket", "object", "dataset", "table", "secret", "serviceaccount", "instance", "service", "cluster", "name", "other"]
)
_PIECE = st.one_of(st.text(), st.from_regex(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", fullmatch=True), st.sampled_from([".", "..", "", "x y", "a"]))
_IDS = st.one_of(
    st.text(),
    st.lists(_PIECE, min_size=1, max_size=4).map("/".join),
    st.builds(
        lambda h, p: "//" + h + ".googleapis.com/" + p, st.from_regex(r"[a-z][a-z0-9-]{0,10}", fullmatch=True), st.lists(_PIECE, max_size=4).map("/".join)
    ),
)
_RESOURCES = st.one_of(st.text(), st.builds(lambda t, i: t + ":" + i, _TYPES, _IDS))


@given(_ACTIONS, _RESOURCES)
def test_fuzz_parse_ref(action: str, resource: str) -> None:
    fuzz_parse_ref(action, resource)
