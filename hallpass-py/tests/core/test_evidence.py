"""Port of internal/evidence/evidence_test.go."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from hallpass.core import evidence
from hallpass.core.context import background
from hallpass.core.evidence import MAX_CALLS, Call, Evidence, Origin, Recorder


def call(p: str) -> Call:
    return Call(method="GET", path=p, status=200)


def _go_json(v: object) -> str:
    """Compact JSON as Go's encoding/json writes it."""
    return json.dumps(v, separators=(",", ":"))


def test_recorder() -> None:
    ctx, rec = evidence.with_recorder(background())
    assert rec.evidence() is None, "empty recorder has evidence"
    r = evidence.recorder_from(ctx)
    assert r is not None
    r.record(Call(method="GET", path="/a", status=200, etag='"1"'))
    ev = rec.evidence()
    assert ev is not None and len(ev.calls()) == 1 and ev.calls()[0].path == "/a" and not ev.truncated(), ev
    # The snapshot does not change under later records.
    r.record(call("/b"))
    snap = rec.evidence()
    assert snap is not None
    assert len(ev.calls()) == 1 and len(snap.calls()) == 2, "snapshot shared with the recorder"
    # Nothing is recorded without a recorder, on a suppressed one, or on nil.
    # Go: TestRecorder calls Record/Add/Evidence on a nil *Recorder; in
    # Python a missing or suppressed recorder is None, which callers skip.
    assert evidence.recorder_from(evidence.without_recorder(ctx)) is None
    assert evidence.recorder_from(background()) is None, "recorder_from found a recorder where none should be"
    assert evidence.recorder_from(None) is None
    snap = rec.evidence()
    assert snap is not None and len(snap.calls()) == 2, "suppressed record leaked"
    assert evidence.without_recorder(background()) is background(), "without_recorder wrapped a context that had no recorder"
    # Go: a nil *Evidence has no calls, is not truncated, and AsCached of it
    # is nil; in Python nil evidence is None and as_cached(None) is None.
    assert evidence.as_cached(None) is None and evidence.of() is None, "nil evidence is not empty"


def test_origins() -> None:
    """Calls a check got from a cache or a concurrent check's lookup are held
    by reference and marked by origin when flattened; the source is untouched."""
    src = evidence.of(call("/a"), Call(method="GET", path="/c", status=200, cached=True))
    assert src is not None
    rec = Recorder()
    rec.add(None, Origin.CACHED)
    rec.add(src, Origin.CACHED)
    ev = rec.evidence()
    assert ev is not None
    got = ev.calls()
    assert len(got) == 2 and got[0].cached and not got[0].shared and got[1].cached, f"cached: {got}"
    rec = Recorder()
    rec.add(src, Origin.SHARED)
    ev = rec.evidence()
    assert ev is not None
    got = ev.calls()
    assert len(got) == 2 and not got[0].cached and got[0].shared and got[1].cached and not got[1].shared, f"shared: {got}"
    rec = Recorder()
    rec.add(src, Origin.OWN)
    rec.record(call("/own"))
    ev = rec.evidence()
    assert ev is not None
    got = ev.calls()
    assert len(got) == 3 and not got[0].cached and not got[0].shared and got[1].cached and got[2].path == "/own", f"own: {got}"
    c = src.calls()
    assert not c[0].cached and not c[0].shared, "add changed the source"
    # Nesting: a decision served from the decision cache marks everything
    # cached, whatever it was before.
    cached = ev.as_cached().calls()
    for cc in cached:
        assert cc.cached and not cc.shared, f"as_cached: {cached}"
    # A shared view of a cached view stays cached.
    rec2 = Recorder()
    rec2.add(ev.as_cached(), Origin.SHARED)
    ev2 = rec2.evidence()
    assert ev2 is not None
    for cc in ev2.calls():
        assert cc.cached and not cc.shared, f"shared of cached: {cc}"


def test_oldest() -> None:
    rec = Recorder()
    assert rec.oldest() is None, "empty recorder has an oldest read"
    rec.record(call("/own"))
    rec.add(evidence.of(call("/now")), Origin.CACHED)
    assert rec.oldest() is None, "own and undated reads have no age"
    t1 = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    hour = 3600.0
    rec.add_at(evidence.of(call("/a")), Origin.CACHED, t1 + hour, t1 + hour)
    rec.add_at(None, Origin.CACHED, t1, t1 + 3 * hour)
    rec.add_at(evidence.of(call("/b")), Origin.SHARED, t1 + 2 * hour, t1 + 2 * hour)
    o = rec.oldest()
    assert o is not None and o == t1, f"oldest = {o}"
    o = rec.oldest_strict()
    assert o is not None and o == t1 + hour, f"oldest strict = {o}"
    ev = rec.evidence()
    assert ev is not None
    assert len(ev.calls()) == 4, f"calls = {len(ev.calls())}"
    # The cached view is one object, built once.
    assert ev.as_cached() is ev.as_cached(), "as_cached built two views"


def test_cap() -> None:
    rec = Recorder()
    for _ in range(MAX_CALLS + 5):
        rec.record(call("/p"))
    ev = rec.evidence()
    assert ev is not None
    assert len(ev.calls()) == MAX_CALLS and ev.truncated(), f"len={len(ev.calls())} truncated={ev.truncated()}"
    # Truncation carries over to whoever replays the evidence.
    rec2 = Recorder()
    rec2.add(ev, Origin.OWN)
    ev2 = rec2.evidence()
    assert ev2 is not None and ev2.truncated(), "truncation not carried over"
    # Replayed calls fill the cap first; the check's own calls then take
    # the place of the oldest replayed ones, never the other way round.
    replayed = Recorder()
    for _ in range(MAX_CALLS):
        replayed.record(call("/replayed"))
    rec = Recorder()
    rec.add(replayed.evidence(), Origin.CACHED)
    rec.record(call("/live-1"))
    rec.record(call("/live-2"))
    rec.add(evidence.of(call("/replayed-late")), Origin.CACHED)
    ev = rec.evidence()
    assert ev is not None
    got = ev.calls()
    assert len(got) == MAX_CALLS and ev.truncated(), f"len={len(got)} truncated={ev.truncated()}"
    # The own calls stay, in order, where they were among the replayed.
    own = [c.path for c in got if not c.cached]
    assert ",".join(own) == "/live-1,/live-2", f"live calls dropped: {own}"
    # It is the oldest replayed calls that went: the late one is kept.
    assert got[MAX_CALLS - 1].path == "/replayed-late" and got[MAX_CALLS - 1].cached, f"last call: {got[MAX_CALLS - 1]}"
    # With nothing replayed left, the oldest own call goes: the last calls
    # a check made are the ones that decided it.
    rec = Recorder()
    for _ in range(MAX_CALLS):
        rec.record(call("/page"))
    rec.record(Call(method="POST", path="/decides", status=200))
    ev = rec.evidence()
    assert ev is not None
    got = ev.calls()
    assert len(got) == MAX_CALLS and got[MAX_CALLS - 1].path == "/decides" and ev.truncated(), f"deciding call dropped: {got[MAX_CALLS - 1]}"


def test_json() -> None:
    rec = Recorder()
    rec.add(evidence.of(Call(method="GET", path="/users/u", status=200, etag='"v1"')), Origin.CACHED)
    rec.record(Call(method="GET", path="/perm", status=200, sha256="ab"))
    ev = rec.evidence()
    assert ev is not None
    b = _go_json(ev.to_json())
    want = (
        '{"upstream":[{"method":"GET","path":"/users/u","status":200,"etag":"\\"v1\\"","cached":true},'
        '{"method":"GET","path":"/perm","status":200,"sha256":"ab"}]}'
    )
    assert b == want, f"\n got {b}\nwant {want}"
    back = Evidence.from_json(json.loads(b))
    c = back.calls()
    assert len(c) == 2 and c[0].cached and c[1].sha256 == "ab" and not back.truncated(), c
    # Go: a nil *Evidence marshals as null, which omitempty leaves out of a
    # struct. Python has no struct tags: an absent evidence is None and has
    # no to_json(); a writer leaves the key out, as declog does.
    s = {k: v.to_json() for k, v in {"e": None}.items() if isinstance(v, Evidence)}
    assert _go_json(s) == "{}", s
    # Truncation is written.
    tr = Recorder()
    for _ in range(MAX_CALLS + 1):
        tr.record(call("/p"))
    trev = tr.evidence()
    assert trev is not None
    b = _go_json(trev.to_json())
    assert b.endswith('],"truncated":true}'), b[-40:]
