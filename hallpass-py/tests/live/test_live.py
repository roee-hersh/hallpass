"""Check cases against real systems. Opt-in:

    HALLPASS_LIVE_CASES=/path/to/cases.yaml python -m pytest tests/live

The cases file names a hallpass config file and a list of expected answers
(see examples/live-cases.yaml). Every connection in the config is probed
first. A case whose answer differs fails the test; the decision text is
printed for every case so an unknown can be understood.

Added over the Go test (test/live/live_test.go): a connection whose
credential is not available here (an env: secret unset or empty, a file:
secret missing, or a referenced connection that is itself not configured)
is NOT CONFIGURED: it is left out of the engine, its probe and cases are
skipped, and the session summary names what was missing. With
HALLPASS_LIVE_REQUIRE=1 such a connection, or a missing HALLPASS_LIVE_CASES,
fails the run instead of skipping.
"""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
import yaml

from hallpass.core import config, engine
from hallpass.core.context import background, with_timeout
from hallpass.core.errors import go_lower, go_trim_space
from hallpass.integrations import registry
from tests.live.conftest import CaseReport, ConnReport, LiveSummary

# Go: TestLive runs under go test's 10-minute default with a 5-minute
# context; the project-wide 120 s pytest timeout would cut a slow system off.
pytestmark = [pytest.mark.live, pytest.mark.timeout(600)]

CASES_ENV = "HALLPASS_LIVE_CASES"
REQUIRE_ENV = "HALLPASS_LIVE_REQUIRE"
TIMEOUT = 5 * 60.0


@dataclass
class Case:
    name: str = ""
    connection: str = ""
    user: str = ""
    groups: list[str] | None = None
    action: str = ""
    resource: str = ""
    expect: str = ""  # allow, deny or unknown
    code: str = ""  # optional reason code


@dataclass
class CasesFile:
    config: str = ""
    cases: list[Case] = field(default_factory=list)


class CasesError(Exception):
    pass


def _str(v: Any, where: str) -> str:
    # BaseLoader keeps every scalar as its text (null is ""), like decoding
    # into a Go string field; a list or mapping is a type error.
    if not isinstance(v, str):
        raise CasesError(f"{where}: cannot unmarshal {type(v).__name__} into string")
    return v


def load_cases(path: str) -> CasesFile:
    """The Go casesFile: unknown keys are ignored, missing ones are empty."""
    with open(path, "rb") as f:
        raw = f.read()
    try:
        doc = yaml.load(raw, Loader=yaml.BaseLoader)  # BaseLoader builds only str, list and dict
    except yaml.YAMLError as e:
        raise CasesError(f"{path}: {e}") from None
    if doc is None or doc == "":
        doc = {}
    if not isinstance(doc, dict):
        raise CasesError(f"{path}: cannot unmarshal {type(doc).__name__} into casesFile")
    cf = CasesFile(config=_str(doc.get("config", ""), f"{path}: config"))
    cases = doc.get("cases", "")
    if cases == "":
        cases = []
    if not isinstance(cases, list):
        raise CasesError(f"{path}: cases: cannot unmarshal {type(cases).__name__} into list")
    for i, c in enumerate(cases):
        where = f"{path}: cases[{i}]"
        if c == "":
            c = {}
        if not isinstance(c, dict):
            raise CasesError(f"{where}: cannot unmarshal {type(c).__name__} into case")
        groups = c.get("groups", "")
        if groups == "":
            groups = None
        elif not isinstance(groups, list):
            raise CasesError(f"{where}.groups: cannot unmarshal {type(groups).__name__} into list")
        else:
            groups = [_str(g, f"{where}.groups[{j}]") for j, g in enumerate(groups)]
        kw = {k: _str(c.get(k, ""), f"{where}.{k}") for k in ("name", "connection", "user", "action", "resource", "expect", "code")}
        cf.cases.append(Case(groups=groups, **kw))
    return cf


def _require() -> bool:
    return os.environ.get(REQUIRE_ENV, "") == "1"


def _case_names() -> list[str]:
    """Case names for parametrization. Any problem with the file is
    reported by the fixture when the test runs, not at collection."""
    path = os.environ.get(CASES_ENV, "")
    if not path:
        return []
    try:
        cf = load_cases(path)
    except Exception:
        return []
    return [c.name or f"case-{i + 1}" for i, c in enumerate(cf.cases)]


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "case_index" in metafunc.fixturenames:
        names = _case_names()
        if names:
            metafunc.parametrize("case_index", range(len(names)), ids=names)
        else:
            # One placeholder so the fixture still reports why nothing ran.
            metafunc.parametrize("case_index", [None], ids=["no-cases"])


@dataclass(repr=False)
class Live:
    cases: list[Case]
    eng: engine.Engine | None
    ctx: Any
    summary: LiveSummary
    # Connection id to what is missing for it.
    not_configured: dict[str, list[str]]
    probes: list[engine.ProbeReport]


def _missing(cfg: config.Config) -> dict[str, list[str]]:
    """What each connection lacks on this machine, in dependency order."""
    out: dict[str, list[str]] = {}
    for s in cfg.connections:
        integ = cfg.integrations[s.id]
        miss: list[str] = []
        for f in integ.fields():
            if f.secret:
                ref = s.secret(f.name).ref()
                if ref.startswith("env:") and not os.environ.get(ref[4:]):
                    miss.append(f"env {ref[4:]}")
                elif ref.startswith("file:") and not os.path.isfile(ref[5:]):
                    miss.append(f"file {ref[5:]}")
            elif f.ref and s.get(f.name) in out:
                miss.append(f"connection {s.get(f.name)} (not configured)")
        if miss:
            out[s.id] = miss
    return out


@pytest.fixture(scope="module")
def live(live_summary: LiveSummary) -> Iterator[Live]:
    summary = live_summary
    summary.active = True
    path = os.environ.get(CASES_ENV, "")
    if path == "":
        summary.note = f"{CASES_ENV} not set; no integration was run"
        if _require():
            pytest.fail(f"{REQUIRE_ENV}=1 but {CASES_ENV} is not set")
        pytest.skip(f"{CASES_ENV} not set")
    summary.cases_path = path
    try:
        cf = load_cases(path)
    except Exception as e:
        summary.note = f"cases file failed to load: {e}"
        pytest.fail(str(e))
    cfg_path = cf.config
    if not os.path.isabs(cfg_path):
        cfg_path = os.path.join(os.path.dirname(path), cfg_path)
    summary.config_path = cfg_path
    try:
        cfg = config.load(cfg_path, registry())
    except Exception as e:
        summary.note = f"config failed to load: {e}"
        pytest.fail(str(e))
    cfg.decision_cache = 0

    not_configured = _missing(cfg)
    for s in cfg.connections:
        summary.conn(s.id, s.integration).missing = not_configured.get(s.id, [])
    # Only connections that can run are built: one without its credential
    # would fail the whole build, as it does in Go.
    runnable = [s for s in cfg.connections if s.id not in not_configured]
    cfg = dataclasses.replace(
        cfg,
        connections=runnable,
        integrations={s.id: cfg.integrations[s.id] for s in runnable},
    )
    try:
        eng = engine.build(background(), cfg, engine.Options(decision_cache=0, identity_cache=0))
    except Exception as e:
        for s in runnable:
            summary.conn(s.id).error = f"engine build failed: {e}"
        pytest.fail(str(e))

    ctx, cancel = with_timeout(background(), TIMEOUT)
    try:
        probes = eng.probe(ctx)
        for p in probes:
            rep = summary.conn(p.id, p.integration)
            if p.err is not None:
                rep.probe_ok, rep.probe = False, str(p.err)
                continue
            rep.probe_ok, rep.probe = True, p.result.summary
            print(f"probe {p.id} ({p.integration}): {p.result.summary}")
            for w in p.result.warnings:
                print(f"  warning: {w}")
        yield Live(cf.cases, eng, ctx, summary, not_configured, probes)
    finally:
        cancel()


def _not_configured_text(live: Live, ids: list[str]) -> str:
    return "; ".join(f"{i} ({live.summary.conns[i].integration}): missing {', '.join(live.not_configured[i])}" for i in ids)


def test_live_configured(live: Live) -> None:
    """Every connection of the config has its credential here. Not in the
    Go test: it makes a run with nothing configured visible."""
    ids = list(live.not_configured)
    if not ids:
        return
    msg = "not configured: " + _not_configured_text(live, ids)
    if _require():
        pytest.fail(f"{REQUIRE_ENV}=1 and {msg}")
    pytest.skip(msg)


def test_live_probe(live: Live) -> None:
    """Go: the probe loop of TestLive (t.Errorf per failing probe)."""
    if not live.probes:
        pytest.skip("no connection is configured")
    errs = [f"probe {p.id} ({p.integration}): {p.err}" for p in live.probes if p.err is not None]
    assert not errs, "\n".join(errs)


def test_live(live: Live, case_index: int | None) -> None:
    """Go: the t.Run subtest of TestLive for each case."""
    if case_index is None:
        pytest.skip("the cases file has no cases")
    c = live.cases[case_index]
    name = c.name or f"case-{case_index + 1}"
    rep: ConnReport = live.summary.conn(c.connection, "" if c.connection in live.summary.conns else "not in config")
    if c.connection in live.not_configured:
        msg = f"connection {_not_configured_text(live, [c.connection])}"
        if _require():
            pytest.fail(f"{REQUIRE_ENV}=1 and {msg}")
        pytest.skip(msg)
    assert live.eng is not None
    res = live.eng.check(live.ctx, engine.Request(user=c.user, groups=c.groups, connection=c.connection, action=c.action, resource=c.resource))
    d = res.decision
    got = d.outcome.value
    code = d.code.value if d.code is not None else ""
    line = f"{c.connection} {c.user} {c.action} on {c.resource} -> {got} ({d.reason()})"
    print(line)
    errs: list[str] = []
    want = go_lower(go_trim_space(c.expect))
    if want != "" and got != want:
        errs.append(f"want {want}, got {got}: {d.reason()}")
    if c.code != "" and code != c.code:
        errs.append(f"want code {c.code}, got {code}")
    rep.cases.append(CaseReport(name=name, ok=not errs, line="; ".join(errs) if errs else f"{got} ({d.reason()})"))
    assert not errs, "\n".join(errs)
