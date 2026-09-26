"""The ``live`` marker and the end-of-session summary of the live test.

The summary lists every connection of the live cases file as PASSED, FAILED
or NOT CONFIGURED (with the environment variables or files that were
missing), so a run in which nothing was configured never looks green.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

PASSED = "PASSED"
FAILED = "FAILED"
NOT_CONFIGURED = "NOT CONFIGURED"
NOT_RUN = "NOT RUN"


@dataclass
class CaseReport:
    name: str
    ok: bool
    line: str


@dataclass
class ConnReport:
    id: str
    integration: str
    # Why the connection cannot run here: "env FOO", "file /p", "connection x".
    missing: list[str] = field(default_factory=list)
    # None until probed; then whether the probe succeeded and its line.
    probe_ok: bool | None = None
    probe: str = ""
    # Set when the connection could not run at all (engine build failed).
    error: str = ""
    cases: list[CaseReport] = field(default_factory=list)

    def status(self) -> str:
        if self.missing:
            return NOT_CONFIGURED
        if self.error or self.probe_ok is False or any(not c.ok for c in self.cases):
            return FAILED
        if self.probe_ok is None and not self.cases:
            return NOT_RUN
        return PASSED


@dataclass
class LiveSummary:
    # Set once the live fixture ran, so a session without the live module
    # prints nothing.
    active: bool = False
    cases_path: str = ""
    config_path: str = ""
    # A reason the whole file did not run (no cases file, load failure).
    note: str = ""
    conns: dict[str, ConnReport] = field(default_factory=dict)

    def conn(self, id: str, integration: str = "") -> ConnReport:
        c = self.conns.get(id)
        if c is None:
            c = self.conns[id] = ConnReport(id=id, integration=integration)
        return c


_KEY = pytest.StashKey[LiveSummary]()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "live: calls real third-party systems (needs credentials)")
    config.stash[_KEY] = LiveSummary()


@pytest.fixture(scope="session")
def live_summary(request: pytest.FixtureRequest) -> LiveSummary:
    return request.config.stash[_KEY]


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter, exitstatus: int, config: pytest.Config) -> None:
    s = config.stash.get(_KEY, None)
    if s is None or not s.active:
        return
    tr = terminalreporter
    tr.write_sep("=", "hallpass live")
    if s.cases_path:
        tr.write_line(f"cases: {s.cases_path}" + (f" (config {s.config_path})" if s.config_path else ""))
    if s.note:
        tr.write_line(s.note)
    if not s.conns:
        if not s.note:
            tr.write_line("no integration was run")
        return
    counts: dict[str, int] = {}
    width = len(NOT_CONFIGURED)
    for c in s.conns.values():
        st = c.status()
        counts[st] = counts.get(st, 0) + 1
        detail: list[str] = []
        if c.missing:
            detail.append("missing " + ", ".join(c.missing))
        if c.error:
            detail.append(c.error)
        if c.probe_ok is not None:
            detail.append(("probe ok" if c.probe_ok else "probe failed") + (f": {c.probe}" if c.probe else ""))
        if c.cases:
            failed = sum(1 for x in c.cases if not x.ok)
            detail.append(f"{len(c.cases) - failed}/{len(c.cases)} cases passed")
        tr.write_line(f"{st:<{width}}  {c.id} ({c.integration or '?'})" + (": " + "; ".join(detail) if detail else ""))
        for x in c.cases:
            tr.write_line(f"{'':<{width}}    {'ok  ' if x.ok else 'FAIL'} {x.name}: {x.line}")
    order = (PASSED, FAILED, NOT_CONFIGURED, NOT_RUN)
    tr.write_line("totals: " + ", ".join(f"{counts[k]} {k.lower()}" for k in order if counts.get(k)))
    if not counts.get(PASSED) and not counts.get(FAILED):
        tr.write_line("WARNING: no integration was configured; nothing was checked against a real system")
