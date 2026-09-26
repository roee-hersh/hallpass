"""Port of internal/declog/declog_test.go."""

from __future__ import annotations

import datetime
import io
import json
import sys
from pathlib import Path

from hallpass.core import evidence
from hallpass.core.declog import DecisionLog, Entry, open_log
from hallpass.core.evidence import Call


def test_log_writes_json_lines() -> None:
    buf = io.StringIO()
    log = DecisionLog(buf)
    log.now = lambda: 0.0  # time.Unix(0, 0)
    log.log(Entry(connection="c", user="u@x", action="a", resource="r:1", decision="allow", code="allowed"))
    log.log(Entry(connection="c", user="u@x", action="a", resource="r:1", decision="deny", code="denied"))
    lines = buf.getvalue().strip().split("\n")
    assert len(lines) == 2, f"lines = {len(lines)}"
    e = json.loads(lines[0])
    assert e["decision"] == "allow"
    assert datetime.datetime.fromisoformat(e["time"].replace("Z", "+00:00")).timestamp() == 0, e
    # fresh and evidence appear only when set, and evidence round-trips.
    assert "fresh" not in lines[0] and "evidence" not in lines[0], f"empty fields written: {lines[0]}"
    buf.seek(0)
    buf.truncate()
    log.log(
        Entry(
            decision="deny",
            fresh=True,
            evidence=evidence.of(
                Call(method="GET", path="/users/u", status=200, etag='"v1"', cached=True),
                Call(method="GET", path="/perm", status=200, sha256="ab"),
            ),
        )
    )
    line = buf.getvalue().strip()
    assert '"fresh":true' in line, line
    assert (
        '"evidence":{"upstream":[{"method":"GET","path":"/users/u","status":200,"etag":"\\"v1\\"","cached":true},'
        '{"method":"GET","path":"/perm","status":200,"sha256":"ab"}]}' in line
    ), line


def test_open_file(tmp_path: Path) -> None:
    p = tmp_path / "decisions.log"
    log = open_log(str(p))
    log.log(Entry(decision="unknown"))
    log.close()
    assert '"decision":"unknown"' in p.read_text()
    for name in ["", "none", "stderr", "stdout"]:
        open_log(name)
    # Go: a nil *Logger's Log is a no-op; here the discarding log is.
    open_log("none").log(Entry())


# -- Behaviour pinned against the Go implementation ------------------------------


def test_entry_is_written_as_go_marshals_it() -> None:
    """Field order, omitempty, UTC RFC 3339 time and encoding/json's
    escaping of <, >, & and U+2028 (what json.Marshal(Entry) writes)."""
    buf = io.StringIO()
    log = DecisionLog(buf)
    log.log(
        Entry(
            time=1.5,
            connection="c",
            user="u@x",
            groups=["g<1>"],
            action="a&b",
            resource="r:1",
            decision="deny",
            code="denied",
            reason="denied: x y",
            duration_ms=7,
            status=200,
            remote="10.0.0.1:5",
        )
    )
    assert buf.getvalue() == (
        '{"time":"1970-01-01T00:00:01.5Z","connection":"c","user":"u@x","groups":["g\\u003c1\\u003e"],'
        '"action":"a\\u0026b","resource":"r:1","decision":"deny","code":"denied","reason":"denied: x\\u2028y",'
        '"cached":false,"duration_ms":7,"status":200,"remote":"10.0.0.1:5"}\n'
    )


def test_log_does_not_change_the_entry() -> None:
    """Go passes the Entry by value: filling in the time is not visible to
    the caller."""
    log = DecisionLog(io.StringIO())
    e = Entry(decision="allow")
    log.log(e)
    assert e.time is None


def test_open_appends(tmp_path: Path) -> None:
    p = tmp_path / "decisions.log"
    p.write_text("previous\n")
    log = open_log(str(p))
    log.log(Entry(decision="allow"))
    log.close()
    lines = p.read_text().splitlines()
    assert lines[0] == "previous" and '"decision":"allow"' in lines[1]
    q = tmp_path / "new.log"
    open_log(str(q)).close()
    if sys.platform != "win32":  # Windows has no Unix permission bits
        assert q.stat().st_mode & 0o777 == 0o600
