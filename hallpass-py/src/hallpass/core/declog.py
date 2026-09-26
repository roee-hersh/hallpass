"""The decision log: one JSON object per line for every answered check.
It is the audit trail."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Any

from hallpass.core.evidence import Evidence
from hallpass.core.log import rfc3339nano

__all__ = ["DecisionLog", "Entry", "open_log"]


@dataclass
class Entry:
    connection: str
    user: str
    action: str
    resource: str
    decision: str
    code: str
    reason: str
    cached: bool
    duration_ms: int
    status: int
    groups: list[str] | tuple[str, ...] | None = None
    # Set when the caller asked for an answer straight from the upstream.
    fresh: bool = False
    remote: str = ""
    # What the upstream said when the decision was computed.
    evidence: Evidence | None = None
    time: float | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "time": rfc3339nano(self.time if self.time is not None else time.time()),
            "connection": self.connection,
            "user": self.user,
        }
        if self.groups:
            out["groups"] = list(self.groups)
        out.update(
            action=self.action,
            resource=self.resource,
            decision=self.decision,
            code=self.code,
            reason=self.reason,
            cached=self.cached,
        )
        if self.fresh:
            out["fresh"] = True
        out["duration_ms"] = self.duration_ms
        out["status"] = self.status
        if self.remote:
            out["remote"] = self.remote
        if self.evidence is not None:
            out["evidence"] = self.evidence.to_json()
        return out


class DecisionLog:
    """Writes entries. Safe for concurrent use."""

    def __init__(self, w: IO[str] | None, closer: IO[str] | None = None, now: Callable[[], float] = time.time) -> None:
        self._w = w
        self._c = closer
        self._lock = threading.Lock()
        self.now = now

    def log(self, e: Entry) -> None:
        if self._w is None:
            return
        if e.time is None:
            e.time = self.now()
        try:
            line = json.dumps(e.to_json(), ensure_ascii=False, separators=(",", ":")) + "\n"
        except (TypeError, ValueError):
            return
        with self._lock:
            try:
                self._w.write(line)
                self._w.flush()
            except OSError:
                pass

    def close(self) -> None:
        if self._c is not None:
            self._c.close()


def open_log(path: str) -> DecisionLog:
    """ "stderr" and "stdout" name the standard streams; "" or "none" discards."""
    if path in ("", "none"):
        return DecisionLog(None)
    if path == "stderr":
        return DecisionLog(sys.stderr)
    if path == "stdout":
        return DecisionLog(sys.stdout)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    f = os.fdopen(fd, "a", encoding="utf-8")
    return DecisionLog(f, f)
