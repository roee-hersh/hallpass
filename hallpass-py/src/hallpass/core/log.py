"""Structured logging in the shape of Go's log/slog.

A Logger carries attributes and writes one record per call through a
handler: JSON lines (the server's format), text, or the standard library's
``logging`` (the default for an application embedding hallpass, so its log
configuration applies). Secrets render as ``[REDACTED]`` because every
attribute is rendered with str(), which a Secret overrides.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import sys
import threading
from typing import IO, Any

__all__ = ["DEBUG", "ERROR", "INFO", "WARN", "JSONHandler", "Logger", "StdlibHandler", "TextHandler", "discard", "go_json", "parse_level"]

DEBUG, INFO, WARN, ERROR = -4, 0, 4, 8
_NAMES = {DEBUG: "DEBUG", INFO: "INFO", WARN: "WARN", ERROR: "ERROR"}


def parse_level(s: str) -> int:
    """debug, info, warn or error (case-insensitive), like slog.Level."""
    v = s.strip().upper()
    table = {"DEBUG": DEBUG, "INFO": INFO, "WARN": WARN, "WARNING": WARN, "ERROR": ERROR}
    if v not in table:
        raise ValueError(f'slog: level string "{s}": unknown name')
    return table[v]


_GO_JSON_ESCAPES = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "\u2028": "\\u2028", "\u2029": "\\u2029"}
_GO_JSON_RE = re.compile("[<>&\u2028\u2029\ud800-\udfff]")


def go_json(v: Any) -> str:
    """json.dumps as Go's encoding/json.Marshal writes it: compact UTF-8,
    with <, >, &, U+2028 and U+2029 escaped as \\u003c and so on, and
    invalid UTF-8 (a lone surrogate here) as \\ufffd. Both write \\", \\\\,
    \\b, \\f, \\n, \\r, \\t and \\u00XX for the other C0 controls the same.
    The characters replaced can only occur inside strings, so a plain
    substitution over the whole text is exact."""
    text = json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    return _GO_JSON_RE.sub(lambda m: _GO_JSON_ESCAPES.get(m.group(0), "\\ufffd"), text)


def rfc3339nano(ts: float | datetime.datetime) -> str:
    """Go's time.RFC3339Nano in UTC, trailing zeros trimmed."""
    if isinstance(ts, datetime.datetime):
        dt = ts.astimezone(datetime.timezone.utc)
    else:
        dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        base += ("." + f"{dt.microsecond:06d}").rstrip("0")
    return base + "Z"


def _plain(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    return str(v)


class Handler:
    level = INFO

    def enabled(self, level: int) -> bool:
        return level >= self.level

    def handle(self, level: int, msg: str, attrs: list[tuple[str, Any]]) -> None:
        raise NotImplementedError


class JSONHandler(Handler):
    def __init__(self, stream: IO[str] | None = None, level: int = INFO) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.level = level
        self._lock = threading.Lock()

    def handle(self, level: int, msg: str, attrs: list[tuple[str, Any]]) -> None:
        rec: dict[str, Any] = {
            "time": rfc3339nano(datetime.datetime.now(datetime.timezone.utc)),
            "level": _NAMES.get(level, str(level)),
            "msg": msg,
        }
        for k, v in attrs:
            rec[k] = _plain(v)
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock:
            self.stream.write(line)
            self.stream.flush()


class TextHandler(Handler):
    def __init__(self, stream: IO[str] | None = None, level: int = INFO) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.level = level
        self._lock = threading.Lock()

    def handle(self, level: int, msg: str, attrs: list[tuple[str, Any]]) -> None:
        parts = [f"level={_NAMES.get(level, level)}", f"msg={json.dumps(msg, ensure_ascii=False)}"]
        for k, v in attrs:
            s = str(_plain(v)) if not isinstance(v, str) else v
            if any(c in s for c in ' ="') or s == "":
                s = json.dumps(s, ensure_ascii=False)
            parts.append(f"{k}={s}")
        with self._lock:
            self.stream.write(" ".join(parts) + "\n")
            self.stream.flush()


class StdlibHandler(Handler):
    """Hand records to a standard library logger (default "hallpass")."""

    _MAP = {DEBUG: logging.DEBUG, INFO: logging.INFO, WARN: logging.WARNING, ERROR: logging.ERROR}

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("hallpass")

    def enabled(self, level: int) -> bool:
        return self.logger.isEnabledFor(self._MAP.get(level, logging.INFO))

    def handle(self, level: int, msg: str, attrs: list[tuple[str, Any]]) -> None:
        text = msg
        if attrs:
            text += " " + " ".join(f"{k}={_plain(v)}" for k, v in attrs)
        self.logger.log(self._MAP.get(level, logging.INFO), text, extra={"hallpass": dict((k, _plain(v)) for k, v in attrs)})


class _Discard(Handler):
    def enabled(self, level: int) -> bool:
        return False

    def handle(self, level: int, msg: str, attrs: list[tuple[str, Any]]) -> None:
        pass


class Logger:
    def __init__(self, handler: Handler | None = None, attrs: list[tuple[str, Any]] | None = None) -> None:
        self.handler = handler if handler is not None else StdlibHandler()
        self._attrs = list(attrs or [])

    def with_(self, *pairs: Any, **attrs: Any) -> Logger:
        """A logger that adds attributes, given as key, value pairs or keywords."""
        extra = list(self._attrs)
        extra.extend(_pairs(pairs))
        extra.extend(attrs.items())
        return Logger(self.handler, extra)

    def log(self, level: int, msg: str, *pairs: Any, **attrs: Any) -> None:
        if not self.handler.enabled(level):
            return
        all_attrs = list(self._attrs)
        all_attrs.extend(_pairs(pairs))
        all_attrs.extend(attrs.items())
        self.handler.handle(level, msg, all_attrs)

    def debug(self, msg: str, *pairs: Any, **attrs: Any) -> None:
        self.log(DEBUG, msg, *pairs, **attrs)

    def info(self, msg: str, *pairs: Any, **attrs: Any) -> None:
        self.log(INFO, msg, *pairs, **attrs)

    def warn(self, msg: str, *pairs: Any, **attrs: Any) -> None:
        self.log(WARN, msg, *pairs, **attrs)

    def error(self, msg: str, *pairs: Any, **attrs: Any) -> None:
        self.log(ERROR, msg, *pairs, **attrs)


def _pairs(pairs: tuple[Any, ...]) -> list[tuple[str, Any]]:
    if len(pairs) % 2:
        pairs = (*pairs, "!BADKEY")
    return [(str(pairs[i]), pairs[i + 1]) for i in range(0, len(pairs), 2)]


def discard() -> Logger:
    return Logger(_Discard())
