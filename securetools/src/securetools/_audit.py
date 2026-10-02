"""One audit event per tool call, whatever its outcome.

The default sink logs each event as one JSON line on the ``securetools``
logger at INFO. Pass ``audit=`` to the toolkit to send events elsewhere.
Credentials never appear in an event; argument values are shortened.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import logging
from collections.abc import Callable, Mapping
from typing import Any

log = logging.getLogger("securetools")

_MAX_VALUE = 200


@dataclasses.dataclass
class AuditEvent:
    """What happened to one call.

    ``outcome`` is ``ran`` (the body returned), ``raised`` (the body raised),
    ``refused`` (a check stopped it before the body) or ``pending`` (it waits
    for approval). ``code`` names the check that refused it.
    """

    time: str
    tool: str
    effect: str
    outcome: str = "refused"
    code: str | None = None
    reason: str | None = None
    session: str | None = None
    user: str | None = None
    arguments: dict[str, Any] | None = None
    authorization: str | None = None
    approval: str | None = None
    approval_reasons: list[str] | None = None
    duration_ms: float | None = None

    @staticmethod
    def start(tool: str, effect: str) -> AuditEvent:
        return AuditEvent(time=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"), tool=tool, effect=effect)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in dataclasses.asdict(self).items() if v is not None}


AuditSink = Callable[[AuditEvent], None]


def log_audit(event: AuditEvent) -> None:
    """The default sink: one JSON line on the ``securetools`` logger."""
    log.info(json.dumps(event.to_dict(), default=repr, ensure_ascii=False))


def shorten(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Argument values made safe to log: long strings cut, other values as JSON or repr."""
    return {k: _short(v, 0) for k, v in arguments.items()}


def _short(v: Any, depth: int) -> Any:
    if isinstance(v, str):
        return v if len(v) <= _MAX_VALUE else v[:_MAX_VALUE] + f"...({len(v)} chars)"
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if depth < 3 and isinstance(v, Mapping):
        return {str(k): _short(x, depth + 1) for k, x in list(v.items())[:50]}
    if depth < 3 and isinstance(v, (list, tuple)):
        return [_short(x, depth + 1) for x in v[:50]]
    return _short(repr(v), depth + 1)
