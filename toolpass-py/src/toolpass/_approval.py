"""Human approval, out of band.

When a call needs a person's confirmation, the toolkit builds an
``ApprovalRequest`` and asks the toolkit's approver. An approver is any
callable that returns True (approved), False (rejected) or None (not decided
yet). None makes the tool answer "waiting for approval" without running.

``ApprovalQueue`` is the approver for the common case: the request waits in
the queue, the application shows it to a person (a Slack button, a web page),
and once they approve it, the same call from the same session runs once.
Approval is bound to the session, the tool and the exact arguments, and it is
used up by the call it approved, once that call reaches its body.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import threading
import time
import unicodedata
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from toolpass._toolkit import Call

Approver = Callable[["ApprovalRequest"], bool | None]


@dataclasses.dataclass(frozen=True)
class ApprovalRequest:
    """A call waiting for a person to approve it.

    ``id`` is derived from the session, the tool, the arguments, the reasons
    and the preview, so the model retrying the same call refers to the same
    request. ``reasons`` says
    why approval is needed; ``preview`` is the tool's own description of what
    the call will change, when it has one.
    """

    id: str
    call: Call
    reasons: tuple[str, ...]
    preview: str | None

    @staticmethod
    def make(call: Call, reasons: tuple[str, ...], preview: str | None) -> ApprovalRequest:
        return ApprovalRequest(_key(call, reasons, preview), call, reasons, preview)

    def describe(self) -> str:
        """A few lines for a person deciding: who, what, why, and the preview."""
        lines = [
            f"{self.call.session.user} asked the agent to run {self.call.tool} ({self.call.effect})",
            # ASCII escapes keep bidi and invisible characters visible to the person deciding.
            "arguments: " + json.dumps(_shown(dict(self.call.arguments)), ensure_ascii=True),
            "needs approval because: " + "; ".join(self.reasons),
        ]
        if self.preview:
            lines.append("preview:\n" + visible(self.preview))
        return "\n".join(lines)


def _plain(value: object, depth: int = 0) -> object:
    """``value`` as JSON-safe data with a stable order, for the approval key.
    Every container is tagged with its kind, so a list of pairs and a dict
    never spell the same key; mapping keys of any type are spelled with
    their type."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if depth > 20:
        return {"repr": repr(value)}
    if isinstance(value, Mapping):
        pairs = [[f"{type(k).__name__}:{k!r}", _plain(v, depth + 1)] for k, v in value.items()]
        return {"mapping": sorted(pairs, key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return {type(value).__name__: [_plain(v, depth + 1) for v in value]}
    if isinstance(value, (set, frozenset)):
        return {"set": sorted((_plain(v, depth + 1) for v in value), key=repr)}
    if isinstance(value, (bytes, bytearray)):
        return {"bytes": bytes(value).hex()}
    kind = f"{type(value).__module__}.{type(value).__qualname__}"
    state = _state(value)
    if state is not None:  # an object is keyed by its state, every field included
        return {"object": kind, "fields": _plain(state, depth + 1)}
    return {"object": kind, "repr": repr(value)}


def visible(text: str) -> str:
    """``text`` with control, format (bidi, zero-width) and unassigned
    characters spelled as escapes, so a person reads what is really there."""
    out = []
    for ch in text:
        if ch in "\n\t" or unicodedata.category(ch) not in ("Cc", "Cf", "Co", "Cn", "Zl", "Zp"):
            out.append(ch)
        else:
            out.append(f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}")
    return "".join(out)


def _state(value: object) -> dict[str, object] | None:
    """An object's field values, raw: every dataclass field (repr=False ones
    too), every pydantic field (exclude=True ones too, and extras, never
    through a serializer), or its ``__dict__``. None when it has none."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: getattr(value, f.name, None) for f in dataclasses.fields(value)}
    model_fields = getattr(type(value), "model_fields", None)
    if isinstance(model_fields, Mapping):
        state = {name: getattr(value, name, None) for name in model_fields}
        extra = getattr(value, "__pydantic_extra__", None)
        if isinstance(extra, Mapping):
            state.update({f"extra:{k}": v for k, v in extra.items()})
        return state
    attrs = getattr(value, "__dict__", None)
    return dict(attrs) if isinstance(attrs, dict) else None


def _shown(value: object, depth: int = 0) -> object:
    """``value`` as JSON-safe data for a person to read."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if depth > 20:
        return repr(value)
    if isinstance(value, Mapping):
        shown: dict[str, object] = {}
        for k, v in value.items():
            label = k if isinstance(k, str) else f"<{type(k).__name__}> {k!r}"
            while label in shown:  # two keys that read alike: show both, never drop one
                label += " (again)"
            shown[label] = _shown(v, depth + 1)
        return shown
    if isinstance(value, (list, tuple)):
        return [_shown(v, depth + 1) for v in value]
    state = _state(value)
    if state is not None:  # the field values the key binds, not a repr that may hide some
        return {type(value).__name__: _shown(state, depth + 1)}
    return repr(value)


def _key(call: Call, reasons: tuple[str, ...], preview: str | None) -> str:
    # The reasons and the preview are part of the key: an approval given for
    # one reason, or for one described effect, does not cover the same call
    # once a new reason applies or the preview describes something else.
    canonical = json.dumps([call.session.id, call.tool, _plain(dict(call.arguments)), sorted(reasons), preview], ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclasses.dataclass
class _Entry:
    request: ApprovalRequest
    state: str  # "pending", "approved", "claimed" (a call is using it), "rejected"
    at: float
    by: str | None = None


class ApprovalQueue:
    """An approver that keeps requests until a person decides.

    ``ttl`` is how many seconds a pending or decided request stays valid.
    Pass the queue as the toolkit's ``approver``, list ``pending()`` in your
    app, and call ``approve(id)`` or ``reject(id)`` when a person decides.
    """

    def __init__(self, ttl: float = 900.0, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}
        self._listeners: list[Callable[[ApprovalRequest], None]] = []

    def __call__(self, request: ApprovalRequest) -> bool | None:
        notify = False
        with self._lock:
            self._expire()
            entry = self._entries.get(request.id)
            if entry is None:
                self._entries[request.id] = _Entry(request, "pending", self._clock())
                notify = True
                verdict: bool | None = None
            elif entry.state == "approved":
                # Claimed, not used up: settle() uses it once the body runs, or gives it back.
                entry.state = "claimed"
                verdict = True
            elif entry.state == "rejected":
                del self._entries[request.id]
                verdict = False
            else:
                verdict = None
        if notify:
            failed: Exception | None = None
            for listen in list(self._listeners):
                try:
                    listen(request)
                except Exception as e:  # every listener still hears of it
                    failed = failed or e
            if failed is not None:
                # Nobody may have seen it: forget it, so the retry asks again.
                with self._lock:
                    self._entries.pop(request.id, None)
                raise failed
        return verdict

    def settle(self, id: str, used: bool) -> None:
        """Called by the toolkit after a claimed approval: ``used`` when the
        call reached its body (the approval is spent), otherwise it is given
        back, so a credential that was unavailable does not cost the person
        another approval."""
        with self._lock:
            entry = self._entries.get(id)
            if entry is None or entry.state != "claimed":
                return
            if used:
                del self._entries[id]
            else:
                entry.state = "approved"

    def on_request(self, listener: Callable[[ApprovalRequest], None]) -> None:
        """Call ``listener`` with each new pending request, e.g. to post it to Slack."""
        self._listeners.append(listener)

    def pending(self, session_id: str | None = None) -> list[ApprovalRequest]:
        with self._lock:
            self._expire()
            return [e.request for e in self._entries.values() if e.state == "pending" and (session_id is None or e.request.call.session.id == session_id)]

    def approve(self, id: str, by: str | None = None) -> ApprovalRequest:
        return self._decide(id, "approved", by)

    def reject(self, id: str, by: str | None = None) -> ApprovalRequest:
        return self._decide(id, "rejected", by)

    def _decide(self, id: str, state: str, by: str | None) -> ApprovalRequest:
        with self._lock:
            self._expire()
            entry = self._entries.get(id)
            if entry is None or entry.state != "pending":
                raise KeyError(f"no pending approval {id!r}")
            entry.state, entry.by, entry.at = state, by, self._clock()
            return entry.request

    def _expire(self) -> None:
        now = self._clock()
        for id in [k for k, e in self._entries.items() if now - e.at > self.ttl]:
            del self._entries[id]


def approve_all(_: ApprovalRequest) -> bool:
    """An approver that approves everything. For tests and demos only."""
    return True
