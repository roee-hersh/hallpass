"""Argument checks that run before anything else: types and scope.

Model output is untrusted input to a tool. Every argument is checked against
its type hint (``str`` must be a ``str``, ``Literal`` must be one of its
values, ``list[str]`` a list of strings), then against the tool's own
validators, then against its scope rules. A hint this module cannot evaluate
(a string forward reference, an exotic generic) is not checked, so declare
validators for anything that matters.
"""

from __future__ import annotations

import collections.abc
import re
import types
import typing
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Union

# A scope rule for one argument: a glob, several globs (any may match), a
# compiled regular expression (must match the whole value), or a predicate.
ScopeRule = Union[str, Sequence[str], "re.Pattern[str]", Callable[[Any], bool]]

# A validator returns False or raises ValueError (or TypeError) to reject.
Validator = Callable[[Any], object]


class ArgumentError(ValueError):
    """An argument failed a type, validator or scope check."""

    def __init__(self, code: str, name: str, message: str) -> None:
        self.code, self.name = code, name
        super().__init__(message)


# Types


def type_matches(value: Any, hint: Any) -> bool:
    """True when ``value`` fits ``hint``, or when ``hint`` cannot be evaluated."""
    if hint is Any or hint is object:
        return True
    if hint is None or hint is type(None):
        return value is None
    if isinstance(hint, (str, typing.ForwardRef, typing.TypeVar)):
        return True
    origin = typing.get_origin(hint)
    args = typing.get_args(hint)
    if origin is typing.Annotated:
        return type_matches(value, args[0])
    if origin is typing.Literal:
        return any(value == a and type(value) is type(a) for a in args)
    if origin is Union or origin is types.UnionType:
        return any(type_matches(value, a) for a in args)
    if hint is bool:
        return isinstance(value, bool)
    if hint is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if hint is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if hint is str:
        return isinstance(value, str)
    if origin in (list, set, frozenset):
        return isinstance(value, origin) and (not args or all(type_matches(v, args[0]) for v in value))
    if origin in (collections.abc.Sequence, collections.abc.Iterable, collections.abc.Collection):
        if not isinstance(value, (list, tuple)):
            return False
        return not args or all(type_matches(v, args[0]) for v in value)
    if origin is tuple:
        if not isinstance(value, tuple):
            return False
        if not args:
            return True
        if len(args) == 2 and args[1] is Ellipsis:
            return all(type_matches(v, args[0]) for v in value)
        return len(value) == len(args) and all(type_matches(v, a) for v, a in zip(value, args, strict=True))
    if origin in (dict, collections.abc.Mapping, collections.abc.MutableMapping):
        if not isinstance(value, Mapping):
            return False
        if len(args) != 2:
            return True
        return all(type_matches(k, args[0]) and type_matches(v, args[1]) for k, v in value.items())
    if origin is not None:
        return True
    if isinstance(hint, type):
        try:
            return isinstance(value, hint)
        except TypeError:  # TypedDict and friends cannot be checked with isinstance
            return True
    return True


def hints(fn: Callable[..., Any]) -> tuple[dict[str, Any], list[str]]:
    """The function's resolved type hints, and the names whose hint could not
    be resolved. Resolution falls back to one annotation at a time, so one
    unresolvable hint leaves only its own argument unchecked."""
    try:
        return typing.get_type_hints(fn, include_extras=True), []
    except Exception:
        pass
    globalns = getattr(fn, "__globals__", {})
    resolved: dict[str, Any] = {}
    unresolved: list[str] = []
    for name, ann in dict(getattr(fn, "__annotations__", None) or {}).items():
        if isinstance(ann, str):
            try:
                # The developer's own annotation, evaluated as typing.get_type_hints would.
                ann = eval(ann, globalns, {})
            except Exception:
                unresolved.append(name)
        resolved[name] = ann
    return resolved, unresolved


# Scope


def _glob(pattern: str) -> re.Pattern[str]:
    """A glob over the whole value: ``*`` stays inside one ``/`` segment,
    ``**`` crosses segments, ``?`` is one character, ``[...]`` a class."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        elif pattern[i] == "[":
            j = pattern.find("]", i + 2)
            if j == -1:
                out.append(re.escape("["))
                i += 1
            else:
                inner = pattern[i + 1 : j]
                negate = inner.startswith("!")
                inner = inner[1:] if negate else inner
                inner = inner.replace("\\", "\\\\").replace("^", "\\^").replace("[", "\\[")
                out.append(f"[^/{inner}]" if negate else f"(?!/)[{inner}]")
                i = j + 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out), re.DOTALL)


class Scope:
    """Compiled scope rules for one tool, by argument name."""

    def __init__(self, rules: Mapping[str, ScopeRule]) -> None:
        self._rules: dict[str, Callable[[Any], bool]] = {name: self._compile(rule) for name, rule in rules.items()}

    @staticmethod
    def _compile(rule: ScopeRule) -> Callable[[Any], bool]:
        if isinstance(rule, re.Pattern):
            regex: re.Pattern[str] = rule
            return lambda v: isinstance(v, str) and regex.fullmatch(v) is not None
        if isinstance(rule, str):
            rule = [rule]
        if isinstance(rule, Sequence):
            patterns = [_glob(p) for p in rule]

            def by_glob(v: Any) -> bool:
                if not isinstance(v, str) or any(c in v for c in "\x00\r\n"):
                    return False
                # A dot segment walks out of whatever the glob was meant to fence in.
                if any(seg in (".", "..") for seg in re.split(r"[/\\]", v)):
                    return False
                return any(p.fullmatch(v) for p in patterns)

            return by_glob
        if callable(rule):
            return rule
        raise TypeError(f"unsupported scope rule: {rule!r}")

    def names(self) -> set[str]:
        return set(self._rules)

    def check(self, arguments: Mapping[str, Any]) -> None:
        for name, allowed in self._rules.items():
            value = arguments.get(name)
            try:
                if isinstance(value, (list, tuple, set, frozenset)):
                    ok = all(allowed(v) for v in value)
                else:
                    ok = bool(allowed(value))
            except Exception:  # a rule that cannot decide keeps the value out
                ok = False
            if not ok:
                raise ArgumentError("out_of_scope", name, f"{name}={_short(value)} is outside this tool's scope")


def check_arguments(
    arguments: Mapping[str, Any],
    types_by_name: Mapping[str, Any],
    validators: Mapping[str, Validator],
    variadic: Mapping[str, str] | None = None,
) -> None:
    """Types first, then validators. Raises ``ArgumentError``. ``variadic``
    names the ``*args`` ("*") and ``**kwargs`` ("**") parameters, whose hint
    applies to each item."""
    variadic = variadic or {}
    for name, value in arguments.items():
        hint = types_by_name.get(name, Any)
        kind = variadic.get(name)
        items = value if kind == "*" else value.values() if kind == "**" else (value,)
        for item in items:
            if not type_matches(item, hint):
                raise ArgumentError("invalid_arguments", name, f"{name} must be {_hint_name(hint)}, got {type(item).__name__}")
    for name, validate in validators.items():
        try:
            ok = validate(arguments.get(name))
        except (ValueError, TypeError) as e:
            raise ArgumentError("invalid_arguments", name, f"{name} is not valid: {e}") from None
        except Exception as e:  # a validator that cannot decide rejects
            raise ArgumentError("invalid_arguments", name, f"{name} could not be validated ({type(e).__name__})") from None
        if ok is False:
            raise ArgumentError("invalid_arguments", name, f"{name}={_short(arguments.get(name))} is not valid")


def _hint_name(hint: Any) -> str:
    return getattr(hint, "__name__", None) or str(hint).replace("typing.", "")


def _short(value: Any, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."
