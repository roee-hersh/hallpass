"""The vault action catalog and the parsing of a question."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_quote, go_trim_space
from hallpass.integrations.vault.policy import CAPABILITIES

__all__ = ["ACTIONS", "ACTION_LIST", "PATH_RE", "RAW_PATTERN", "Target", "VaultAction", "catalog_actions", "match_action", "parse_raw", "parse_target"]


@dataclass(frozen=True)
class VaultAction:
    """One named question, in terms of the capabilities Vault needs."""

    name: str
    desc: str
    # The capabilities the request needs on the resolved path.
    need: tuple[str, ...]
    # The KV v2 sub-path the request goes to (data, metadata, destroy); ""
    # keeps the logical path (KV v1 and path: resources).
    kv2: str = ""
    # Match the path as a prefix, the way Vault sanitizes LIST requests.
    list: bool = False


ACTION_LIST = (
    VaultAction("secret.read", "read the secret", ("read",), "data", False),
    VaultAction("secret.write", "create or update the secret", ("create", "update"), "data", False),
    VaultAction("secret.delete", "delete the secret (KV v2: soft-delete the latest version)", ("delete",), "data", False),
    VaultAction("secret.list", "list the keys under the path", ("list",), "metadata", True),
    VaultAction("secret.metadata", "read the secret's metadata (KV v2)", ("read",), "metadata", False),
    VaultAction("secret.destroy", "permanently destroy the secret's versions (KV v2)", ("update",), "destroy", False),
)

ACTIONS = {a.name: a for a in ACTION_LIST}

RAW_PATTERN = "raw:<capability>"


def catalog_actions() -> list[Action]:
    """The actions of the vault integration."""
    out = [Action(a.name, a.desc + " (" + "+".join(a.need) + ")") for a in ACTION_LIST]
    out.append(Action(RAW_PATTERN, "any capability on a path: resource, e.g. raw:read, raw:update, raw:sudo, raw:list", pattern=True))
    return out


def parse_raw(name: str) -> VaultAction | None:
    """raw:<capability>."""
    if not name.startswith("raw:"):
        return None
    c = name[len("raw:") :]
    if c not in CAPABILITIES or c == "deny":
        return None
    return VaultAction(name, "perform a request needing " + c, (c,), "", c == "list")


def match_action(name: str) -> Action | None:
    """Accept raw:<capability>."""
    a = parse_raw(name)
    if a is None:
        return None
    return Action(RAW_PATTERN, a.desc, pattern=True)


# A Vault API path: segments of ordinary characters, no wildcards (a
# requested path is literal), no dot-only segments.
PATH_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:~=-]*(/[A-Za-z0-9_.@:~=-]+)*")


def _invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


@dataclass(frozen=True)
class Target:
    """A parsed question."""

    action: VaultAction
    # kv or path.
    kind: str
    # The logical path (kv:) or the whole API path (path:); the mount a kv:
    # path lives in is resolved against sys/mounts at check time, since
    # mounts may span several segments.
    path: str

    def __str__(self) -> str:
        return self.kind + ":" + self.path


def parse_target(action_name: str, r: Resource) -> Target:
    """Validate the action and resource; HallpassError(invalid_request)."""
    a = ACTIONS.get(action_name)
    if a is None:
        a = parse_raw(action_name)
        if a is None:
            raise _invalid(f"unknown action {go_quote(action_name)}")
    if r.query:
        raise _invalid(f"resource {go_quote(r.raw)} must not carry a query")
    p = go_trim_space(r.id).strip("/")
    if p == "" or len(p.encode("utf-8", "surrogatepass")) > 512 or not PATH_RE.fullmatch(p) or _bad_segments(p):
        raise _invalid(f"{r.type}: takes a Vault path of plain segments (letters, digits, _ . - @ : ~ =), no wildcards")
    t = Target(a, r.type, p)
    if r.type == "kv":
        if "/" not in p:
            raise _invalid("kv: takes <mount>/<key path>")
        if action_name.startswith("raw:"):
            raise _invalid("raw: capabilities take a path: resource; kv: resolves the path from the action")
    elif r.type == "path":
        if a.name in ("secret.destroy", "secret.metadata"):
            raise _invalid(f"{a.name} is a KV v2 question; use kv:<mount>/<key>")
    else:
        raise _invalid(f"resource type {go_quote(r.type)} is not kv: or path:")
    return t


def _bad_segments(p: str) -> bool:
    return any(seg.strip(".") == "" for seg in p.split("/"))
