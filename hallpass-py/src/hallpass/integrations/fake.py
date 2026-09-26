"""A test integration. It talks to nothing. It exists so the engine, server
and command can be exercised end to end, and so a fresh deployment can be
smoke-tested before any real connection is added."""

from __future__ import annotations

from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import (
    Code,
    Decision,
    allowed,
    denied,
    errorf,
    unknown_decision,
    unsupported,
    user_ambiguous,
    user_not_found,
)
from hallpass.core.integration import CheckRequest, Connection, Deps, Field, Identity, Integration, ProbeResult, Settings, User


class Fake(Integration):
    def name(self) -> str:
        return "fake"

    def fields(self) -> list[Field]:
        return [
            Field(name="users", description="comma-separated emails that exist and may read"),
            Field(name="admins", description="comma-separated emails allowed every action"),
            Field(
                name="fail",
                default="none",
                enum=("none", "upstream_timeout", "upstream_error", "credential_rejected", "upstream_rate_limited"),
                description="make every call fail with this code (for testing callers)",
            ),
        ]

    def actions(self) -> list[Action]:
        return [
            Action("thing.read", "read a thing (any known user)"),
            Action("thing.write", "write a thing (admins only)"),
            Action("thing.admin", "administer a thing (admins only)"),
        ]

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        fail = s.get("fail")
        return FakeConnection(_set(s.get("users")), _set(s.get("admins")), Code(fail) if fail not in ("", "none") else None)


def _set(csv: str) -> frozenset[str]:
    return frozenset(p.strip().lower() for p in csv.split(",") if p.strip())


class FakeConnection(Connection):
    def __init__(self, users: frozenset[str], admins: frozenset[str], fail: Code | None) -> None:
        self.users = users
        self.admins = admins
        self.fail = fail

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Known users and admins resolve; an email containing "ambiguous"
        is ambiguous; everything else has no account."""
        if self.fail is not None:
            raise errorf(self.fail, "fake failure")
        email = u.email.lower()
        if "ambiguous" in email:
            raise user_ambiguous(f"several accounts match {u.email}")
        if email not in self.users and email not in self.admins:
            raise user_not_found(f"no account for {u.email}")
        role = "admin" if email in self.admins else "user"
        return Identity(id=email, display=email, attrs={"role": role})

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """The three actions on "thing:<id>". The id "hidden" is not
        visible; "broken" is unsupported."""
        if self.fail is not None:
            raise errorf(self.fail, "fake failure")
        if r.resource.type != "thing" or r.resource.id == "":
            raise errorf(Code.INVALID_REQUEST, "resource must be thing:<id>")
        if r.resource.id == "hidden":
            return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f'thing "{r.resource.id}" is not visible to the fake credential')
        if r.resource.id == "broken":
            return unsupported(f'thing "{r.resource.id}" uses a policy the fake integration cannot evaluate')
        admin = r.identity.attr("role") == "admin"
        if r.action.name == "thing.read":
            return allowed(f"{r.identity.display} is a known user")
        if r.action.name in ("thing.write", "thing.admin"):
            if admin:
                return allowed(f"{r.identity.display} is an admin")
            return denied(f"{r.identity.display} is not an admin")
        raise RuntimeError("unreachable: unknown action")

    def probe(self, ctx: Context) -> ProbeResult:
        if self.fail is not None:
            raise errorf(self.fail, "fake failure")
        warnings: tuple[str, ...] = ()
        if not self.users and not self.admins:
            warnings = ("no users or admins configured; every check will answer user_not_found",)
        return ProbeResult(summary="fake integration ready", warnings=warnings)
