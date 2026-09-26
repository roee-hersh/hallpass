"""Helpers the Cloud and Data Center tests share (Go: the package-level
helpers of cloud_test.go)."""

from __future__ import annotations

import json
from typing import Any

from hallpass.core.decision import Code, Decision
from hallpass.core.integration import Connection, User
from hallpass.integrations.bitbucket import INTEGRATION
from tests import harness as itest

dana = User(email="dana@example.com")  # write on api, write on APP
bob = User(email="bob@example.com")  # read on api, read on APP and DOCS
ola = User(email="ola@example.com")  # workspace owner
cr = User(email="cr@example.com")  # create-repo on APP, nothing else
left = User(email="left@example.com")  # listed by email, no longer a member
root = User(email="root@example.com")  # global ADMIN (Data Center)
eve = User(email="eve@example.com")  # no grants (Data Center)


def write(w: itest.ResponseWriter, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write(json.dumps(v) + "\n")


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, INTEGRATION, u, action, resource)


def expect(d: Decision, code: Code, text: str) -> None:
    itest.expect_code(d, code)
    if text != "":
        assert text in d.text, f"text {d.text!r} does not contain {text!r}"
    itest.assert_no_canary(d.text)


class Tracker:
    """The servers and fakes a test started: closed at the end, with every
    spec mismatch and every error a fake recorded (Go: t.Errorf inside a
    handler) failing the test."""

    def __init__(self) -> None:
        self.servers: list[itest.Server] = []
        self.fakes: list[Any] = []

    def server(self) -> itest.Server:
        s = itest.Server()
        self.servers.append(s)
        return s

    def finish(self) -> None:
        errors: list[str] = []
        for s in self.servers:
            s.close()
            errors.extend(s.spec_errors)
        for f in self.fakes:
            errors.extend(f.errors)
        assert not errors, "\n".join(errors)
