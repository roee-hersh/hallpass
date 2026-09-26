"""Port of test/differential/argocd_test.go: compares the Argo CD RBAC
evaluator with the real argocd CLI (`argocd admin settings rbac can`).
Skips unless the argocd binary is on the PATH.

The CLI calls run in a small thread pool (Go runs them one after another);
each call is independent, so the answers are the same.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

from hallpass.integrations.argocd.rbac import BUILTIN_POLICY_CSV, Enforcer, Options

# Satisfies the CLI, which builds a Kubernetes client even when the policy
# comes from a file. Nothing is ever contacted.
DUMMY_KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- cluster: {server: "https://127.0.0.1:1"}
  name: dummy
contexts:
- context: {cluster: dummy, user: dummy}
  name: dummy
current-context: dummy
users:
- name: dummy
  user: {token: dummy}
"""


class UnexpectedOutput(Exception):
    pass


def argocd_can(kubeconfig: str, policy_file: str, default_role: str, sub: str, act: str, res: str, obj: str) -> bool:
    """Run `argocd admin settings rbac can` and return its printed answer.
    Anything other than "Yes" or "No" fails the test."""
    args = ["admin", "settings", "rbac", "can", sub, act, res, obj, "--policy-file", policy_file, "--strict=false"]
    if default_role != "":
        args += ["--default-role", default_role]
    out = subprocess.run(["argocd", *args], capture_output=True, text=True, env={**os.environ, "KUBECONFIG": kubeconfig}, timeout=60)
    answer = out.stdout.strip()
    if answer == "Yes":
        return True
    if answer == "No":
        return False
    raise UnexpectedOutput(f"argocd {args}: unexpected output\n{out.stdout}{out.stderr}")


@dataclass(frozen=True)
class Triple:
    res: str
    act: str
    obj: str


@dataclass(frozen=True)
class Policy:
    mode: str
    csv: str
    subjects: tuple[str, ...]
    triples: tuple[Triple, ...]


def _t(*items: tuple[str, str, str]) -> tuple[Triple, ...]:
    return tuple(Triple(*x) for x in items)


POLICIES = [
    Policy(
        mode="glob",
        csv="""
p, role:dev, applications, get, dev/*, allow
p, role:dev, applications, sync, dev/*, allow
p, role:ops, applications, *, */*, allow
p, role:ops, applications, delete, prod/*, deny
p, role:ops, clusters, get, *, allow
p, role:ops, applications, action/apps/Deployment/*, */*, allow
p, alice, repositories, *, foo/*, allow
p, bob, repositories, *, foo/https://github.com/argoproj/argo-cd.git, allow
p, carol, clusters, get, "https://github.com/*/*.git", allow
p, dan, applications, get, "{dev,staging}/*", allow
p, erin, applications, get, dev/app-?, allow
p, frank, applications, get, dev/[a-c]*, allow
p, grace, applications, get, dev/[!a-c]*, allow
p, heidi, applications, update, */*, allow
p, ivan, applications, get, dev/**, allow
p, judy, applications, get, dev/\\*, allow
g, developers, role:dev
g, sre, role:ops
g, role:ops, role:dev
g, admins, role:admin
g, chain1, chain2
g, chain2, chain3
g, chain3, role:dev
""",
        subjects=(
            "admin",
            "role:admin",
            "role:readonly",
            "role:dev",
            "role:ops",
            "developers",
            "sre",
            "admins",
            "alice",
            "bob",
            "carol",
            "dan",
            "erin",
            "frank",
            "grace",
            "heidi",
            "ivan",
            "judy",
            "chain1",
            "nobody",
        ),
        triples=_t(
            ("applications", "get", "dev/web"),
            ("applications", "get", "prod/web"),
            ("applications", "get", "staging/web"),
            ("applications", "sync", "dev/web"),
            ("applications", "delete", "dev/web"),
            ("applications", "delete", "prod/web"),
            ("applications", "create", "dev/web"),
            ("applications", "override", "prod/web"),
            ("applications", "rollback", "dev/web"),
            ("applications", "action/apps/Deployment/restart", "dev/web"),
            ("applications", "action/apps/StatefulSet/restart", "dev/web"),
            ("applications", "update", "dev/web"),
            ("applications", "update/apps/Deployment/ns/x", "dev/web"),
            ("applications", "delete/apps/Deployment/ns/x", "prod/web"),
            ("applications", "get", "dev/app-1"),
            ("applications", "get", "dev/app-12"),
            ("applications", "get", "dev/bee"),
            ("applications", "get", "dev/zed"),
            ("applications", "get", "dev/a/b"),
            ("applications", "get", "dev/*"),
            ("applications", "get", "dev"),
            ("clusters", "get", "https://github.com/argoproj/argo-cd.git"),
            ("clusters", "get", "https://github.com/argo-cd.git"),
            ("clusters", "get", "in-cluster"),
            ("clusters", "create", "in-cluster"),
            ("repositories", "delete", "foo/https://github.com/argoproj/argo-cd.git"),
            ("repositories", "delete", "foo/https://github.com/golang/go.git"),
            ("repositories", "get", "bar/x"),
            ("projects", "get", "dev"),
            ("projects", "update", "dev"),
            ("logs", "get", "dev/web"),
            ("exec", "create", "dev/web"),
            ("accounts", "get", "admin"),
            ("certificates", "create", "x"),
            ("gpgkeys", "delete", "x"),
            ("extensions", "invoke", "x"),
            ("write-repositories", "get", "x"),
            ("applicationsets", "delete", "dev/set"),
        ),
    ),
    Policy(
        mode="regex",
        csv="""
p, alice, clusters, get, "https://github.com/argo[a-z]{4}/argo-[a-z]+.git", allow
p, bob, applications, get, ^dev/, allow
p, carol, applications, get, dev, allow
p, dan, applications, "get|sync", "^(dev|staging)/", allow
p, erin, applications, get, "dev/(", allow
g, team, role:readonly
""",
        subjects=("alice", "bob", "carol", "dan", "erin", "team", "role:readonly", "admin", "nobody"),
        triples=_t(
            ("clusters", "get", "https://github.com/argoproj/argo-cd.git"),
            ("clusters", "get", "https://github.com/argoproj/1argo-cd.git"),
            ("applications", "get", "dev/web"),
            ("applications", "get", "xdev/web"),
            ("applications", "get", "my-dev-1"),
            ("applications", "sync", "staging/web"),
            ("applications", "sync", "prod/web"),
            ("applications", "get", "dev/("),
            ("applications", "get", "prod/x"),
            ("projects", "get", "dev"),
            ("clusters", "get", "in-cluster"),
        ),
    ),
]


@pytest.mark.timeout(1200)
def test_argocd_rbac_differential(tmp_path: Path) -> None:
    if shutil.which("argocd") is None:
        pytest.skip("argocd binary not on PATH")
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text(DUMMY_KUBECONFIG)
    kubeconfig.chmod(0o600)
    total = 0
    mismatches: list[str] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for p in POLICIES:
            for default_role in ("", "role:readonly"):
                cm = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-rbac-cm\ndata:\n  policy.matchMode: " + p.mode + "\n  policy.csv: |\n"
                for line in p.csv.split("\n"):
                    cm += "    " + line + "\n"
                file = tmp_path / f"{p.mode}-{default_role or 'none'}.yaml"
                file.write_text(cm)
                file.chmod(0o600)
                enf = Enforcer(Options(builtin=BUILTIN_POLICY_CSV, user=p.csv, match_mode=p.mode, default_role=default_role))
                cases = [(sub, tr) for sub in p.subjects for tr in p.triples]
                wants = pool.map(lambda c, f=str(file), d=default_role: argocd_can(str(kubeconfig), f, d, c[0], c[1].act, c[1].res, c[1].obj), cases)
                for (sub, tr), want in zip(cases, wants, strict=True):
                    total += 1
                    got = enf.enforce(sub, tr.res, tr.act, tr.obj)
                    if want != got:
                        mismatches.append(f"mode={p.mode} default={default_role!r} sub={sub!r} {tr.res} {tr.act} {tr.obj}: argocd={want} hallpass={got}")
    print(f"differential: {total} cases, {len(mismatches)} mismatches")
    assert not mismatches, "\n".join(mismatches)
