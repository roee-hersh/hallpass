"""Evaluates Argo CD RBAC locally.

Argo CD has no API to ask "may user X do Y" for another user, so hallpass
reads the policy (argocd-rbac-cm, argocd-cm and AppProjects) through a
kubernetes connection and evaluates it with the same rules as the Argo CD
API server (see the rbac subpackage).
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any

from hallpass.core import integration as integ
from hallpass.core import jsonx
from hallpass.core.cache import TTL
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import Code, Decision, allowed, denied, errorf, unsupported
from hallpass.core.errors import go_quote, go_trim_space
from hallpass.integrations import kubernetes
from hallpass.net import httpx

from . import rbac
from .actions import ACT_ROLLBACK, ACTION_LIST, build_request, parse_pattern

__all__ = ["INTEGRATION", "Connection", "Integration"]

_NAME_RE = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")


def validate_name(v: str) -> None:
    if _NAME_RE.fullmatch(v) is None:
        raise ValueError(f"{go_quote(v)} is not a valid Kubernetes name")


# How long a loaded policy bundle is reused.
POLICY_CACHE_TTL = 30.0


class Integration(integ.Integration):
    """The argocd product."""

    def name(self) -> str:
        return "argocd"

    def fields(self) -> list[integ.Field]:
        return [
            integ.connection_ref_field(
                "kubernetes_connection",
                "kubernetes",
                True,
                "the kubernetes connection whose ServiceAccount may read Argo CD's config maps and AppProjects",
            ),
            integ.Field(name="namespace", default="argocd", validate=validate_name, description="namespace Argo CD is installed in"),
            integ.Field(name="rbac_configmap", default="argocd-rbac-cm", validate=validate_name, description="name of the RBAC config map"),
            integ.Field(
                name="user_subject",
                default="none",
                enum=("none", "email"),
                description="what Argo CD sees as the user's subject: none (evaluate groups only) or email",
            ),
        ]

    def actions(self) -> list[Action]:
        acts = [Action(name=a.name, description=a.desc) for a in ACTION_LIST]
        acts.extend(
            [
                Action(name="app.action/<group>/<kind>/<action>", pattern=True, description="run a resource action, e.g. app.action/apps/Deployment/restart"),
                Action(
                    name="app.update/<group>/<kind>/<namespace>/<name>",
                    pattern=True,
                    description="update one resource of the application (fine-grained)",
                ),
                Action(
                    name="app.delete/<group>/<kind>/<namespace>/<name>",
                    pattern=True,
                    description="delete one resource of the application (fine-grained)",
                ),
            ]
        )
        return acts

    def match_action(self, name: str) -> Action | None:
        """Accept the three pattern actions."""
        if parse_pattern(name) is None:
            return None
        return Action(name=name, pattern=True)

    def new(self, ctx: Context, s: integ.Settings, d: integ.Deps) -> Connection:
        kc = d.connection(s.get("kubernetes_connection"))
        if not isinstance(kc, kubernetes.Connection):
            raise ValueError(f"kubernetes_connection {go_quote(s.get('kubernetes_connection'))} is not a kubernetes connection")
        return Connection(kc, s.get("namespace"), s.get("rbac_configmap"), s.get("user_subject"), d.now)


@dataclass
class Bundle:
    """Everything read from the cluster, parsed once."""

    user_policy: str = ""
    # User policy that Argo CD itself would reject.
    user_err: ValueError | None = None
    match_mode: str = rbac.GLOB_MATCH_MODE
    default_role: str = ""
    scopes: list[str] | None = None
    projects: dict[str, rbac.Project] = field(default_factory=dict)
    # Fine-grained update/delete inherit from update/delete.
    inherit: bool = False
    rollback_act: str = rbac.ACTION_SYNC
    # The policy names users (subjects with "@").
    user_level: bool = False
    argocd_cm_seen: bool = False

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    # Per project ("" = none).
    _enforcers: dict[str, rbac.Enforcer] = field(default_factory=dict, repr=False, compare=False)

    def enforcer(self, project: str) -> rbac.Enforcer:
        """The enforcer for a project ("" for none), built once. Raises
        ValueError for a policy Argo CD would reject."""
        with self._lock:
            e = self._enforcers.get(project)
            if e is not None:
                return e
            if self.user_err is not None:
                raise self.user_err
            runtime = ""
            p = self.projects.get(project)
            if p is not None:
                runtime = p.policies_string()
            opts = rbac.Options(
                builtin=rbac.BUILTIN_POLICY_CSV, user=self.user_policy, runtime=runtime, match_mode=self.match_mode, default_role=self.default_role
            )
            try:
                e = rbac.Enforcer(opts)
            except rbac.PolicyError:
                if runtime == "":
                    raise
                # Argo CD falls back to the enforcer without the project
                # policy when the project policy is invalid.
                e = rbac.Enforcer(rbac.Options(builtin=rbac.BUILTIN_POLICY_CSV, user=self.user_policy, match_mode=self.match_mode, default_role=self.default_role))
            self._enforcers[project] = e
            return e


def _config_map(v: Any) -> dict[str, str]:
    """The data of a ConfigMap, decoded as Go decodes map[string]string."""
    data = jsonx.o(jsonx.obj(v), "data")
    out: dict[str, str] = {}
    for k in data:
        out[k] = jsonx.s(data, k)
    return out


def _project_list(v: Any) -> list[rbac.Project]:
    out = []
    for it in jsonx.arr(jsonx.obj(v), "items"):
        it = jsonx.obj(it)
        p = rbac.Project(name=jsonx.s(jsonx.o(it, "metadata"), "name"))
        for r in jsonx.arr(jsonx.o(it, "spec"), "roles"):
            r = jsonx.obj(r)
            p.roles.append(rbac.ProjectRole(name=jsonx.s(r, "name"), policies=jsonx.strs(r, "policies"), groups=jsonx.strs(r, "groups")))
        out.append(p)
    return out


class Connection(integ.Connection):
    """One Argo CD installation."""

    def __init__(self, k8s: kubernetes.Connection, namespace: str, rbac_cm: str, user_subject: str, now: Any) -> None:
        self.k8s = k8s
        self.namespace = namespace
        self.rbac_cm = rbac_cm
        self.user_subject = user_subject
        self.now = now
        # Holds the one policy bundle under the key ().
        self.policies: TTL[tuple[()], Bundle] = TTL(1)
        self.policies.set_clock(now)

    def load(self, ctx: Context) -> Bundle:
        """The cached policy bundle, or one fetch shared with concurrent
        callers (TTL.do: a fetch runs on a context detached from the first
        caller's cancellation, a crash in it becomes a PanicError for
        everyone waiting, and its evidence is replayed to every check the
        bundle serves)."""
        return self.policies.do(ctx, (), self._fill_bundle)

    def _fill_bundle(self, ctx: Context) -> tuple[Bundle, float]:
        """The cache fill: one fetch, kept for POLICY_CACHE_TTL."""
        return self._fetch(ctx), POLICY_CACHE_TTL

    def _fetch(self, ctx: Context) -> Bundle:
        b = Bundle()
        ns = httpx.path_escape(self.namespace)

        try:
            rbac_cm = self.k8s.get(ctx, "/api/v1/namespaces/" + ns + "/configmaps/" + httpx.path_escape(self.rbac_cm), _config_map)
        except kubernetes.NotFoundError:
            # No RBAC config map: builtin policy only, as Argo CD would.
            pass
        else:
            b.user_policy = rbac.policy_csv(rbac_cm)
            if rbac_cm.get(rbac.MATCH_MODE_KEY, "") == rbac.REGEX_MATCH_MODE:
                b.match_mode = rbac.REGEX_MATCH_MODE
            b.default_role = rbac_cm.get(rbac.POLICY_DEFAULT_KEY, "")
            try:
                b.scopes = rbac.parse_scopes(rbac_cm.get(rbac.SCOPES_KEY, ""))
            except ValueError as e:
                b.user_err = ValueError(f"scopes: {e}")
            try:
                rbac.parse_policy(b.user_policy)
            except rbac.PolicyError as e:
                b.user_err = e

        try:
            argocd_cm = self.k8s.get(ctx, "/api/v1/namespaces/" + ns + "/configmaps/argocd-cm", _config_map)
        except kubernetes.NotFoundError:
            pass
        else:
            b.argocd_cm_seen = True
            # Default true since v3: update/delete no longer imply update/*, delete/*.
            if argocd_cm.get("server.rbac.disableApplicationFineGrainedRBACInheritance", "") == "false":
                b.inherit = True
            if argocd_cm.get("server.rbac.rollback.enforce.enable", "") == "true":
                b.rollback_act = rbac.ACTION_ROLLBACK

        try:
            projects = self.k8s.get(ctx, "/apis/argoproj.io/v1alpha1/namespaces/" + ns + "/appprojects", _project_list)
        except kubernetes.NotFoundError:
            projects = []
        for p in projects:
            b.projects[p.name] = p

        # user_level: the policy names users (subjects containing "@") in a
        # way that only the subject claim can reach. With "email" in scopes
        # the email is also a group value, and a group value matches a g
        # line's subject; a p line's subject is never matched through a
        # group unless some g line starts with it (Argo CD's prefilter).
        email_scope = "email" in (b.scopes or [])
        try:
            pol = rbac.parse_policy(b.user_policy)
        except rbac.PolicyError:
            pol = None
        if pol is not None:
            g_subs: set[str] = set()
            for lk in pol.links:
                g_subs.add(lk.sub)
                if "@" in lk.sub and not email_scope:
                    b.user_level = True
            for r in pol.rules:
                if "@" in r.sub and not (email_scope and r.sub in g_subs):
                    b.user_level = True
        return b

    def resolve_identity(self, ctx: Context, u: integ.User) -> integ.Identity:
        """Map the caller to an Argo CD subject and group values."""
        subject = u.email if self.user_subject == "email" else ""
        return integ.Identity(id=subject, display=u.email, groups=tuple(u.groups))

    def check(self, ctx: Context, r: integ.CheckRequest) -> Decision:
        """Evaluate the request against the loaded policy."""
        try:
            req = build_request(r.action_name, r.resource)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, str(e)) from None
        b = self.load(ctx)
        if req.act == ACT_ROLLBACK:
            req.act = b.rollback_act
        project = rbac.project_from_request(req.res, req.obj)
        if project not in b.projects:
            project = ""
        try:
            enf = b.enforcer(project)
        except ValueError as err:
            return unsupported(f"Argo CD's {self.rbac_cm} is not a valid policy and cannot be evaluated: {err}")
        groups = list(r.identity.groups)
        for s in b.scopes or []:
            if s == "email":
                groups = [*groups, r.user.email]
        subject = r.identity.id

        acts = [req.act]
        if req.fine_grained and b.inherit:
            # v2 behaviour: the top-level verb is checked first, then the
            # fine-grained one.
            acts = [req.top_act, req.act]
        for act in acts:
            if enf.enforce_claims(subject, groups, req.res, act, req.obj):
                return allowed(f"Argo CD policy allows {act} {req.res} on {req.obj} for {who(subject, groups)}")
        if subject == "" and b.user_level:
            return unsupported(
                f"no group rule allows {req.act} {req.res} on {req.obj}, and the policy has user-level rules that cannot be evaluated with user_subject: none"
            )
        return denied(f"Argo CD policy has no rule allowing {req.act} {req.res} on {req.obj} for {who(subject, groups)}")

    def probe(self, ctx: Context) -> integ.ProbeResult:
        """Read the policy and report what was found."""
        # The probe reads the cluster itself, whatever the cache holds: what
        # it finds replaces the bundle, evidence included, and a failure
        # leaves the bundle checks are being answered from.
        b = self.policies.refresh(ctx, (), self._fill_bundle)
        lines = 0
        for ln in b.user_policy.split("\n"):
            ln = go_trim_space(ln)
            if ln != "" and not ln.startswith("#"):
                lines += 1
        summary = f"{lines} policy lines, {len(b.projects)} projects, match mode {b.match_mode}, default role {go_quote(b.default_role)}"
        warnings: list[str] = []
        if b.user_err is not None:
            warnings.append("the RBAC policy is invalid and every check will answer unknown: " + str(b.user_err))
        if not b.argocd_cm_seen:
            warnings.append("argocd-cm was not found; assuming Argo CD v3 defaults (no fine-grained inheritance, rollback checks sync)")
        if self.user_subject == "none" and b.user_level:
            warnings.append(
                "the policy names individual users but user_subject is none; those rules are not evaluated "
                "(set user_subject: email if Argo CD's subject claim is the email)"
            )
        return integ.ProbeResult(summary=summary, warnings=tuple(warnings))


def who(subject: str, groups: list[str]) -> str:
    if subject == "":
        if not groups:
            return "a user with no groups"
        return "groups " + ", ".join(groups)
    if not groups:
        return subject
    return subject + " (groups " + ", ".join(groups) + ")"


INTEGRATION = Integration()
