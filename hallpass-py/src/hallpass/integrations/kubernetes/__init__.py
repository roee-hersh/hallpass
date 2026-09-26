"""Checks permissions with SubjectAccessReview.

hallpass authenticates to the API server with a ServiceAccount token whose
only permission is `create subjectaccessreviews.authorization.k8s.io`. It
derives the Kubernetes username from the caller's email with a template,
adds the caller's groups (with an optional prefix) and system:authenticated,
and asks the API server whether that subject may perform the verb on the
resource. The API server evaluates RBAC and every configured authorizer;
nothing is persisted.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from hallpass.core import integration as integ
from hallpass.core import jsonx
from hallpass.core.cache import is_panic_type
from hallpass.core.catalog import Action, go_bytes, go_decode
from hallpass.core.context import Context
from hallpass.core.decision import Code, Decision, allowed, denied, errorf, unsupported, wrap_error
from hallpass.core.errors import go_quote, go_trim_space
from hallpass.core.template import Template, parse_template, validate_template
from hallpass.net import httpx

from .actions import ALIAS_LIST, Attributes, build_attributes, parse_raw

__all__ = ["INTEGRATION", "Connection", "Integration", "NotFoundError"]

T = TypeVar("T")

# Applies when username_template is unset.
DEFAULT_TEMPLATE = "{email}"

SAR_PATH = "/apis/authorization.k8s.io/v1/subjectaccessreviews"
SELF_RULES_PATH = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"

# Marks the groups the API server assigns itself (system:masters,
# system:authenticated, system:nodes, ...).
RESERVED_GROUP_PREFIX = "system:"


class Integration(integ.Integration):
    """The kubernetes product."""

    def name(self) -> str:
        return "kubernetes"

    def fields(self) -> list[integ.Field]:
        return [
            integ.url_field(True, "API server URL, e.g. https://10.20.0.5:6443"),
            integ.credential_field(True, "ServiceAccount token allowed to create subjectaccessreviews"),
            integ.Field(
                name="username_template",
                default=DEFAULT_TEMPLATE,
                validate=validate_template,
                description="how the API server names users: placeholders {email}, {local}, {domain}, e.g. oidc:{email}",
            ),
            integ.Field(name="group_prefix", description="prefix the API server puts on OIDC groups, e.g. oidc:"),
            integ.Field(
                name="add_authenticated_group",
                default="true",
                enum=("true", "false"),
                description="also send system:authenticated, as the API server would",
            ),
        ]

    def actions(self) -> list[Action]:
        acts = [
            Action(
                name="raw:<verb>:<resource>[.<group>][/<subresource>]",
                pattern=True,
                description="any Kubernetes verb on any resource, e.g. raw:create:deployments.apps, raw:get:pods/log",
            ),
            Action(
                name="raw:<verb>",
                pattern=True,
                description="a verb on a non-resource path, used with nonresource:<path>, e.g. raw:get with nonresource:/metrics",
            ),
        ]
        acts.extend(Action(name=a.name, description=a.desc) for a in ALIAS_LIST)
        return acts

    def match_action(self, name: str) -> Action | None:
        """Accept raw:<verb>:<resource> patterns."""
        if not name.startswith("raw:"):
            return None
        try:
            parse_raw(name)
        except ValueError:
            return None
        return Action(name=name, pattern=True, description="raw Kubernetes verb")

    def new(self, ctx: Context, s: integ.Settings, d: integ.Deps) -> Connection:
        hc = d.http_client(s)
        cred = s.secret("credential")
        if cred.is_zero():
            raise ValueError("credential is required")
        tpl_text = s.get("username_template")
        if tpl_text == "":
            tpl_text = DEFAULT_TEMPLATE
        try:
            tpl = parse_template(tpl_text)
        except ValueError as e:
            raise ValueError(f"username_template: {e}") from e
        client = httpx.Client(
            http=hc,
            base=s.get("url"),
            logger=d.logger,
            auth=httpx.bearer_auth(lambda _ctx: cred.get_string()),
        )
        return Connection(s, client, tpl, s.get("group_prefix"), s.bool("add_authenticated_group", True))


class NotFoundError(Exception):
    """Raised by Connection.get for a 404 (Go: kubernetes.ErrNotFound)."""

    def __init__(self) -> None:
        super().__init__("kubernetes: not found")


def _fail(err: Exception) -> None:
    """Re-raise a crash (Go: a panic) as it is; everything else is an error."""
    if is_panic_type(err):
        raise err


class Connection(integ.Connection):
    """One cluster."""

    def __init__(self, settings: integ.Settings, client: httpx.Client, template: Template, prefix: str, add_auth: bool) -> None:
        self.settings = settings
        self.client = client
        self.template = template
        self.prefix = prefix
        self.add_auth = add_auth

    def get(self, ctx: Context, path: str, decode: Callable[[Any], T] | None = None) -> T:
        """GET against the API server and decode the JSON response with
        decode (the identity when None). Other integrations that live
        inside a cluster (argocd) read their configuration through it. A
        404 raises NotFoundError; 401/403, transport and decode failures
        raise HallpassError."""
        try:
            _, v = self.client.get_json(ctx, path)
            return decode(v) if decode is not None else v
        except Exception as err:
            _fail(err)
            st = httpx.status(err)
            if st == 404:
                raise NotFoundError() from None
            if st == 403:
                raise wrap_error(Code.CREDENTIAL_REJECTED, err, f"hallpass's ServiceAccount may not read {path} (HTTP 403)") from err
            raise httpx.classify(err) from err  # type: ignore[misc]

    def username(self, email: str) -> str:
        """Apply the template to an email."""
        return self.template.render(email)

    def resolve_identity(self, ctx: Context, u: integ.User) -> integ.Identity:
        """A string transform; Kubernetes has no user directory."""
        name = self.username(u.email)
        groups: list[str] = []
        for g in u.groups:
            if self.prefix == "" and g.startswith(RESERVED_GROUP_PREFIX):
                # Without a prefix the caller's value reaches the review as
                # is, and system:masters is cluster-admin on most clusters.
                raise errorf(
                    Code.INVALID_REQUEST,
                    f"group {go_quote(g)} is reserved by Kubernetes; hallpass only sends {RESERVED_GROUP_PREFIX} groups it adds itself "
                    "unless the connection sets group_prefix",
                )
            groups.append(self.prefix + g)
        if self.add_auth:
            groups.append("system:authenticated")
        return integ.Identity(id=name, display=name, groups=tuple(groups))

    def check(self, ctx: Context, r: integ.CheckRequest) -> Decision:
        """Post one SubjectAccessReview."""
        try:
            attrs = build_attributes(r.action_name, r.resource)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, str(e)) from None
        spec: dict[str, Any] = {"user": r.identity.id}
        if r.identity.groups:
            spec["groups"] = list(r.identity.groups)
        if attrs.non_resource_path != "":
            spec["nonResourceAttributes"] = {"path": attrs.non_resource_path, "verb": attrs.verb}
        else:
            spec["resourceAttributes"] = _resource_attributes(attrs)
        req = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": spec}
        try:
            _, out = self.client.post_json(ctx, SAR_PATH, req, idempotent=True)
            st = _sar_status(out)
        except Exception as err:
            _fail(err)
            if httpx.status(err) == 403:
                raise wrap_error(Code.CREDENTIAL_REJECTED, err, "hallpass's ServiceAccount may not create subjectaccessreviews (HTTP 403)") from err
            raise httpx.classify(err) from err  # type: ignore[misc]
        what = describe(attrs)
        if jsonx.b(st, "allowed"):
            return allowed(f"{r.identity.id} may {what}{suffix(jsonx.s(st, 'reason'))}")
        evaluation_error = jsonx.s(st, "evaluationError")
        if evaluation_error != "":
            return unsupported(f"the API server could not evaluate {what}: {evaluation_error}")
        return denied(f"{r.identity.id} may not {what}{suffix(jsonx.s(st, 'reason'))}")

    def probe(self, ctx: Context) -> integ.ProbeResult:
        """Post a review for a throwaway subject. Any 201 proves the token
        is valid and may create reviews. It reveals nothing about real users."""
        req = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "spec": {"user": "hallpass:probe", "resourceAttributes": {"verb": "get", "resource": "namespaces", "name": "default"}},
        }
        try:
            _, out = self.client.post_json(ctx, SAR_PATH, req, idempotent=True)
            st = _sar_status(out)
        except Exception as err:
            _fail(err)
            if httpx.status(err) == 403:
                raise RuntimeError(
                    "the token is valid but may not create subjectaccessreviews.authorization.k8s.io; grant a ClusterRole with that one rule"
                ) from None
            raise httpx.classify(err) from err  # type: ignore[misc]
        warnings: list[str] = []
        if jsonx.b(st, "allowed"):
            warnings.append("the cluster lets an unknown user read namespaces; check that authorization is enabled")
        warnings.extend(self._extra_rules(ctx))
        return integ.ProbeResult(summary="can create SubjectAccessReviews", warnings=tuple(warnings))

    def _extra_rules(self, ctx: Context) -> list[str]:
        """Ask the API server what hallpass's own token may do (any
        authenticated subject may create a SelfSubjectRulesReview) and warn
        about anything beyond creating SubjectAccessReviews. Rules every
        authenticated user has (self reviews, discovery) are ignored."""
        req = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": "kube-system"}}
        try:
            _, out = self.client.post_json(ctx, SELF_RULES_PATH, req, idempotent=True)
            rules = _resource_rules(out)
        except Exception as err:  # noqa: BLE001 - _fail re-raises a crash; any failure is a warning
            _fail(err)
            return ["could not list the token's own permissions (SelfSubjectRulesReview failed); check for over-privilege by hand"]
        extra: list[str] = []
        for verbs, groups, resources in rules:
            if _all_self_review(resources):
                continue
            if resources == ["subjectaccessreviews"] and verbs == ["create"]:
                continue
            extra.append(",".join(verbs) + " " + ",".join(resources) + _group_suffix(groups))
        if not extra:
            return []
        if len(extra) > 8:
            extra = [*extra[:8], f"and {len(extra) - 8} more"]
        return ["the token can do more than create SubjectAccessReviews (in kube-system): " + "; ".join(extra) + ". Bind only the hallpass ClusterRole to it"]


def _resource_attributes(a: Attributes) -> dict[str, str]:
    """The resourceAttributes object, with Go's omitempty fields left out
    when empty and the keys in Go's field order."""
    out: dict[str, str] = {}
    if a.namespace:
        out["namespace"] = a.namespace
    out["verb"] = a.verb
    if a.group:
        out["group"] = a.group
    out["resource"] = a.resource
    if a.subresource:
        out["subresource"] = a.subresource
    if a.name:
        out["name"] = a.name
    return out


def _sar_status(v: Any) -> dict[str, Any]:
    """The status of a SubjectAccessReview answer, type-checked the way Go
    decodes it into sarResponse."""
    st = jsonx.o(jsonx.obj(v), "status")
    jsonx.b(st, "allowed")
    jsonx.b(st, "denied")
    jsonx.s(st, "reason")
    jsonx.s(st, "evaluationError")
    return st


def _resource_rules(v: Any) -> list[tuple[list[str], list[str], list[str]]]:
    """(verbs, apiGroups, resources) of each resourceRules entry of a
    SelfSubjectRulesReview answer."""
    st = jsonx.o(jsonx.obj(v), "status")
    jsonx.b(st, "incomplete")
    jsonx.s(st, "evaluationError")
    out = []
    for r in jsonx.arr(st, "resourceRules"):
        r = jsonx.obj(r)
        jsonx.strs(r, "resourceNames")
        out.append((jsonx.strs(r, "verbs"), jsonx.strs(r, "apiGroups"), jsonx.strs(r, "resources")))
    return out


def suffix(reason: str) -> str:
    reason = go_trim_space(reason)
    if reason == "":
        return ""
    b = go_bytes(reason)
    if len(b) > 200:
        # Go cuts at byte 200, which may split a rune; each byte of a split
        # rune reads as U+FFFD, as Go's JSON encoder writes it.
        reason = go_decode(b[:200]) + "..."
    return " (" + reason + ")"


def describe(a: Attributes) -> str:
    if a.non_resource_path != "":
        return a.verb + " " + a.non_resource_path
    res = a.resource
    if a.group != "":
        res += "." + a.group
    if a.subresource != "":
        res += "/" + a.subresource
    s = a.verb + " " + res
    if a.name != "":
        s += " " + a.name
    if a.namespace != "":
        s += " in namespace " + a.namespace
    return s


def _all_self_review(resources: list[str]) -> bool:
    if not resources:
        return False
    return all(r in ("selfsubjectaccessreviews", "selfsubjectrulesreviews", "selfsubjectreviews") for r in resources)


def _group_suffix(groups: list[str]) -> str:
    if not groups or groups == [""]:
        return ""
    return "." + ",".join(groups)


INTEGRATION = Integration()
