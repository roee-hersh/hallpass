// Package kubernetes checks permissions with SubjectAccessReview.
//
// hallpass authenticates to the API server with a ServiceAccount token whose
// only permission is `create subjectaccessreviews.authorization.k8s.io`. It
// derives the Kubernetes username from the caller's email with a template,
// adds the caller's groups (with an optional prefix) and system:authenticated,
// and asks the API server whether that subject may perform the verb on the
// resource. The API server evaluates RBAC and every configured authorizer;
// nothing is persisted.
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// Integration is the kubernetes product.
type Integration struct{}

// Name is "kubernetes".
func (Integration) Name() string { return "kubernetes" }

// Fields of a kubernetes connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.URLField(true, "API server URL, e.g. https://10.20.0.5:6443"),
		integration.CredentialField(true, "ServiceAccount token allowed to create subjectaccessreviews"),
		{Name: "username_template", Default: defaultTemplate, Validate: integration.ValidateTemplate,
			Description: "how the API server names users: placeholders {email}, {local}, {domain}, e.g. oidc:{email}"},
		{Name: "group_prefix", Description: "prefix the API server puts on OIDC groups, e.g. oidc:"},
		{Name: "add_authenticated_group", Default: "true", Enum: []string{"true", "false"},
			Description: "also send system:authenticated, as the API server would"},
	}
}

// defaultTemplate applies when username_template is unset.
const defaultTemplate = "{email}"

// Actions of the kubernetes integration.
func (Integration) Actions() []catalog.Action {
	acts := []catalog.Action{
		{
			Name:        "raw:<verb>:<resource>[.<group>][/<subresource>]",
			Pattern:     true,
			Description: "any Kubernetes verb on any resource, e.g. raw:create:deployments.apps, raw:get:pods/log",
		},
		{
			Name:        "raw:<verb>",
			Pattern:     true,
			Description: "a verb on a non-resource path, used with nonresource:<path>, e.g. raw:get with nonresource:/metrics",
		},
	}
	for _, a := range aliasList {
		acts = append(acts, catalog.Action{Name: a.name, Description: a.desc})
	}
	return acts
}

// MatchAction accepts raw:<verb>:<resource> patterns.
func (Integration) MatchAction(name string) (catalog.Action, bool) {
	if !strings.HasPrefix(name, "raw:") {
		return catalog.Action{}, false
	}
	if _, err := parseRaw(name); err != nil {
		return catalog.Action{}, false
	}
	return catalog.Action{Name: name, Pattern: true, Description: "raw Kubernetes verb"}, true
}

// New builds a connection.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	cred := s.Secret("credential")
	if cred.IsZero() {
		return nil, errors.New("credential is required")
	}
	tplText := s.Get("username_template")
	if tplText == "" {
		tplText = defaultTemplate
	}
	tpl, err := integration.ParseTemplate(tplText)
	if err != nil {
		return nil, fmt.Errorf("username_template: %w", err)
	}
	c := &Connection{
		settings: s,
		template: tpl,
		prefix:   s.Get("group_prefix"),
		addAuth:  s.Bool("add_authenticated_group", true),
	}
	c.client = &httpx.Client{
		HTTP:   hc,
		Base:   s.Get("url"),
		Logger: d.Logger,
		Auth:   httpx.BearerAuth(func(context.Context) (string, error) { return cred.GetString() }),
	}
	return c, nil
}

// Connection is one cluster.
type Connection struct {
	settings *integration.Settings
	client   *httpx.Client
	template integration.Template
	prefix   string
	addAuth  bool
}

// ErrNotFound is returned by Get for a 404.
var ErrNotFound = errors.New("kubernetes: not found")

// Get performs a GET against the API server and decodes the JSON response.
// Other integrations that live inside a cluster (argocd) read their
// configuration through it. A 404 returns ErrNotFound; 401/403 and
// transport failures come back as *integration.Error.
func (c *Connection) Get(ctx context.Context, path string, out any) error {
	_, err := c.client.GetJSON(ctx, path, nil, out)
	if err == nil {
		return nil
	}
	switch httpx.Status(err) {
	case 404:
		return ErrNotFound
	case 403:
		return integration.Wrap(integration.CodeCredentialRejected, err, "hallpass's ServiceAccount may not read %s (HTTP 403)", path)
	}
	return httpx.Classify(err)
}

// Username applies the template to an email.
func (c *Connection) Username(email string) string { return c.template.Render(email) }

// reservedGroupPrefix marks the groups the API server assigns itself
// (system:masters, system:authenticated, system:nodes, ...).
const reservedGroupPrefix = "system:"

// ResolveIdentity is a string transform; Kubernetes has no user directory.
func (c *Connection) ResolveIdentity(_ context.Context, u integration.User) (integration.Identity, error) {
	name := c.Username(u.Email)
	groups := make([]string, 0, len(u.Groups)+1)
	for _, g := range u.Groups {
		if c.prefix == "" && strings.HasPrefix(g, reservedGroupPrefix) {
			// Without a prefix the caller's value reaches the review as
			// is, and system:masters is cluster-admin on most clusters.
			return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest,
				"group %q is reserved by Kubernetes; hallpass only sends %s groups it adds itself unless the connection sets group_prefix", g, reservedGroupPrefix)
		}
		groups = append(groups, c.prefix+g)
	}
	if c.addAuth {
		groups = append(groups, "system:authenticated")
	}
	return integration.Identity{ID: name, Display: name, Groups: groups}, nil
}

// attributes is what goes into the review.
type attributes struct {
	namespace, verb, group, resource, name, subresource string
	nonResourcePath                                     string
}

type sarRequest struct {
	APIVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Spec       sarSpec `json:"spec"`
}

type sarSpec struct {
	User                  string                 `json:"user"`
	Groups                []string               `json:"groups,omitempty"`
	ResourceAttributes    *resourceAttributes    `json:"resourceAttributes,omitempty"`
	NonResourceAttributes *nonResourceAttributes `json:"nonResourceAttributes,omitempty"`
}

type resourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb"`
	Group       string `json:"group,omitempty"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

type nonResourceAttributes struct {
	Path string `json:"path"`
	Verb string `json:"verb"`
}

type sarResponse struct {
	Status struct {
		Allowed         bool   `json:"allowed"`
		Denied          bool   `json:"denied"`
		Reason          string `json:"reason"`
		EvaluationError string `json:"evaluationError"`
	} `json:"status"`
}

// Check posts one SubjectAccessReview.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	attrs, err := buildAttributes(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	req := sarRequest{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"}
	req.Spec.User = r.Identity.ID
	req.Spec.Groups = r.Identity.Groups
	if attrs.nonResourcePath != "" {
		req.Spec.NonResourceAttributes = &nonResourceAttributes{Path: attrs.nonResourcePath, Verb: attrs.verb}
	} else {
		req.Spec.ResourceAttributes = &resourceAttributes{
			Namespace: attrs.namespace, Verb: attrs.verb, Group: attrs.group,
			Resource: attrs.resource, Subresource: attrs.subresource, Name: attrs.name,
		}
	}
	var out sarResponse
	_, err = c.client.PostJSON(ctx, "/apis/authorization.k8s.io/v1/subjectaccessreviews", req, &out, true)
	if err != nil {
		if httpx.Status(err) == 403 {
			return integration.Decision{}, integration.Wrap(integration.CodeCredentialRejected, err,
				"hallpass's ServiceAccount may not create subjectaccessreviews (HTTP 403)")
		}
		return integration.Decision{}, httpx.Classify(err)
	}
	what := describe(attrs)
	switch {
	case out.Status.Allowed:
		return integration.Allowed("%s may %s%s", r.Identity.ID, what, suffix(out.Status.Reason)), nil
	case out.Status.EvaluationError != "":
		return integration.Unsupported("the API server could not evaluate %s: %s", what, out.Status.EvaluationError), nil
	default:
		return integration.Denied("%s may not %s%s", r.Identity.ID, what, suffix(out.Status.Reason)), nil
	}
}

func suffix(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	if len(reason) > 200 {
		reason = reason[:200] + "..."
	}
	return " (" + reason + ")"
}

func describe(a attributes) string {
	if a.nonResourcePath != "" {
		return a.verb + " " + a.nonResourcePath
	}
	res := a.resource
	if a.group != "" {
		res += "." + a.group
	}
	if a.subresource != "" {
		res += "/" + a.subresource
	}
	s := a.verb + " " + res
	if a.name != "" {
		s += " " + a.name
	}
	if a.namespace != "" {
		s += " in namespace " + a.namespace
	}
	return s
}

// Probe posts a review for a throwaway subject. Any 201 proves the token is
// valid and may create reviews. It reveals nothing about real users.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	req := sarRequest{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"}
	req.Spec.User = "hallpass:probe"
	req.Spec.ResourceAttributes = &resourceAttributes{Verb: "get", Resource: "namespaces", Name: "default"}
	var out sarResponse
	_, err := c.client.PostJSON(ctx, "/apis/authorization.k8s.io/v1/subjectaccessreviews", req, &out, true)
	if err != nil {
		if httpx.Status(err) == 403 {
			return integration.ProbeResult{}, errors.New("the token is valid but may not create subjectaccessreviews.authorization.k8s.io; grant a ClusterRole with that one rule")
		}
		return integration.ProbeResult{}, httpx.Classify(err)
	}
	res := integration.ProbeResult{Summary: "can create SubjectAccessReviews"}
	if out.Status.Allowed {
		res.Warnings = append(res.Warnings, "the cluster lets an unknown user read namespaces; check that authorization is enabled")
	}
	res.Warnings = append(res.Warnings, c.extraRules(ctx)...)
	return res, nil
}

// selfRulesReview is the part of a SelfSubjectRulesReview the probe reads.
type selfRulesReview struct {
	Status struct {
		ResourceRules []struct {
			Verbs         []string `json:"verbs"`
			APIGroups     []string `json:"apiGroups"`
			Resources     []string `json:"resources"`
			ResourceNames []string `json:"resourceNames"`
		} `json:"resourceRules"`
		Incomplete      bool   `json:"incomplete"`
		EvaluationError string `json:"evaluationError"`
	} `json:"status"`
}

// extraRules asks the API server what hallpass's own token may do (any
// authenticated subject may create a SelfSubjectRulesReview) and warns
// about anything beyond creating SubjectAccessReviews. Rules every
// authenticated user has (self reviews, discovery) are ignored.
func (c *Connection) extraRules(ctx context.Context) []string {
	req := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectRulesReview",
		"spec":       map[string]any{"namespace": "kube-system"},
	}
	var out selfRulesReview
	if _, err := c.client.PostJSON(ctx, "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", req, &out, true); err != nil {
		return []string{"could not list the token's own permissions (SelfSubjectRulesReview failed); check for over-privilege by hand"}
	}
	var extra []string
	for _, r := range out.Status.ResourceRules {
		if allSelfReview(r.Resources) {
			continue
		}
		if len(r.Resources) == 1 && r.Resources[0] == "subjectaccessreviews" && len(r.Verbs) == 1 && r.Verbs[0] == "create" {
			continue
		}
		extra = append(extra, strings.Join(r.Verbs, ",")+" "+strings.Join(r.Resources, ",")+groupSuffix(r.APIGroups))
	}
	if len(extra) == 0 {
		return nil
	}
	if len(extra) > 8 {
		extra = append(extra[:8], fmt.Sprintf("and %d more", len(extra)-8))
	}
	return []string{"the token can do more than create SubjectAccessReviews (in kube-system): " + strings.Join(extra, "; ") + ". Bind only the hallpass ClusterRole to it"}
}

func allSelfReview(resources []string) bool {
	if len(resources) == 0 {
		return false
	}
	for _, r := range resources {
		if r != "selfsubjectaccessreviews" && r != "selfsubjectrulesreviews" && r != "selfsubjectreviews" {
			return false
		}
	}
	return true
}

func groupSuffix(groups []string) string {
	if len(groups) == 0 || (len(groups) == 1 && groups[0] == "") {
		return ""
	}
	return "." + strings.Join(groups, ",")
}
