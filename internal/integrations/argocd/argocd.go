// Package argocd evaluates Argo CD RBAC locally.
//
// Argo CD has no API to ask "may user X do Y" for another user, so hallpass
// reads the policy (argocd-rbac-cm, argocd-cm and AppProjects) through a
// kubernetes connection and evaluates it with the same rules as the Argo CD
// API server (see the rbac subpackage).
package argocd

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integrations/argocd/rbac"
	"github.com/roee-hersh/hallpass/internal/integrations/kubernetes"
)

// Integration is the argocd product.
type Integration struct{}

// Name is "argocd".
func (Integration) Name() string { return "argocd" }

// Fields of an argocd connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.ConnectionRefField("kubernetes_connection", "kubernetes", true,
			"the kubernetes connection whose ServiceAccount may read Argo CD's config maps and AppProjects"),
		{Name: "namespace", Default: "argocd", Validate: validateName, Description: "namespace Argo CD is installed in"},
		{Name: "rbac_configmap", Default: "argocd-rbac-cm", Validate: validateName, Description: "name of the RBAC config map"},
		{Name: "user_subject", Default: "none", Enum: []string{"none", "email"},
			Description: "what Argo CD sees as the user's subject: none (evaluate groups only) or email"},
	}
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

func validateName(v string) error {
	if !nameRe.MatchString(v) {
		return fmt.Errorf("%q is not a valid Kubernetes name", v)
	}
	return nil
}

// policyCacheTTL is how long a loaded policy bundle is reused.
const policyCacheTTL = 30 * time.Second

// New builds a connection.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	kc, err := d.Connection(s.Get("kubernetes_connection"))
	if err != nil {
		return nil, err
	}
	k8s, ok := kc.(*kubernetes.Connection)
	if !ok {
		return nil, fmt.Errorf("kubernetes_connection %q is not a kubernetes connection", s.Get("kubernetes_connection"))
	}
	c := &Connection{
		k8s:         k8s,
		namespace:   s.Get("namespace"),
		rbacCM:      s.Get("rbac_configmap"),
		userSubject: s.Get("user_subject"),
		now:         d.Now,
		policies:    cache.New[struct{}, *bundle](1),
	}
	c.policies.SetClock(c.now)
	return c, nil
}

// Connection is one Argo CD installation.
type Connection struct {
	k8s         *kubernetes.Connection
	namespace   string
	rbacCM      string
	userSubject string
	now         func() time.Time

	// policies holds the one policy bundle under the empty key.
	policies *cache.TTL[struct{}, *bundle]
}

// bundle is everything read from the cluster, parsed once.
type bundle struct {
	userPolicy   string
	userErr      error // user policy that Argo CD itself would reject
	matchMode    string
	defaultRole  string
	scopes       []string
	projects     map[string]*rbac.Project
	inherit      bool // fine-grained update/delete inherit from update/delete
	rollbackAct  string
	userLevel    bool // policy names users (subjects with "@")
	argocdCMSeen bool

	emu       sync.Mutex
	enforcers map[string]*rbac.Enforcer // per project ("" = none)
}

type configMap struct {
	Data map[string]string `json:"data"`
}

type projectList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Roles []struct {
				Name     string   `json:"name"`
				Policies []string `json:"policies"`
				Groups   []string `json:"groups"`
			} `json:"roles"`
		} `json:"spec"`
	} `json:"items"`
}

// load returns the cached policy bundle or fetches it once, sharing the
// result with concurrent callers (cache.TTL.Do: a fetch runs on a context
// detached from the first caller's cancellation, a panic in it becomes a
// *cache.PanicError for everyone waiting, and its evidence is replayed to
// every check the bundle serves).
func (c *Connection) load(ctx context.Context) (*bundle, error) {
	return c.policies.Do(ctx, struct{}{}, func(ctx context.Context) (*bundle, time.Duration, error) {
		b, err := c.fetch(ctx)
		return b, policyCacheTTL, err
	})
}

func (c *Connection) fetch(ctx context.Context) (*bundle, error) {
	b := &bundle{matchMode: rbac.GlobMatchMode, projects: map[string]*rbac.Project{}, enforcers: map[string]*rbac.Enforcer{}, rollbackAct: rbac.ActionSync}
	ns := httpx.PathEscape(c.namespace)

	var rbacCM configMap
	err := c.k8s.Get(ctx, "/api/v1/namespaces/"+ns+"/configmaps/"+httpx.PathEscape(c.rbacCM), &rbacCM)
	switch {
	case err == nil:
		b.userPolicy = rbac.PolicyCSV(rbacCM.Data)
		if rbacCM.Data[rbac.MatchModeKey] == rbac.RegexMatchMode {
			b.matchMode = rbac.RegexMatchMode
		}
		b.defaultRole = rbacCM.Data[rbac.PolicyDefaultKey]
		b.scopes, err = rbac.ParseScopes(rbacCM.Data[rbac.ScopesKey])
		if err != nil {
			b.userErr = fmt.Errorf("scopes: %w", err)
		}
		if _, err := rbac.ParsePolicy(b.userPolicy); err != nil {
			b.userErr = err
		}
	case errors.Is(err, kubernetes.ErrNotFound):
		// No RBAC config map: builtin policy only, as Argo CD would.
	default:
		return nil, err
	}

	var argocdCM configMap
	err = c.k8s.Get(ctx, "/api/v1/namespaces/"+ns+"/configmaps/argocd-cm", &argocdCM)
	switch {
	case err == nil:
		b.argocdCMSeen = true
		// Default true since v3: update/delete no longer imply update/*, delete/*.
		if v := argocdCM.Data["server.rbac.disableApplicationFineGrainedRBACInheritance"]; v == "false" {
			b.inherit = true
		}
		if v := argocdCM.Data["server.rbac.rollback.enforce.enable"]; v == "true" {
			b.rollbackAct = rbac.ActionRollback
		}
	case errors.Is(err, kubernetes.ErrNotFound):
	default:
		return nil, err
	}

	var projects projectList
	if err := c.k8s.Get(ctx, "/apis/argoproj.io/v1alpha1/namespaces/"+ns+"/appprojects", &projects); err != nil && !errors.Is(err, kubernetes.ErrNotFound) {
		return nil, err
	}
	for _, it := range projects.Items {
		p := &rbac.Project{Name: it.Metadata.Name}
		for _, r := range it.Spec.Roles {
			p.Roles = append(p.Roles, rbac.ProjectRole{Name: r.Name, Policies: r.Policies, Groups: r.Groups})
		}
		b.projects[p.Name] = p
	}

	// userLevel: the policy names users (subjects containing "@") in a way
	// that only the subject claim can reach. With "email" in scopes the
	// email is also a group value, and a group value matches a g line's
	// subject; a p line's subject is never matched through a group unless
	// some g line starts with it (Argo CD's prefilter).
	emailScope := false
	for _, s := range b.scopes {
		if s == "email" {
			emailScope = true
		}
	}
	if pol, err := rbac.ParsePolicy(b.userPolicy); err == nil {
		gSubs := map[string]bool{}
		for _, l := range pol.Links {
			gSubs[l.Sub] = true
			if strings.Contains(l.Sub, "@") && !emailScope {
				b.userLevel = true
			}
		}
		for _, r := range pol.Rules {
			if strings.Contains(r.Sub, "@") && !(emailScope && gSubs[r.Sub]) {
				b.userLevel = true
			}
		}
	}
	return b, nil
}

// enforcer returns the enforcer for a project ("" for none), building it once.
func (b *bundle) enforcer(project string) (*rbac.Enforcer, error) {
	b.emu.Lock()
	defer b.emu.Unlock()
	if e, ok := b.enforcers[project]; ok {
		return e, nil
	}
	if b.userErr != nil {
		return nil, b.userErr
	}
	runtime := ""
	if p := b.projects[project]; p != nil {
		runtime = p.PoliciesString()
	}
	e, err := rbac.NewEnforcer(rbac.Options{Builtin: rbac.BuiltinPolicyCSV, User: b.userPolicy, Runtime: runtime, MatchMode: b.matchMode, DefaultRole: b.defaultRole})
	if err != nil && runtime != "" {
		// Argo CD falls back to the enforcer without the project policy when
		// the project policy is invalid.
		e, err = rbac.NewEnforcer(rbac.Options{Builtin: rbac.BuiltinPolicyCSV, User: b.userPolicy, MatchMode: b.matchMode, DefaultRole: b.defaultRole})
	}
	if err != nil {
		return nil, err
	}
	b.enforcers[project] = e
	return e, nil
}

// ResolveIdentity maps the caller to an Argo CD subject and group values.
func (c *Connection) ResolveIdentity(_ context.Context, u integration.User) (integration.Identity, error) {
	subject := ""
	if c.userSubject == "email" {
		subject = u.Email
	}
	return integration.Identity{ID: subject, Display: u.Email, Groups: append([]string(nil), u.Groups...)}, nil
}

// Check evaluates the request against the loaded policy.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	req, err := buildRequest(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	b, err := c.load(ctx)
	if err != nil {
		return integration.Decision{}, err
	}
	if req.act == actRollback {
		req.act = b.rollbackAct
	}
	project := rbac.ProjectFromRequest(req.res, req.obj)
	if b.projects[project] == nil {
		project = ""
	}
	enf, err := b.enforcer(project)
	if err != nil {
		return integration.Unsupported("Argo CD's %s is not a valid policy and cannot be evaluated: %v", c.rbacCM, err), nil
	}
	groups := r.Identity.Groups
	for _, s := range b.scopes {
		if s == "email" {
			groups = append(append([]string(nil), groups...), r.User.Email)
		}
	}
	subject := r.Identity.ID

	acts := []string{req.act}
	if req.fineGrained && b.inherit {
		// v2 behaviour: the top-level verb is checked first, then the
		// fine-grained one.
		acts = []string{req.topAct, req.act}
	}
	for _, act := range acts {
		if enf.EnforceClaims(subject, groups, req.res, act, req.obj) {
			return integration.Allowed("Argo CD policy allows %s %s on %s for %s", act, req.res, req.obj, who(subject, groups)), nil
		}
	}
	if subject == "" && b.userLevel {
		return integration.Unsupported("no group rule allows %s %s on %s, and the policy has user-level rules that cannot be evaluated with user_subject: none", req.act, req.res, req.obj), nil
	}
	return integration.Denied("Argo CD policy has no rule allowing %s %s on %s for %s", req.act, req.res, req.obj, who(subject, groups)), nil
}

func who(subject string, groups []string) string {
	if subject == "" {
		if len(groups) == 0 {
			return "a user with no groups"
		}
		return "groups " + strings.Join(groups, ", ")
	}
	if len(groups) == 0 {
		return subject
	}
	return subject + " (groups " + strings.Join(groups, ", ") + ")"
}

// Probe reads the policy and reports what it found.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	c.policies.Delete(struct{}{})
	b, err := c.load(ctx)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	res := integration.ProbeResult{}
	lines := 0
	for _, l := range strings.Split(b.userPolicy, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			lines++
		}
	}
	res.Summary = fmt.Sprintf("%d policy lines, %d projects, match mode %s, default role %q", lines, len(b.projects), b.matchMode, b.defaultRole)
	if b.userErr != nil {
		res.Warnings = append(res.Warnings, "the RBAC policy is invalid and every check will answer unknown: "+b.userErr.Error())
	}
	if !b.argocdCMSeen {
		res.Warnings = append(res.Warnings, "argocd-cm was not found; assuming Argo CD v3 defaults (no fine-grained inheritance, rollback checks sync)")
	}
	if c.userSubject == "none" && b.userLevel {
		res.Warnings = append(res.Warnings, "the policy names individual users but user_subject is none; those rules are not evaluated (set user_subject: email if Argo CD's subject claim is the email)")
	}
	return res, nil
}

// Actions of the argocd integration.
func (Integration) Actions() []catalog.Action {
	acts := make([]catalog.Action, 0, len(actionList)+3)
	for _, a := range actionList {
		acts = append(acts, catalog.Action{Name: a.name, Description: a.desc})
	}
	acts = append(acts,
		catalog.Action{Name: "app.action/<group>/<kind>/<action>", Pattern: true, Description: "run a resource action, e.g. app.action/apps/Deployment/restart"},
		catalog.Action{Name: "app.update/<group>/<kind>/<namespace>/<name>", Pattern: true, Description: "update one resource of the application (fine-grained)"},
		catalog.Action{Name: "app.delete/<group>/<kind>/<namespace>/<name>", Pattern: true, Description: "delete one resource of the application (fine-grained)"},
	)
	return acts
}

// MatchAction accepts the three pattern actions.
func (Integration) MatchAction(name string) (catalog.Action, bool) {
	if _, ok := parsePattern(name); !ok {
		return catalog.Action{}, false
	}
	return catalog.Action{Name: name, Pattern: true}, true
}
