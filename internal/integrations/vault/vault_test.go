package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const (
	accOIDC = "auth_oidc_1a2b3c4d"
	accTok  = "auth_token_0000aaaa"

	entDana = "e1000000-0000-4000-8000-000000000001" // dev policy, group team, metadata team=payments
	entBob  = "e1000000-0000-4000-8000-000000000002" // default only
	entRoot = "e1000000-0000-4000-8000-000000000003" // root
	entOps  = "e1000000-0000-4000-8000-000000000004" // ops
	entOff  = "e1000000-0000-4000-8000-000000000005" // disabled
	grpTeam = "g1000000-0000-4000-8000-000000000001" // team-readers
	grpExt  = "g1000000-0000-4000-8000-000000000002" // external group, policy missing in Vault
)

var (
	dana = integration.User{Email: "dana@example.com"}
	bob  = integration.User{Email: "bob@example.com"}
	root = integration.User{Email: "root@example.com"}
	ops  = integration.User{Email: "ops@example.com"}
)

const devPolicy = `
# Developers: their own space, shared configs, their team's space.
path "secret/data/dev/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/dev/*" { capabilities = ["list", "read", "delete"] }
path "secret/destroy/dev/*" { capabilities = ["update"] }
path "secret/data/dev/locked" {
  capabilities = ["deny"]
}
path "secret/data/shared/+/config" {
  capabilities = ["read"]
}
path "secret/data/teams/{{identity.entity.metadata.team}}/*" {
  capabilities = ["read", "create", "update"]
}
path "secret/data/x/{{identity.entity.metadata.missing}}/*" {
  capabilities = ["deny"]
}
path "kv1/legacy/*" {
  policy = "read"
}
path "secret/data/dev/params" {
  capabilities = ["create", "update"]
  allowed_parameters = {
    "key" = []
  }
}
path "secret/data/dev/wrapped" {
  capabilities = ["read"]
  min_wrapping_ttl = "1s"
}
path "secret/data/dev/half" { capabilities = ["update"] }
path "team/secrets/data/*" { capabilities = ["read"] }
`

const teamPolicy = `{"path": {"secret/data/shared/*": {"capabilities": ["read", "list"]}, "secret/metadata/shared/*": {"capabilities": ["list"]}}}`

const opsPolicy = `
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "secret/data/prod/*" { capabilities = ["deny"] }
path "sys/*" { capabilities = ["sudo", "read"] }
path "pki/issue/web" { capabilities = ["update"] }
`

const defaultPolicy = `
path "auth/token/lookup-self" { capabilities = ["read"] }
path "sys/capabilities-self" { capabilities = ["update"] }
`

type fakeEntity struct {
	id, name, email string
	disabled        bool
	policies        []string
	groups          []string
	metadata        map[string]string
}

type fake struct {
	t  *testing.T
	mu sync.Mutex

	token, roleID, secretID string
	entities                []fakeEntity
	groups                  map[string]map[string]any
	policies                map[string]string
	mounts                  map[string]map[string]any
	logins, policyReads     int
	status                  int
	forbidden               map[string]bool
}

func newFake(t *testing.T) *fake {
	return &fake{t: t, token: itest.Canary + "tok", roleID: "r0le-id", secretID: itest.Canary + "sid",
		entities: []fakeEntity{
			{entDana, "dana", "dana@example.com", false, []string{"dev"}, []string{grpTeam, grpExt}, map[string]string{"team": "payments", "note": itest.Canary}},
			{entBob, "bob", "bob@example.com", false, nil, nil, nil},
			{entRoot, "rooty", "root@example.com", false, []string{"root"}, nil, nil},
			{entOps, "ops", "ops@example.com", false, []string{"ops"}, nil, nil},
			{entOff, "off", "off@example.com", true, []string{"dev"}, nil, nil},
		},
		groups: map[string]map[string]any{
			grpTeam: {"id": grpTeam, "name": "team", "type": "internal", "policies": []string{"team-readers"}, "metadata": map[string]string{"x": itest.Canary}},
			grpExt:  {"id": grpExt, "name": "ext", "type": "external", "policies": []string{"gone-policy"}},
		},
		policies: map[string]string{"dev": devPolicy, "team-readers": teamPolicy, "ops": opsPolicy, "default": defaultPolicy, "root": ""},
		mounts: map[string]map[string]any{
			"secret/":       {"type": "kv", "options": map[string]any{"version": "2"}, "description": itest.Canary},
			"kv1/":          {"type": "kv", "options": map[string]any{"version": "1"}},
			"team/secrets/": {"type": "kv", "options": map[string]any{"version": "2"}},
			"pki/":          {"type": "pki", "options": nil},
		},
		forbidden: map[string]bool{},
	}
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func vaultErr(w http.ResponseWriter, status int, msg string) {
	write(w, status, map[string]any{"errors": []string{msg + " " + itest.Canary}})
}

func wrap(data any) map[string]any {
	return map[string]any{"request_id": "r", "lease_id": "", "renewable": false, "lease_duration": 0, "data": data, "wrap_info": nil, "warnings": nil, "auth": nil}
}

func (f *fake) api(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v1")
	if p == "/auth/approle/login" {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] != f.roleID || body["secret_id"] != f.secretID {
			vaultErr(w, 400, "invalid role or secret ID")
			return
		}
		f.logins++
		write(w, 200, map[string]any{"auth": map[string]any{"client_token": f.token, "lease_duration": 3600, "renewable": true, "policies": []string{"hallpass"}}})
		return
	}
	if r.Header.Get("X-Vault-Token") != f.token {
		vaultErr(w, 403, "permission denied")
		return
	}
	if f.status != 0 {
		vaultErr(w, f.status, "boom")
		return
	}
	if f.forbidden[p] {
		vaultErr(w, 403, "1 error occurred: permission denied")
		return
	}
	switch {
	case p == "/sys/auth":
		write(w, 200, wrap(map[string]any{
			"oidc/":  map[string]any{"accessor": accOIDC, "type": "oidc", "description": itest.Canary, "config": map[string]any{"default_lease_ttl": 0}},
			"token/": map[string]any{"accessor": accTok, "type": "token"},
		}))
	case p == "/sys/mounts":
		out := map[string]any{}
		for k, v := range f.mounts {
			out[k] = v
		}
		write(w, 200, wrap(out))
	case p == "/identity/lookup/entity":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["alias_mount_accessor"] != accOIDC {
			f.t.Errorf("lookup with accessor %q", body["alias_mount_accessor"])
		}
		for _, e := range f.entities {
			if strings.EqualFold(e.email, body["alias_name"]) {
				write(w, 200, wrap(map[string]any{"id": e.id, "name": e.name, "policies": e.policies, "aliases": []any{}, "metadata": e.metadata, "group_ids": e.groups}))
				return
			}
		}
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/identity/entity/id/"):
		id := strings.TrimPrefix(p, "/identity/entity/id/")
		for _, e := range f.entities {
			if e.id == id {
				var direct, inherited []string
				for i, g := range e.groups {
					if i == 0 {
						direct = append(direct, g)
					} else {
						inherited = append(inherited, g)
					}
				}
				write(w, 200, wrap(map[string]any{
					"id": e.id, "name": e.name, "disabled": e.disabled, "policies": e.policies, "metadata": e.metadata,
					"group_ids": e.groups, "direct_group_ids": direct, "inherited_group_ids": inherited,
					"aliases": []map[string]any{{"id": "alias-" + e.id, "name": e.email, "mount_accessor": accOIDC, "mount_path": "auth/oidc/", "mount_type": "oidc", "metadata": map[string]string{"role": "dev"}}},
				}))
				return
			}
		}
		vaultErr(w, 404, "")
	case strings.HasPrefix(p, "/identity/group/id/"):
		g, ok := f.groups[strings.TrimPrefix(p, "/identity/group/id/")]
		if !ok {
			vaultErr(w, 404, "")
			return
		}
		write(w, 200, wrap(g))
	case strings.HasPrefix(p, "/sys/policies/acl/"):
		name := strings.TrimPrefix(p, "/sys/policies/acl/")
		text, ok := f.policies[name]
		if !ok {
			vaultErr(w, 404, "")
			return
		}
		f.policyReads++
		write(w, 200, wrap(map[string]any{"name": name, "policy": text}))
	case p == "/auth/token/lookup-self":
		write(w, 200, wrap(map[string]any{"display_name": "approle-hallpass", "policies": []string{"default", "hallpass"}, "entity_id": "", "meta": map[string]string{"x": itest.Canary}}))
	default:
		f.t.Errorf("fake: no route for %s %s", r.Method, p)
		vaultErr(w, 404, "")
	}
}

func newServer(t *testing.T) (*itest.Server, *fake) {
	t.Helper()
	srv := itest.NewServer(t)
	srv.UseSpec(itest.SpecFromEnv(t, "vault"), itest.SpecOptions{StripPrefix: []string{`/v1`}})
	f := newFake(t)
	srv.Handle("", "/v1/*", f.api)
	return srv, f
}

func setupValues(t *testing.T, values map[string]string, cred string) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	srv, f := newServer(t)
	deps, _ := itest.Deps(t, srv)
	base := map[string]string{"url": srv.URL, "alias_mount": "oidc/"}
	for k, v := range values {
		base[k] = v
	}
	if cred == "" {
		cred = f.token
	}
	s := itest.Settings("vault", "vault", base, map[string]secret.Secret{"credential": secret.Literal(cred)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

func setup(t *testing.T) (*itest.Server, *fake, integration.Connection) {
	t.Helper()
	return setupValues(t, nil, "")
}

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

func expect(t *testing.T, d integration.Decision, code integration.Code, text string) {
	t.Helper()
	itest.ExpectCode(t, d, code)
	if text != "" && !strings.Contains(d.Text, text) {
		t.Errorf("text %q does not contain %q", d.Text, text)
	}
	itest.AssertNoCanary(t, d.Text)
}

// --- the action table -------------------------------------------------------

func TestAction_secret_read_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeAllowed, `policy dev grants read on "secret/data/dev/*", covering secret/data/dev/app`)
	// A group's policy.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/shared/db"), integration.CodeAllowed, "team-readers")
	// + spans one segment; the more specific pattern wins over shared/*.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/shared/a/config"), integration.CodeAllowed, `"secret/data/shared/+/config"`)
	// A template resolved from entity metadata.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/teams/payments/db"), integration.CodeAllowed, "secret/data/teams/payments/*")
	// KV v1 keeps the logical path; the legacy policy attribute maps to read.
	expect(t, check(t, c, dana, "secret.read", "kv:kv1/legacy/x"), integration.CodeAllowed, `"kv1/legacy/*", covering kv1/legacy/x`)
	// root is not evaluated: Vault refuses it next to other policies.
	expect(t, check(t, c, root, "secret.read", "kv:secret/prod/db"), integration.CodeUnsupported, "root policy")
	// path: takes the API path as is.
	expect(t, check(t, c, ops, "secret.read", "path:secret/data/dev/x"), integration.CodeAllowed, "ops")
	// A mount spanning two segments.
	expect(t, check(t, c, dana, "secret.read", "kv:team/secrets/app"), integration.CodeAllowed, "team/secrets/data/*")
}
func TestAction_secret_read_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, bob, "secret.read", "kv:secret/dev/app"), integration.CodeDenied, "no path in bob@example.com's policies (default) matches secret/data/dev/app")
	// An explicit deny on the exact path beats the glob.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/locked"), integration.CodeDenied, `policy path "secret/data/dev/locked" denies`)
	// ops: secret/* grants, secret/data/prod/* denies and is more specific.
	expect(t, check(t, c, ops, "secret.read", "kv:secret/prod/db"), integration.CodeDenied, "denies")
	// The template resolves to another team.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/teams/other/db"), integration.CodeDenied, "")
	// shared/+/config grants read only; a deeper path falls to shared/*, read+list.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/shared/a/b/config"), integration.CodeAllowed, "")
}
func TestAction_secret_write_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.write", "kv:secret/dev/app"), integration.CodeAllowed, "create+update")
	expect(t, check(t, c, dana, "secret.write", "kv:secret/teams/payments/x"), integration.CodeAllowed, "")
}
func TestAction_secret_write_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.write", "kv:secret/shared/a/config"), integration.CodeDenied, "grants neither create nor update")
	expect(t, check(t, c, dana, "secret.write", "kv:kv1/legacy/x"), integration.CodeDenied, "")
	expect(t, check(t, c, bob, "secret.write", "kv:secret/dev/app"), integration.CodeDenied, "")
}
func TestWriteHalfGranted(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.write", "kv:secret/dev/half"), integration.CodeUnsupported, "grants update but not create, so the write succeeds only if the secret already exists")
}
func TestAction_secret_delete_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.delete", "kv:secret/dev/app"), integration.CodeAllowed, "delete")
}
func TestAction_secret_delete_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.delete", "kv:secret/shared/db"), integration.CodeDenied, "grants list, read but not delete")
}
func TestAction_secret_list_allow(t *testing.T) {
	_, _, c := setup(t)
	// LIST is matched as a prefix: secret/metadata/dev/ against secret/metadata/dev/*.
	expect(t, check(t, c, dana, "secret.list", "kv:secret/dev"), integration.CodeAllowed, `"secret/metadata/dev/*", covering secret/metadata/dev`)
	expect(t, check(t, c, dana, "secret.list", "kv:secret/shared/a"), integration.CodeAllowed, "team-readers")
}
func TestAction_secret_list_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.list", "kv:secret/teams/payments"), integration.CodeDenied, "")
	expect(t, check(t, c, bob, "secret.list", "kv:secret/dev"), integration.CodeDenied, "")
}
func TestAction_secret_metadata_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.metadata", "kv:secret/dev/app"), integration.CodeAllowed, "secret/metadata/dev/*")
}
func TestAction_secret_metadata_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.metadata", "kv:secret/shared/db"), integration.CodeDenied, "")
	expect(t, check(t, c, dana, "secret.metadata", "kv:kv1/legacy/x"), integration.CodeUnsupported, "KV v1 mount")
}
func TestAction_secret_destroy_allow(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.destroy", "kv:secret/dev/app"), integration.CodeAllowed, "secret/destroy/dev/*")
}
func TestAction_secret_destroy_deny(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, dana, "secret.destroy", "kv:secret/shared/db"), integration.CodeDenied, "")
}

func TestRawCapabilities(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, ops, "raw:sudo", "path:sys/seal"), integration.CodeAllowed, `"sys/*"`)
	expect(t, check(t, c, ops, "raw:update", "path:pki/issue/web"), integration.CodeAllowed, "")
	expect(t, check(t, c, dana, "raw:sudo", "path:sys/seal"), integration.CodeDenied, "")
	expect(t, check(t, c, ops, "raw:delete", "path:pki/issue/web"), integration.CodeDenied, "grants update but not delete")
	// LIST with raw is a prefix match too.
	expect(t, check(t, c, dana, "raw:list", "path:secret/metadata/dev"), integration.CodeAllowed, "")
	expect(t, check(t, c, bob, "raw:read", "path:auth/token/lookup-self"), integration.CodeAllowed, "default")
}

func TestUnknowns(t *testing.T) {
	_, _, c := setup(t)
	// A parameter constraint on a write.
	expect(t, check(t, c, dana, "secret.write", "kv:secret/dev/params"), integration.CodeUnsupported, "request parameters")
	// A wrapping requirement.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/wrapped"), integration.CodeUnsupported, "response wrapping")
	// A template that does not resolve, on a deny stanza that could match.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/x/anything/z"), integration.CodeUnsupported, "template hallpass could not resolve")
	// A mount that is not KV.
	expect(t, check(t, c, ops, "secret.read", "kv:pki/issue/web"), integration.CodeUnsupported, "not kv")
	// A mount that does not exist, and a mount without a key.
	expect(t, check(t, c, ops, "secret.read", "kv:nope/x"), integration.CodeResourceNotVisible, "no secrets engine")
	expect(t, check(t, c, ops, "secret.read", "kv:team/secrets"), integration.CodeResourceNotVisible, "")
}

func TestUnresolvedTemplateOutsideWinner(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	// Rendered by Vault this may become secret/data/dev/* and add a deny.
	f.policies["dev"] = devPolicy + `
path "secret/data/{{identity.groups.names.team.metadata.region}}/*" { capabilities = ["deny"] }
`
	f.mu.Unlock()
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeUnsupported, "template hallpass could not resolve")
}

func TestListDenyWithoutSlash(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.policies["dev"] = `
path "secret/metadata/*" { capabilities = ["list"] }
path "secret/metadata/prod" { capabilities = ["deny"] }
path "secret/metadata/+" { capabilities = ["deny"] }
path "secret/metadata/dev/*" { capabilities = ["list"] }
`
	f.mu.Unlock()
	// The exact deny is written without the trailing slash Vault adds.
	expect(t, check(t, c, dana, "secret.list", "kv:secret/prod"), integration.CodeDenied, "denies")
	// A + rule matches the slash-less form too.
	expect(t, check(t, c, dana, "secret.list", "kv:secret/other"), integration.CodeDenied, "denies")
	expect(t, check(t, c, dana, "secret.list", "kv:secret/dev/a"), integration.CodeAllowed, "")
}

func TestLeadingSlashInStanza(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.policies["dev"] = `
path "secret/*" { capabilities = ["read"] }
path "/secret/data/prod/*" { capabilities = ["deny"] }
`
	f.mu.Unlock()
	expect(t, check(t, c, dana, "secret.read", "kv:secret/prod/db"), integration.CodeDenied, "denies")
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/db"), integration.CodeAllowed, "")
}

func TestTemplateValueWithSlash(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.policies["dev"] = `
path "secret/*" { capabilities = ["read"] }
path "secret/data/{{identity.entity.metadata.scope}}" { capabilities = ["deny"] }
`
	for i := range f.entities {
		if f.entities[i].id == entDana {
			f.entities[i].metadata = map[string]string{"scope": "a/b"}
		}
	}
	f.mu.Unlock()
	// Rendered, the deny is secret/data/a/b; a value with a slash cannot
	// be placed, so anything under secret/data/ is unknown.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/a/b"), integration.CodeUnsupported, "template")
	expect(t, check(t, c, dana, "secret.read", "kv:secret/zzz"), integration.CodeUnsupported, "template")
	expect(t, check(t, c, dana, "raw:read", "path:secret/other"), integration.CodeAllowed, "")
}

func TestParametersOnRead(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.policies["dev"] = `path "secret/data/dev/*" { capabilities = ["read"] required_parameters = ["version"] }`
	f.mu.Unlock()
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeUnsupported, "request parameters")
}

func TestControlGroupBlocksParse(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.policies["dev"] = `
path "secret/data/dev/*" {
  capabilities = ["read"]
  control_group = {
    factor "managers" {
      identity {
        group_names = ["managers"]
        approvals = 1
      }
    }
  }
}`
	f.mu.Unlock()
	// The control group itself is not modelled; the stanza still parses
	// and grants read.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeAllowed, "")
}

func TestPolicySyntaxUnknown(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.policies["dev"] = `path "secret/*" { capabilities = <<EOF
read
EOF
}`
	f.mu.Unlock()
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeUnsupported, "syntax hallpass does not parse")
}

func TestTokenPolicies(t *testing.T) {
	_, _, c := setupValues(t, map[string]string{"token_policies": "ops, default"}, "")
	// bob has nothing on the entity, but every login through oidc/ gets ops.
	expect(t, check(t, c, bob, "secret.read", "kv:secret/dev/app"), integration.CodeAllowed, "ops")
}

func TestPriorityRules(t *testing.T) {
	for _, tc := range []struct {
		low, high string
	}{
		{"secret/*", "secret/data/*"},             // earlier glob is lower
		{"secret/+/+/foo/*", "secret/*"},          // rules 1 and 2 tie; more + segments is lower
		{"secret/data/*", "secret/data/foo"},      // glob is lower than exact
		{"secret/data/foo", "secret/data/foobar"}, // shorter is lower
		{"secret/data/abc", "secret/data/abd"},    // lexicographic
		{"secret/+/config", "secret/data/config"}, // wildcard earlier is lower
		{"secret/data/+/+", "secret/data/+/x"},    // more + is lower
	} {
		if !lessPriority(tc.low, tc.high) || lessPriority(tc.high, tc.low) {
			t.Errorf("%q should be lower priority than %q", tc.low, tc.high)
		}
	}
	// The documented example: secret/* and secret/+/+/foo/* tie on rules 1
	// and 2 and end at rule 3, which gives secret/+/+/foo/* lower priority.
	if !lessPriority("secret/+/+/foo/*", "secret/*") {
		t.Error("secret/+/+/foo/* should be lower than secret/*")
	}
}

func TestMatchPattern(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"secret/*", "secret/data/foo", true},
		{"secret/*", "secret/", true},
		{"secret/*", "secrets/x", false},
		{"secret/data/foo", "secret/data/foo", true},
		{"secret/data/foo", "secret/data/foobar", false},
		{"secret/+/foo", "secret/a/foo", true},
		{"secret/+/foo", "secret/a/b/foo", false},
		{"secret/+/foo", "secret//foo", true},
		{"secret/ab+/foo", "secret/abc/foo", false}, // + is a wildcard only as a whole segment
		{"secret/ab+/foo", "secret/ab+/foo", true},
		{"secret/+", "secret/a", true},
		{"secret/+", "secret", false},
		{"*", "anything/at/all", true},
		{"secret/+/+/foo/*", "secret/a/b/foo/bar", true},
		{"secret/+/+/foo/*", "secret/a/foo/bar", false},
		{"a*b", "axb", false}, // * only globs at the end; elsewhere it is literal
		{"a*b", "a*b", true},
		{"sys/*", "sys/seal", true},
	} {
		if got := matchPattern(tc.pattern, tc.path); got != tc.want {
			t.Errorf("match(%q, %q) = %v", tc.pattern, tc.path, got)
		}
	}
}

// --- identity ---------------------------------------------------------------

func TestIdentity(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: "nobody@example.com"}, "secret.read", "kv:secret/dev/app"), integration.CodeUserNotFound, "no Vault entity has an alias")
	expect(t, check(t, c, integration.User{Email: "off@example.com"}, "secret.read", "kv:secret/dev/app"), integration.CodeDenied, "disabled")
	expect(t, check(t, c, integration.User{Email: "not an email"}, "secret.read", "kv:secret/dev/app"), integration.CodeInvalidRequest, "")
}

func TestIdentityAttrs(t *testing.T) {
	_, _, c := setup(t)
	id, err := c.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != entDana || id.Attr("entity_name") != "dana" || id.Attr("policies") != "dev,gone-policy,team-readers" || id.Attr("meta:team") != "payments" || id.Attr("group:"+grpTeam) != "team" || id.Attr("alias:"+accOIDC+":name") != "dana@example.com" {
		t.Errorf("identity %+v", id)
	}
	if len(id.Groups) != 2 {
		t.Errorf("groups %v", id.Groups)
	}
	// Metadata values are the operator's, not secrets; the canary sits in
	// fields hallpass does not copy.
	for k, v := range id.Attrs {
		if k != "meta:note" {
			itest.AssertNoCanary(t, k+"="+v)
		}
	}
}

func TestCallerGroupsIgnored(t *testing.T) {
	_, _, c := setup(t)
	expect(t, check(t, c, integration.User{Email: "bob@example.com", Groups: []string{grpTeam, "team"}}, "secret.read", "kv:secret/shared/db"), integration.CodeDenied, "")
}

func TestMissingPolicyIsSkipped(t *testing.T) {
	srv, _, c := setup(t)
	// dana's external group names gone-policy, which Vault does not have.
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeAllowed, "")
	seen := false
	for _, call := range srv.Calls() {
		if strings.HasSuffix(call.Path, "/sys/policies/acl/gone-policy") {
			seen = true
		}
	}
	if !seen {
		t.Error("the missing policy was not read")
	}
}

func TestPoliciesAreCached(t *testing.T) {
	_, f, c := setup(t)
	check(t, c, dana, "secret.read", "kv:secret/dev/app")
	check(t, c, dana, "secret.write", "kv:secret/dev/app")
	f.mu.Lock()
	defer f.mu.Unlock()
	// dev, team-readers, default read once each; gone-policy is 404.
	if f.policyReads != 3 {
		t.Errorf("policies read %d times, want 3", f.policyReads)
	}
}

func TestWrongAliasMount(t *testing.T) {
	_, _, c := setupValues(t, map[string]string{"alias_mount": "ldap/"}, "")
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeInvalidRequest, "not an enabled auth method")
}

func TestForbidden(t *testing.T) {
	_, f, c := setup(t)
	f.mu.Lock()
	f.forbidden["/sys/policies/acl/dev"] = true
	f.mu.Unlock()
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeCredentialRejected, "permission denied")
	_, _, c = setupValues(t, nil, "wrong")
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeCredentialRejected, "")
}

func TestAppRole(t *testing.T) {
	srv, f, c := setupValues(t, map[string]string{"auth_mode": "approle", "role_id": "r0le-id"}, itest.Canary+"sid")
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeAllowed, "")
	expect(t, check(t, c, ops, "secret.read", "kv:secret/dev/app"), integration.CodeAllowed, "")
	f.mu.Lock()
	logins := f.logins
	f.mu.Unlock()
	if logins != 1 {
		t.Errorf("%d logins, want 1 (token cached)", logins)
	}
	for _, call := range srv.Calls() {
		if strings.HasSuffix(call.Path, "/login") && !strings.Contains(string(call.Body), `"role_id":"r0le-id"`) {
			t.Errorf("login body %s", call.Body)
		}
	}
	// A revoked token: one re-login, then success.
	f.mu.Lock()
	f.token = itest.Canary + "tok2"
	f.mu.Unlock()
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeAllowed, "")
	// A path hallpass may not read: at most one re-login per token, not
	// one per denied request.
	f.mu.Lock()
	f.forbidden["/identity/lookup/entity"] = true // never cached
	before := f.logins
	f.mu.Unlock()
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeCredentialRejected, "")
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeCredentialRejected, "")
	f.mu.Lock()
	extra := f.logins - before
	f.mu.Unlock()
	if extra > 1 {
		t.Errorf("%d re-logins for a permission denial, want at most 1", extra)
	}
	// A wrong secret id.
	_, _, c = setupValues(t, map[string]string{"auth_mode": "approle", "role_id": "r0le-id"}, "bad")
	expect(t, check(t, c, dana, "secret.read", "kv:secret/dev/app"), integration.CodeCredentialRejected, "AppRole login")
}

func TestNamespaceHeader(t *testing.T) {
	srv, _, c := setupValues(t, map[string]string{"namespace": "admin/team"}, "")
	check(t, c, dana, "secret.read", "kv:secret/dev/app")
	for _, call := range srv.Calls() {
		if call.Header.Get("X-Vault-Namespace") != "admin/team" {
			t.Errorf("%s without namespace header", call.Path)
		}
	}
}

func TestInvalidRequests(t *testing.T) {
	_, _, c := setup(t)
	for _, tc := range [][2]string{
		{"secret.read", "kv:secret"}, {"secret.read", "kv:secret/"}, {"secret.read", "kv:secret/a b"},
		{"secret.read", "kv:secret/*"}, {"secret.read", "kv:secret/+/x"}, {"secret.read", "kv:secret/../x"},
		{"secret.read", "kv:secret/./x"}, {"secret.read", "kv:secret/x?v=1"}, {"secret.read", "path:"},
		{"secret.read", "mount:x"}, {"secret.destroy", "path:secret/destroy/x"}, {"secret.metadata", "path:secret/metadata/x"},
		{"raw:read", "kv:secret/x"}, {"secret.read", "kv:secret//x"},
	} {
		d := check(t, c, dana, tc[0], tc[1])
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s: %s %s", tc[0], tc[1], d.Code, d.Text)
		}
	}
	for _, bad := range []string{"raw:deny", "raw:root", "raw:READ", "raw:"} {
		if _, ok := (Integration{}).MatchAction(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t)
	itest.FailureCases(t, srv, func() integration.Decision { return check(t, c, dana, "secret.read", "kv:secret/dev/app") })
}

func TestNewValidation(t *testing.T) {
	srv := itest.NewServer(t)
	deps, _ := itest.Deps(t, srv)
	for _, tc := range []struct {
		values map[string]string
		secret bool
	}{
		{map[string]string{"url": srv.URL, "alias_mount": "oidc/"}, false},
		{map[string]string{"alias_mount": "oidc/"}, true},
		{map[string]string{"url": srv.URL}, true},
		{map[string]string{"url": srv.URL, "alias_mount": "oidc/", "auth_mode": "approle"}, true},
		{map[string]string{"url": srv.URL, "alias_mount": "oidc/", "auth_mode": "magic"}, true},
		{map[string]string{"url": srv.URL, "alias_mount": "oidc/", "token_policies": "a b"}, true},
		{map[string]string{"url": srv.URL, "alias_mount": "oidc/", "token_policies": "root"}, true},
		{map[string]string{"url": srv.URL, "alias_mount": "oidc/", "namespace": "a b"}, true},
	} {
		secrets := map[string]secret.Secret{}
		if tc.secret {
			secrets["credential"] = secret.Literal("x")
		}
		if _, err := (Integration{}).New(context.Background(), itest.Settings("vault", "vault", tc.values, secrets), deps); err == nil {
			t.Errorf("New(%v, secret=%v) accepted", tc.values, tc.secret)
		}
	}
}

func TestProbe(t *testing.T) {
	_, _, c := setup(t)
	res, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "approle-hallpass") || !strings.Contains(res.Summary, accOIDC) || len(res.Warnings) != 2 {
		t.Errorf("probe %+v", res)
	}
	itest.AssertNoCanary(t, res.Summary)
	_, _, c = setupValues(t, nil, "wrong")
	var ie *integration.Error
	if _, err := c.Probe(context.Background()); !errors.As(err, &ie) || ie.Code != integration.CodeCredentialRejected {
		t.Errorf("bad token: %v", err)
	}
}

func TestNoSecretInLogs(t *testing.T) {
	srv, f := newServer(t)
	deps, logs := itest.Deps(t, srv)
	s := itest.Settings("vault", "vault", map[string]string{"url": srv.URL, "alias_mount": "oidc/"}, map[string]secret.Secret{"credential": secret.Literal(f.token)})
	c, err := (Integration{}).New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	check(t, c, dana, "secret.read", "kv:secret/dev/app")
	check(t, c, dana, "secret.read", "kv:nope/x")
	itest.AssertNoCanary(t, logs.String())
	_ = fmt.Sprint
}
