package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// token is the fake workspace's bot token: a real-looking prefix carrying the canary.
const token = "xoxb-" + itest.Canary + "x"

// Fixture user ids.
const (
	uFull     = "U0000FULL1"
	uAdmin    = "U0000ADMIN"
	uOwner    = "U0000OWNER"
	uGuest    = "U0000GUEST"
	uUltra    = "U0000ULTRA"
	uDead     = "U0000DEAD1"
	uBot      = "U0000BOT01"
	uInvited  = "U0000INVIT"
	uStranger = "U0000STRNG"
	uGridAdm  = "U0000GRIDA"
	uGridUser = "U0000GRIDU"
)

// Fixture channel ids.
const (
	cPublic   = "C0000PUBLC"
	cGeneral  = "C0000GENRL"
	cRestrict = "C0000RSTRC"
	cArchived = "C0000ARCHV"
	cNoProps  = "C0000NOPRP" // conversations.info returns no properties object
	gPrivate  = "G0000PRIVT"
	gHidden   = "G0000HIDDN"
	sGroup    = "S0000GROUP"
)

type fakeChannel struct {
	obj     map[string]any
	members []string
	visible bool // false: conversations.info answers channel_not_found
}

// fakeSlack is the fake Web API.
type fakeSlack struct {
	users     map[string]map[string]any // email -> user object
	channels  map[string]*fakeChannel
	order     []string // channel ids in listing order
	groups    []map[string]any
	prefs     map[string]any    // team.preferences.list fields
	prefScope bool              // team.preferences:read granted
	ugScope   bool              // usergroups:read granted
	pageSize  int               // users.conversations page size, 0 = one page
	memberPS  int               // conversations.members page size, 0 = one page
	listPS    int               // conversations.list page size, 0 = one page
	fail      map[string]string // method -> ok:false error code
	needed    string            // scope named on missing_scope
	scopesHdr string            // X-OAuth-Scopes on auth.test
}

func user(id, email string, extra map[string]any) map[string]any {
	u := map[string]any{
		"id": id, "team_id": "T0000TEAM1", "name": strings.ToLower(id), "real_name": "Person " + id,
		"deleted": false, "is_admin": false, "is_owner": false, "is_primary_owner": false,
		"is_restricted": false, "is_ultra_restricted": false, "is_bot": false, "is_invited_user": false,
		"profile": map[string]any{"email": email, "real_name": "Person " + id, "title": itest.Canary + "title"},
	}
	for k, v := range extra {
		u[k] = v
	}
	return u
}

// chanObj builds a channel object. By default it carries a properties object
// with an empty posting rule (everyone may post); pass "properties": nil to
// leave the object out, as Slack may for a channel without properties.
func chanObj(id, name string, extra map[string]any) map[string]any {
	c := map[string]any{"id": id, "name": name, "is_channel": true, "is_archived": false, "is_private": false,
		"is_general": false, "is_member": true, "is_ext_shared": false, "is_shared": false, "purpose": map[string]any{"value": itest.Canary + "purpose"},
		"properties": map[string]any{"posting_restricted_to": map[string]any{"type": []string{}, "user": []string{}}}}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func newFake() *fakeSlack {
	f := &fakeSlack{
		users: map[string]map[string]any{
			"dana@example.com":     user(uFull, "dana@example.com", nil),
			"admin@example.com":    user(uAdmin, "admin@example.com", map[string]any{"is_admin": true}),
			"owner@example.com":    user(uOwner, "owner@example.com", map[string]any{"is_admin": true, "is_owner": true}),
			"guest@example.com":    user(uGuest, "guest@example.com", map[string]any{"is_restricted": true}),
			"ultra@example.com":    user(uUltra, "ultra@example.com", map[string]any{"is_restricted": true, "is_ultra_restricted": true}),
			"dead@example.com":     user(uDead, "dead@example.com", map[string]any{"deleted": true}),
			"bot@example.com":      user(uBot, "bot@example.com", map[string]any{"is_bot": true}),
			"invited@example.com":  user(uInvited, "invited@example.com", map[string]any{"is_invited_user": true}),
			"stranger@example.com": user(uStranger, "stranger@example.com", map[string]any{"is_stranger": true}),
			"gridadmin@example.com": user(uGridAdm, "gridadmin@example.com", map[string]any{
				"enterprise_user": map[string]any{"id": uGridAdm, "enterprise_id": "E0000ENTRP", "is_admin": true, "is_owner": false}}),
			"griduser@example.com": user(uGridUser, "griduser@example.com", map[string]any{
				"enterprise_user": map[string]any{"id": uGridUser, "enterprise_id": "E0000ENTRP", "is_admin": false, "is_owner": false}}),
		},
		channels: map[string]*fakeChannel{
			cPublic:   {obj: chanObj(cPublic, "public", nil), members: []string{uFull, uAdmin, uOwner, uUltra}, visible: true},
			cGeneral:  {obj: chanObj(cGeneral, "general", map[string]any{"is_general": true}), members: []string{uFull, uAdmin, uOwner, uGuest}, visible: true},
			cRestrict: {obj: chanObj(cRestrict, "announcements", map[string]any{"properties": map[string]any{"posting_restricted_to": map[string]any{"type": []string{"admin"}, "user": []string{uUltra}}}}), members: []string{uFull, uAdmin, uGuest, uUltra}, visible: true},
			cArchived: {obj: chanObj(cArchived, "old", map[string]any{"is_archived": true}), members: []string{uFull, uAdmin}, visible: true},
			cNoProps:  {obj: chanObj(cNoProps, "plain", map[string]any{"properties": nil}), members: []string{uFull, uAdmin, uGuest}, visible: true},
			gPrivate:  {obj: chanObj(gPrivate, "secret", map[string]any{"is_private": true, "is_channel": false, "is_group": true}), members: []string{uFull, uGuest}, visible: true},
			gHidden:   {obj: chanObj(gHidden, "hidden", map[string]any{"is_private": true}), members: []string{uFull}, visible: false},
		},
		order:     []string{cPublic, cGeneral, cRestrict, cArchived, cNoProps, gPrivate, gHidden},
		groups:    []map[string]any{{"id": sGroup, "handle": "oncall", "users": []string{uFull, uAdmin}}},
		prefs:     map[string]any{"who_can_post_general": map[string]any{"type": []string{"admin"}, "user": []string{}}, "msg_edit_window_mins": -1},
		prefScope: true,
		ugScope:   true,
		fail:      map[string]string{},
		scopesHdr: "users:read,users:read.email,channels:read,groups:read,team.preferences:read,usergroups:read",
	}
	return f
}

func (f *fakeSlack) userByID(id string) map[string]any {
	for _, u := range f.users {
		if u["id"] == id {
			return u
		}
	}
	return nil
}

func (f *fakeSlack) handler(t *testing.T) http.HandlerFunc {
	write := func(w http.ResponseWriter, body map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(body)
	}
	fail := func(w http.ResponseWriter, code string) {
		body := map[string]any{"ok": false, "error": code}
		if code == "missing_scope" {
			body["needed"] = f.needed
			body["provided"] = "users:read"
		}
		write(w, body)
	}
	page := func(r *http.Request, n, size int) (lo, hi int, next string) {
		lo = 0
		if c := r.URL.Query().Get("cursor"); c != "" {
			lo, _ = strconv.Atoi(c)
		}
		hi = n
		if size > 0 && lo+size < n {
			hi = lo + size
			next = strconv.Itoa(hi)
		}
		return lo, hi, next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		method := strings.TrimPrefix(r.URL.Path, "/api/")
		if r.Method != "GET" {
			t.Errorf("%s called with %s, want GET", method, r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			fail(w, "invalid_auth")
			return
		}
		if code := f.fail[method]; code != "" {
			fail(w, code)
			return
		}
		q := r.URL.Query()
		switch method {
		case "auth.test":
			if f.scopesHdr != "" {
				w.Header().Set("X-OAuth-Scopes", f.scopesHdr)
			}
			write(w, map[string]any{"ok": true, "url": "https://" + itest.Canary + ".slack.com/", "team": "Acme", "user": "hallpass",
				"team_id": "T0000TEAM1", "user_id": "U0000HALLP", "bot_id": "B0000HALLP", "is_enterprise_install": false})
		case "users.lookupByEmail":
			u, ok := f.users[q.Get("email")]
			if !ok {
				fail(w, "users_not_found")
				return
			}
			write(w, map[string]any{"ok": true, "user": u})
		case "conversations.info":
			ch, ok := f.channels[q.Get("channel")]
			if !ok || !ch.visible {
				fail(w, "channel_not_found")
				return
			}
			write(w, map[string]any{"ok": true, "channel": ch.obj})
		case "users.conversations":
			uid := q.Get("user")
			if f.userByID(uid) == nil {
				fail(w, "user_not_found")
				return
			}
			if q.Get("types") != "public_channel,private_channel" || q.Get("limit") == "" {
				t.Errorf("users.conversations query %v", q)
			}
			var mine []map[string]any
			for _, id := range f.order {
				ch := f.channels[id]
				if !ch.visible {
					continue
				}
				for _, m := range ch.members {
					if m == uid {
						mine = append(mine, map[string]any{"id": id, "name": ch.obj["name"]})
					}
				}
			}
			lo, hi, next := page(r, len(mine), f.pageSize)
			write(w, map[string]any{"ok": true, "channels": mine[lo:hi], "response_metadata": map[string]any{"next_cursor": next}})
		case "conversations.list":
			if q.Get("types") != "public_channel" || q.Get("exclude_archived") != "true" || q.Get("limit") == "" {
				t.Errorf("conversations.list query %v", q)
			}
			var list []map[string]any
			for _, id := range f.order {
				ch := f.channels[id]
				if !ch.visible || ch.obj["is_private"] == true || ch.obj["is_archived"] == true {
					continue
				}
				list = append(list, ch.obj)
			}
			lo, hi, next := page(r, len(list), f.listPS)
			write(w, map[string]any{"ok": true, "channels": list[lo:hi], "response_metadata": map[string]any{"next_cursor": next}})
		case "conversations.members":
			ch, ok := f.channels[q.Get("channel")]
			if !ok || !ch.visible {
				fail(w, "channel_not_found")
				return
			}
			lo, hi, next := page(r, len(ch.members), f.memberPS)
			write(w, map[string]any{"ok": true, "members": ch.members[lo:hi], "response_metadata": map[string]any{"next_cursor": next}})
		case "team.preferences.list":
			if !f.prefScope {
				f.needed = "team.preferences:read"
				fail(w, "missing_scope")
				return
			}
			body := map[string]any{"ok": true}
			for k, v := range f.prefs {
				body[k] = v
			}
			write(w, body)
		case "usergroups.list":
			if !f.ugScope {
				f.needed = "usergroups:read"
				fail(w, "missing_scope")
				return
			}
			write(w, map[string]any{"ok": true, "usergroups": f.groups})
		default:
			t.Errorf("unexpected method %s", method)
			fail(w, "unknown_method")
		}
	}
}

func setup(t *testing.T, values map[string]string) (*itest.Server, *fakeSlack, integration.Connection) {
	t.Helper()
	return setupToken(t, values, secret.Literal(token))
}

func setupToken(t *testing.T, values map[string]string, cred secret.Secret) (*itest.Server, *fakeSlack, integration.Connection) {
	t.Helper()
	srv := itest.NewServer(t)
	// Slack's published description is the legacy one: the token is a query
	// parameter there, team_id (org installs) and team.preferences.list are
	// newer than it.
	srv.UseSpec(itest.SpecFromEnv(t, "slack"), itest.SpecOptions{StripPrefix: []string{`/api`}, OptionalParams: []string{"token"}, AllowQuery: []string{"team_id"}, IgnorePaths: []string{`^(/api)?/team\.preferences\.list$`}})
	f := newFake()
	srv.Handle("", "/api/*", f.handler(t))
	deps, _ := itest.Deps(t, srv)
	v := map[string]string{"url": srv.URL + "/api", "assume_default_prefs": "false"}
	for k, val := range values {
		v[k] = val
	}
	s := itest.Settings("slack", "slack", v, map[string]secret.Secret{"credential": cred})
	c, err := Integration{}.New(context.Background(), s, deps)
	if err != nil {
		t.Fatal(err)
	}
	return srv, f, c
}

var (
	dana     = integration.User{Email: "dana@example.com"}
	admin    = integration.User{Email: "admin@example.com"}
	owner    = integration.User{Email: "owner@example.com"}
	guest    = integration.User{Email: "guest@example.com"}
	ultra    = integration.User{Email: "ultra@example.com"}
	dead     = integration.User{Email: "dead@example.com"}
	bot      = integration.User{Email: "bot@example.com"}
	invited  = integration.User{Email: "invited@example.com"}
	stranger = integration.User{Email: "stranger@example.com"}
	gridAdm  = integration.User{Email: "gridadmin@example.com"}
	gridUser = integration.User{Email: "griduser@example.com"}
	nobody   = integration.User{Email: "nobody@example.com"}
)

func check(t *testing.T, c integration.Connection, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	return itest.Check(t, c, Integration{}, u, action, resource)
}

func expectText(t *testing.T, d integration.Decision, sub string) {
	t.Helper()
	if !strings.Contains(d.Text, sub) {
		t.Errorf("decision text %q does not mention %q", d.Text, sub)
	}
}

func methods(srv *itest.Server) []string {
	var out []string
	for _, c := range srv.Calls() {
		out = append(out, strings.TrimPrefix(c.Path, "/api/"))
	}
	return out
}

func count(ms []string, m string) int {
	n := 0
	for _, x := range ms {
		if x == m {
			n++
		}
	}
	return n
}

// Identity.

func TestIdentity(t *testing.T) {
	srv, _, c := setup(t, nil)
	id, err := c.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != uFull || id.Display != "Person "+uFull || id.Attr(attrAdmin) != "false" || id.Attr(attrDeleted) != "false" || id.Attr(attrTeamID) != "T0000TEAM1" {
		t.Errorf("identity %+v", id)
	}
	if id.Attr(attrEnterpriseAdmin) != "" {
		t.Error("non-Grid user should have no enterprise attrs")
	}
	if _, ok := id.Native.(*slackUser); !ok {
		t.Errorf("Native is %T", id.Native)
	}
	last := srv.LastCall()
	if last.Method != "GET" || last.Path != "/api/users.lookupByEmail" || last.Query.Get("email") != dana.Email {
		t.Errorf("lookup call %s %s %v", last.Method, last.Path, last.Query)
	}
	if last.Query.Has("team_id") {
		t.Error("team_id sent without configuration")
	}

	id, _ = c.ResolveIdentity(context.Background(), admin)
	if id.Attr(attrAdmin) != "true" {
		t.Error("admin attr")
	}
	id, _ = c.ResolveIdentity(context.Background(), gridAdm)
	if id.Attr(attrEnterpriseAdmin) != "true" || id.Attr(attrEnterpriseID) != "E0000ENTRP" {
		t.Errorf("grid attrs %v", id.Attrs)
	}

	_, err = c.ResolveIdentity(context.Background(), nobody)
	if !isCode(err, integration.CodeUserNotFound) {
		t.Errorf("nobody: %v", err)
	}
	itest.ExpectCode(t, check(t, c, nobody, "user.active", "workspace"), integration.CodeUserNotFound)
}

func isCode(err error, code integration.Code) bool {
	d := integration.ToDecision(err)
	return d.Code == code
}

func TestInactiveAccounts(t *testing.T) {
	_, _, c := setup(t, nil)
	d := check(t, c, dead, "user.active", "workspace")
	itest.ExpectCode(t, d, integration.CodeDenied)
	expectText(t, d, "deactivated")
	d = check(t, c, bot, "user.active", "workspace")
	itest.ExpectCode(t, d, integration.CodeDenied)
	expectText(t, d, "bot")
	d = check(t, c, invited, "user.active", "workspace")
	itest.ExpectCode(t, d, integration.CodeDenied)
	expectText(t, d, "invited")
	// Inactive accounts are denied everything, without a channel lookup.
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dead, "channel.read", "channel:"+cPublic), integration.CodeDenied)
	if count(methods(srv), "conversations.info") != 0 {
		t.Error("channel looked up for a deactivated account")
	}
}

func TestSlackbotIsBot(t *testing.T) {
	_, f, c := setup(t, nil)
	f.users["slackbot@example.com"] = user("USLACKBOT", "slackbot@example.com", nil)
	d := check(t, c, integration.User{Email: "slackbot@example.com"}, "user.active", "workspace")
	itest.ExpectCode(t, d, integration.CodeDenied)
	expectText(t, d, "bot")
}

func TestTokenPrefix(t *testing.T) {
	srv, _, c := setupToken(t, nil, itest.Literal("not-a-bot-token"))
	d := check(t, c, dana, "user.active", "workspace")
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	expectText(t, d, "xoxb-")
	if len(srv.Calls()) != 0 {
		t.Error("a request was sent with a non-bot token")
	}
	if strings.Contains(d.Text, "not-a-bot-token") {
		t.Error("decision text carries the credential")
	}
	if _, err := c.Probe(context.Background()); !isCode(err, integration.CodeCredentialRejected) {
		t.Errorf("probe: %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	_, f, c := setup(t, nil)
	cases := []struct {
		code string
		want integration.Code
	}{
		{"invalid_auth", integration.CodeCredentialRejected},
		{"not_authed", integration.CodeCredentialRejected},
		{"account_inactive", integration.CodeCredentialRejected},
		{"token_revoked", integration.CodeCredentialRejected},
		{"token_expired", integration.CodeCredentialRejected},
		{"missing_scope", integration.CodeCredentialRejected},
		{"ratelimited", integration.CodeUpstreamRateLimit},
		{"users_not_found", integration.CodeUserNotFound},
		{"internal_error", integration.CodeUpstreamError},
		{"fatal_error", integration.CodeUpstreamError},
	}
	for _, cs := range cases {
		f.fail["users.lookupByEmail"] = cs.code
		f.needed = "users:read.email"
		d := check(t, c, dana, "user.active", "workspace")
		if d.Code != cs.want {
			t.Errorf("%s -> %s (%s), want %s", cs.code, d.Code, d.Text, cs.want)
		}
		if cs.code == "missing_scope" {
			expectText(t, d, "users:read.email")
		}
	}
	delete(f.fail, "users.lookupByEmail")

	// Errors on later calls map the same way.
	f.fail["conversations.info"] = "channel_not_found"
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+cPublic), integration.CodeResourceNotVisible)
	f.fail["conversations.info"] = "not_in_channel"
	d := check(t, c, dana, "channel.read", "channel:"+cPublic)
	itest.ExpectCode(t, d, integration.CodeResourceNotVisible)
	expectText(t, d, "invite the bot")
	f.fail["conversations.info"] = "internal_error"
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+cPublic), integration.CodeUpstreamError)
	delete(f.fail, "conversations.info")
	f.fail["users.conversations"] = "not_in_channel"
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cPublic), integration.CodeResourceNotVisible)
	f.fail["users.conversations"] = "token_revoked"
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cPublic), integration.CodeCredentialRejected)
	delete(f.fail, "users.conversations")
	f.fail["usergroups.list"] = "missing_scope"
	f.needed = "usergroups:read"
	d = check(t, c, dana, "usergroup.member", "usergroup:"+sGroup)
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	expectText(t, d, "usergroups:read")
}

func TestNotVisibleChannel(t *testing.T) {
	_, _, c := setup(t, nil)
	for _, res := range []string{"channel:" + gHidden, "channel:C0000NOSUCH", "channel:G0000NOSUCH"} {
		d := check(t, c, dana, "channel.read", res)
		itest.ExpectCode(t, d, integration.CodeResourceNotVisible)
		expectText(t, d, "invite the bot")
	}
}

func TestStranger(t *testing.T) {
	srv, _, c := setup(t, nil)
	for _, a := range []string{"channel.read", "channel.join", "message.post", "channel.invite"} {
		itest.ExpectCode(t, check(t, c, stranger, a, "channel:"+cPublic), integration.CodeUnsupported)
	}
	if count(methods(srv), "conversations.info") != 0 {
		t.Error("channel looked up for an external user")
	}
	// Workspace facts are still answered.
	itest.ExpectCode(t, check(t, c, stranger, "user.active", "workspace"), integration.CodeAllowed)
}

func TestTeamID(t *testing.T) {
	srv, _, c := setup(t, map[string]string{"team_id": "T0000TEAM1"})
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cPublic), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "usergroup.member", "usergroup:"+sGroup), integration.CodeAllowed)
	if _, err := c.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := srv.Calls()
	if len(calls) < 6 {
		t.Fatalf("only %d calls", len(calls))
	}
	for _, cl := range calls {
		if cl.Query.Get("team_id") != "T0000TEAM1" {
			t.Errorf("%s sent without team_id: %v", cl.Path, cl.Query)
		}
	}
	for _, bad := range []string{"acme", "t0123", "T0123?x=1"} {
		if err := validateTeamID(bad); err == nil {
			t.Errorf("team_id %q accepted", bad)
		}
	}
	if err := validateTeamID("E0000ENTRP"); err != nil {
		t.Error(err)
	}
}

func TestMembershipPagination(t *testing.T) {
	srv, f, c := setup(t, nil)
	f.pageSize = 1 // dana is in 6 visible channels; secret is the fifth: public, general, announcements, old, plain, secret
	f.order = []string{cPublic, cGeneral, cRestrict, cArchived, gPrivate, cNoProps, gHidden}
	d := check(t, c, dana, "message.post", "channel:"+gPrivate)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	ms := methods(srv)
	if n := count(ms, "users.conversations"); n != 5 {
		t.Errorf("users.conversations called %d times, want 5 (%v)", n, ms)
	}
	if count(ms, "conversations.members") != 0 {
		t.Error("fell back to conversations.members although the channel was on page 5")
	}
	calls := srv.Calls()
	var cursors []string
	for _, cl := range calls {
		if strings.HasSuffix(cl.Path, "users.conversations") {
			cursors = append(cursors, cl.Query.Get("cursor"))
		}
	}
	if strings.Join(cursors, ",") != ",1,2,3,4" {
		t.Errorf("cursors %v", cursors)
	}
}

func TestMembershipFallback(t *testing.T) {
	srv, f, c := setup(t, nil)
	f.pageSize = 1
	// Put dana in enough channels that the target is beyond page 5.
	for i := 0; i < 6; i++ {
		id := "C0000EXTRA" + strconv.Itoa(i)
		f.channels[id] = &fakeChannel{obj: chanObj(id, "extra"+strconv.Itoa(i), nil), members: []string{uFull}, visible: true}
		f.order = append([]string{id}, f.order...)
	}
	f.memberPS = 2
	d := check(t, c, dana, "message.post", "channel:"+gPrivate)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	ms := methods(srv)
	if n := count(ms, "users.conversations"); n != 5 {
		t.Errorf("users.conversations called %d times, want 5", n)
	}
	if n := count(ms, "conversations.members"); n != 1 {
		t.Errorf("conversations.members called %d times, want 1 (%v)", n, ms)
	}
	// Members pagination: a user on the second page.
	srv.Reset()
	f.channels[gPrivate].members = []string{uAdmin, uOwner, uFull}
	d = check(t, c, dana, "message.post", "channel:"+gPrivate)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	if n := count(methods(srv), "conversations.members"); n != 2 {
		t.Errorf("conversations.members called %d times, want 2", n)
	}
	// Not a member after the whole fallback: deny.
	f.channels[gPrivate].members = []string{uAdmin}
	d = check(t, c, dana, "message.post", "channel:"+gPrivate)
	itest.ExpectCode(t, d, integration.CodeDenied)
}

func TestGeneralPosting(t *testing.T) {
	_, f, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "message.post", "channel:"+cGeneral), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, owner, "message.post", "channel:"+cGeneral), integration.CodeAllowed)

	f.prefs["who_can_post_general"] = map[string]any{"type": []string{"owner"}, "user": []string{uFull}}
	itest.ExpectCode(t, check(t, c, admin, "message.post", "channel:"+cGeneral), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, owner, "message.post", "channel:"+cGeneral), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeAllowed)

	f.prefs["who_can_post_general"] = "admin"
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeDenied)
	f.prefs["who_can_post_general"] = "everyone"
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeAllowed)
	f.prefs["who_can_post_general"] = "something_new"
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeUnsupported)

	delete(f.prefs, "who_can_post_general")
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeUnsupported)
	f.prefScope = false
	d := check(t, c, dana, "message.post", "channel:"+cGeneral)
	itest.ExpectCode(t, d, integration.CodeCredentialRejected)
	expectText(t, d, "team.preferences:read")

	// Non-general channels never read the preferences.
	srv, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cPublic), integration.CodeAllowed)
	if count(methods(srv), "team.preferences.list") != 0 {
		t.Error("team.preferences.list read for a non-general channel")
	}
}

func TestAssumeDefaultPrefs(t *testing.T) {
	_, f, c := setup(t, map[string]string{"assume_default_prefs": "true"})
	f.prefScope = false
	d := check(t, c, dana, "message.post", "channel:"+cGeneral)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	f.prefScope = true
	delete(f.prefs, "who_can_post_general")
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeAllowed)
	f.prefs["who_can_post_general"] = map[string]any{"type": []string{"admin"}}
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeDenied)

	d = check(t, c, dana, "channel.create", "workspace")
	itest.ExpectCode(t, d, integration.CodeAllowed)
	expectText(t, d, "default")
	itest.ExpectCode(t, check(t, c, guest, "channel.create", "workspace"), integration.CodeDenied)
}

func TestPostingRestriction(t *testing.T) {
	_, _, c := setup(t, nil)
	d := check(t, c, dana, "message.post", "channel:"+cRestrict)
	itest.ExpectCode(t, d, integration.CodeDenied)
	expectText(t, d, "admins and owners")
	itest.ExpectCode(t, check(t, c, admin, "message.post", "channel:"+cRestrict), integration.CodeAllowed)
	// A named user may post even as a guest.
	itest.ExpectCode(t, check(t, c, ultra, "message.post", "channel:"+cRestrict), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, guest, "message.post", "channel:"+cRestrict), integration.CodeDenied)
	// Thread replies are not blocked by the restriction.
	d = check(t, c, dana, "message.post_thread", "channel:"+cRestrict)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	expectText(t, d, "thread replies")
	// An empty rule means everyone.
	d = check(t, c, dana, "message.post", "channel:"+cPublic)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	expectText(t, d, "is a member of")
}

// An absent posting_restricted_to is not "unrestricted": whether a bot token
// sees the property is unverified, so the answer is unknown unless the
// connection opts in with assume_default_prefs.
func TestPostingPropertyAbsent(t *testing.T) {
	_, f, c := setup(t, nil)
	for _, a := range []string{"message.post", "message.post_thread", "file.upload"} {
		d := check(t, c, dana, a, "channel:"+cNoProps)
		itest.ExpectCode(t, d, integration.CodeUnsupported)
		expectText(t, d, "not visible to the bot")
		itest.ExpectCode(t, check(t, c, admin, a, "channel:"+cNoProps), integration.CodeUnsupported)
	}
	// A properties object without the posting_restricted_to key is absent too.
	f.channels[cNoProps].obj["properties"] = map[string]any{"canvas": map[string]any{"is_empty": true}}
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cNoProps), integration.CodeUnsupported)
	// Membership and archival are still decided first.
	itest.ExpectCode(t, check(t, c, ultra, "message.post", "channel:"+cNoProps), integration.CodeDenied)
	f.channels[cNoProps].obj["is_archived"] = true
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cNoProps), integration.CodeDenied)

	_, _, c = setup(t, map[string]string{"assume_default_prefs": "true"})
	d := check(t, c, dana, "message.post", "channel:"+cNoProps)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	expectText(t, d, "no posting restriction is visible to the bot")
	expectText(t, d, "assume_default_prefs")
	itest.ExpectCode(t, check(t, c, guest, "message.post", "channel:"+cNoProps), integration.CodeAllowed)
	// #general's own rule still applies before the channel property.
	_, f, c = setup(t, map[string]string{"assume_default_prefs": "true"})
	f.channels[cGeneral].obj["properties"] = nil
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "message.post", "channel:"+cGeneral), integration.CodeAllowed)
}

// A posting rule naming a poster type hallpass does not model cannot be
// evaluated: unknown, not deny.
func TestUnrecognisedPosterType(t *testing.T) {
	_, f, c := setup(t, nil)
	f.prefs["who_can_post_general"] = map[string]any{"type": []string{"something_new"}, "user": []string{}}
	d := check(t, c, dana, "message.post", "channel:"+cGeneral)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	expectText(t, d, "something_new")
	itest.ExpectCode(t, check(t, c, admin, "message.post", "channel:"+cGeneral), integration.CodeUnsupported)
	// A recognised match still wins.
	f.prefs["who_can_post_general"] = map[string]any{"type": []string{"admin", "something_new"}, "user": []string{uGuest}}
	itest.ExpectCode(t, check(t, c, admin, "message.post", "channel:"+cGeneral), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, guest, "message.post", "channel:"+cGeneral), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeUnsupported)

	f.channels[cRestrict].obj["properties"] = map[string]any{"posting_restricted_to": map[string]any{"type": []string{"something_new"}, "user": []string{uUltra}}}
	d = check(t, c, dana, "message.post", "channel:"+cRestrict)
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	expectText(t, d, "something_new")
	itest.ExpectCode(t, check(t, c, dana, "file.upload", "channel:"+cRestrict), integration.CodeUnsupported)
	// Admins bypass the channel restriction, named users match, threads are
	// not limited by it.
	itest.ExpectCode(t, check(t, c, admin, "message.post", "channel:"+cRestrict), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, ultra, "message.post", "channel:"+cRestrict), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "message.post_thread", "channel:"+cRestrict), integration.CodeAllowed)
	// A recognised type that positively excludes the user is still a deny.
	f.channels[cRestrict].obj["properties"] = map[string]any{"posting_restricted_to": map[string]any{"type": []string{"owner"}, "user": []string{}}}
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cRestrict), integration.CodeDenied)
}

// Invite, rename and archive act from inside the channel: membership first.
func TestChannelActionsNeedMembership(t *testing.T) {
	srv, f, c := setup(t, nil)
	for _, a := range []string{"channel.invite", "channel.rename", "channel.archive"} {
		// Admins and owners who are not members of a private channel.
		for _, u := range []integration.User{admin, owner} {
			d := check(t, c, u, a, "channel:"+gPrivate)
			itest.ExpectCode(t, d, integration.CodeDenied)
			expectText(t, d, "not a member")
		}
		// A full member of the private channel: the preference gate as usual.
		d := check(t, c, dana, a, "channel:"+gPrivate)
		itest.ExpectCode(t, d, integration.CodeUnsupported)
		expectText(t, d, "not readable by a bot token")
		// A guest member of the private channel is refused by the gate.
		itest.ExpectCode(t, check(t, c, guest, a, "channel:"+gPrivate), integration.CodeDenied)
	}
	if count(methods(srv), "users.conversations") == 0 {
		t.Error("membership never read")
	}
	// An admin member of a private channel is allowed.
	f.channels[gPrivate].members = append(f.channels[gPrivate].members, uAdmin)
	for _, a := range []string{"channel.invite", "channel.rename", "channel.archive"} {
		itest.ExpectCode(t, check(t, c, admin, a, "channel:"+gPrivate), integration.CodeAllowed)
	}
	// Public channel, not a member: joining first is possible, so unknown
	// for admins and full members, deny for guests.
	f.channels[cPublic].members = []string{uOwner}
	for _, a := range []string{"channel.invite", "channel.rename", "channel.archive"} {
		for _, u := range []integration.User{admin, dana} {
			d := check(t, c, u, a, "channel:"+cPublic)
			itest.ExpectCode(t, d, integration.CodeUnsupported)
			expectText(t, d, "not a member")
			expectText(t, d, "joining first is possible")
		}
		for _, u := range []integration.User{guest, ultra} {
			d := check(t, c, u, a, "channel:"+cPublic)
			itest.ExpectCode(t, d, integration.CodeDenied)
			expectText(t, d, "not a member")
		}
		itest.ExpectCode(t, check(t, c, owner, a, "channel:"+cPublic), integration.CodeAllowed)
	}
	// assume_default_prefs does not turn a non-member into an allow.
	_, f, c = setup(t, map[string]string{"assume_default_prefs": "true"})
	f.channels[cPublic].members = []string{uOwner}
	itest.ExpectCode(t, check(t, c, dana, "channel.invite", "channel:"+cPublic), integration.CodeUnsupported)
	itest.ExpectCode(t, check(t, c, admin, "channel.archive", "channel:"+gPrivate), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "channel.rename", "channel:"+gPrivate), integration.CodeAllowed)
	// Archived and #general answers come before the membership read.
	srv, _, c = setup(t, nil)
	itest.ExpectCode(t, check(t, c, admin, "channel.archive", "channel:"+cGeneral), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "channel.invite", "channel:"+cArchived), integration.CodeDenied)
	if count(methods(srv), "users.conversations") != 0 {
		t.Error("membership read for an answer that does not depend on it")
	}
}

// On an Enterprise Grid org-level install the user object may belong to
// another workspace of the organization; "any full member of this workspace"
// is then not established.
func TestGridTeamMismatch(t *testing.T) {
	_, f, c := setup(t, map[string]string{"team_id": "T0000OTHR1"})
	for _, a := range []string{"channel.read", "channel.join"} {
		d := check(t, c, dana, a, "channel:"+cPublic)
		itest.ExpectCode(t, d, integration.CodeUnsupported)
		expectText(t, d, "another workspace of the organization")
		itest.ExpectCode(t, check(t, c, admin, a, "channel:"+cPublic), integration.CodeUnsupported)
	}
	// Positive facts still decide: membership of a private channel, guests.
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+gPrivate), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, admin, "channel.read", "channel:"+gPrivate), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, ultra, "channel.read", "channel:"+cPublic), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, guest, "channel.join", "channel:"+cPublic), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "channel.join", "channel:"+cArchived), integration.CodeDenied)
	// A user object without team_id cannot be compared.
	delete(f.users["dana@example.com"], "team_id")
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+cPublic), integration.CodeAllowed)

	// The same workspace, or no team_id on the connection: allowed as before.
	_, _, c = setup(t, map[string]string{"team_id": "T0000TEAM1"})
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+cPublic), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "channel.join", "channel:"+cPublic), integration.CodeAllowed)
	_, f, c = setup(t, nil)
	f.users["dana@example.com"]["team_id"] = "T0000OTHR1"
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+cPublic), integration.CodeAllowed)
}

func TestReadAndJoinRules(t *testing.T) {
	srv, _, c := setup(t, nil)
	// Public channel, full member: no membership call.
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+cPublic), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "channel.join", "channel:"+cPublic), integration.CodeAllowed)
	if count(methods(srv), "users.conversations") != 0 {
		t.Error("membership read for a full member on a public channel")
	}
	// Guests need membership.
	itest.ExpectCode(t, check(t, c, ultra, "channel.read", "channel:"+cPublic), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, guest, "channel.read", "channel:"+cPublic), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, ultra, "channel.join", "channel:"+cPublic), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, guest, "channel.join", "channel:"+cPublic), integration.CodeDenied)
	// Private: membership decides.
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+gPrivate), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, admin, "channel.read", "channel:"+gPrivate), integration.CodeDenied)
	d := check(t, c, dana, "channel.join", "channel:"+gPrivate)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	expectText(t, d, "already a member")
	itest.ExpectCode(t, check(t, c, admin, "channel.join", "channel:"+gPrivate), integration.CodeDenied)
	// Archived: readable, not joinable, not postable.
	d = check(t, c, dana, "channel.read", "channel:"+cArchived)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	expectText(t, d, "archived")
	itest.ExpectCode(t, check(t, c, dana, "channel.join", "channel:"+cArchived), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cArchived), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "file.upload", "channel:"+cArchived), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "channel.rename", "channel:"+cArchived), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "channel.invite", "channel:"+cArchived), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "channel.archive", "channel:"+cArchived), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "channel.archive", "channel:"+cGeneral), integration.CodeDenied)
	// Not a member of a public channel: post denied, join possible.
	d = check(t, c, guest, "message.post", "channel:"+cPublic)
	itest.ExpectCode(t, d, integration.CodeDenied)
	_, f2, c2 := setup(t, nil)
	f2.channels[cPublic].members = []string{uAdmin}
	d = check(t, c2, dana, "message.post", "channel:"+cPublic)
	itest.ExpectCode(t, d, integration.CodeDenied)
	expectText(t, d, "joining is possible")
}

func TestPrefGate(t *testing.T) {
	_, _, c := setup(t, nil)
	for _, cs := range []struct{ action, resource string }{
		{"channel.invite", "channel:" + cPublic},
		{"channel.create", "workspace"},
		{"channel.archive", "channel:" + cPublic},
		{"channel.rename", "channel:" + cPublic},
	} {
		d := check(t, c, dana, cs.action, cs.resource)
		itest.ExpectCode(t, d, integration.CodeUnsupported)
		expectText(t, d, "not readable by a bot token")
		itest.ExpectCode(t, check(t, c, guest, cs.action, cs.resource), integration.CodeDenied)
		itest.ExpectCode(t, check(t, c, ultra, cs.action, cs.resource), integration.CodeDenied)
		itest.ExpectCode(t, check(t, c, admin, cs.action, cs.resource), integration.CodeAllowed)
		itest.ExpectCode(t, check(t, c, owner, cs.action, cs.resource), integration.CodeAllowed)
	}
	// Channel-scoped ones still need a visible channel.
	itest.ExpectCode(t, check(t, c, admin, "channel.rename", "channel:"+gHidden), integration.CodeResourceNotVisible)
}

func TestUsergroups(t *testing.T) {
	srv, _, c := setup(t, nil)
	d := check(t, c, dana, "usergroup.member", "usergroup:"+sGroup)
	itest.ExpectCode(t, d, integration.CodeAllowed)
	expectText(t, d, "@oncall")
	if last := srv.LastCall(); last.Path != "/api/usergroups.list" || last.Query.Get("include_users") != "true" {
		t.Errorf("usergroups.list call %s %v", last.Path, last.Query)
	}
	itest.ExpectCode(t, check(t, c, guest, "usergroup.member", "usergroup:"+sGroup), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "usergroup.member", "usergroup:S0000NOSUCH"), integration.CodeResourceNotVisible)
}

func TestOrgAdmin(t *testing.T) {
	_, _, c := setup(t, nil)
	d := check(t, c, dana, "org.admin", "workspace")
	itest.ExpectCode(t, d, integration.CodeUnsupported)
	expectText(t, d, "Enterprise Grid")
	itest.ExpectCode(t, check(t, c, gridAdm, "org.admin", "workspace"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, gridUser, "org.admin", "workspace"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "org.admin", "workspace"), integration.CodeUnsupported)
}

func TestBadResources(t *testing.T) {
	_, _, c := setup(t, nil)
	cases := []struct{ action, resource string }{
		{"channel.read", "workspace"},
		{"channel.read", "channel:general"},
		{"channel.read", "channel:C0000PUBLC?x=1"},
		{"channel.read", "channel:c0000publc"},
		{"channel.read", "channel:D0000DMDM1"},
		{"channel.read", "channel:"},
		{"user.active", "workspace:acme"},
		{"user.active", "channel:" + cPublic},
		{"usergroup.member", "usergroup:oncall"},
		{"usergroup.member", "usergroup:" + cPublic},
		{"channel.create", "channel:" + cPublic},
	}
	for _, cs := range cases {
		d := check(t, c, dana, cs.action, cs.resource)
		if d.Code != integration.CodeInvalidRequest {
			t.Errorf("%s %s -> %s: %s", cs.action, cs.resource, d.Code, d.Text)
		}
	}
	if _, ok := integration.FindAction(Integration{}, "raw:x"); ok {
		t.Error("pattern action accepted")
	}
	if err := integration.ValidateFields(Integration{}.Fields()); err != nil {
		t.Error(err)
	}
}

func TestFailures(t *testing.T) {
	srv, _, c := setup(t, nil)
	itest.FailureCases(t, srv, func() integration.Decision {
		return check(t, c, dana, "message.post", "channel:"+cPublic)
	})
	// A failure after identity resolution maps the same way.
	id, err := c.ResolveIdentity(context.Background(), dana)
	if err != nil {
		t.Fatal(err)
	}
	itest.FailureCases(t, srv, func() integration.Decision {
		res, _ := integration.FindAction(Integration{}, "channel.read")
		d, err := c.Check(context.Background(), integration.CheckRequest{User: dana, Identity: id, Action: res, ActionName: "channel.read", Resource: mustRes(t, "channel:"+gPrivate)})
		if err != nil {
			return integration.ToDecision(err)
		}
		return d
	})
}

func mustRes(t *testing.T, s string) catalog.Resource {
	t.Helper()
	r, err := catalog.ParseResource(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestProbe(t *testing.T) {
	_, f, c := setup(t, nil)
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "U0000HALLP") || !strings.Contains(r.Summary, "Acme") || !strings.Contains(r.Summary, "B0000HALLP") || !strings.Contains(r.Summary, "channel properties visible") {
		t.Errorf("summary %q", r.Summary)
	}
	if len(r.Warnings) != 0 {
		t.Errorf("warnings %v", r.Warnings)
	}

	f.scopesHdr = "users:read,users:read.email,channels:read,groups:read,chat:write,channels:manage,admin.users:read"
	r, _ = c.Probe(context.Background())
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "chat:write") || !strings.Contains(r.Warnings[0], "channels:manage") || !strings.Contains(r.Warnings[0], "admin.users:read") {
		t.Errorf("write scope warnings %v", r.Warnings)
	}
	f.scopesHdr = "users:read,channels:read"
	r, _ = c.Probe(context.Background())
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "users:read.email") || !strings.Contains(r.Warnings[0], "groups:read") {
		t.Errorf("missing scope warnings %v", r.Warnings)
	}
	f.scopesHdr = ""

	f.prefScope, f.ugScope = false, false
	r, _ = c.Probe(context.Background())
	if len(r.Warnings) != 2 || !strings.Contains(r.Warnings[0], "team.preferences:read") || !strings.Contains(r.Warnings[1], "usergroups:read") {
		t.Errorf("optional scope warnings %v", r.Warnings)
	}
	f.prefScope, f.ugScope = true, true

	f.fail["users.lookupByEmail"] = "missing_scope"
	f.needed = "users:read.email"
	r, err = c.Probe(context.Background())
	if err != nil || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "users:read.email") {
		t.Errorf("lookup scope: %v %v", r.Warnings, err)
	}
	delete(f.fail, "users.lookupByEmail")

	f.fail["auth.test"] = "invalid_auth"
	if _, err := c.Probe(context.Background()); !isCode(err, integration.CodeCredentialRejected) {
		t.Errorf("auth.test invalid_auth: %v", err)
	}
	delete(f.fail, "auth.test")
	f.fail["usergroups.list"] = "internal_error"
	if _, err := c.Probe(context.Background()); !isCode(err, integration.CodeUpstreamError) {
		t.Errorf("usergroups internal_error: %v", err)
	}
}

// The probe reads #general to report whether channel properties are visible.
func TestProbeChannelProperties(t *testing.T) {
	srv, f, c := setup(t, nil)
	f.listPS = 1 // #general is the second public channel listed
	r, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Summary, "channel properties visible") || len(r.Warnings) != 0 {
		t.Errorf("summary %q warnings %v", r.Summary, r.Warnings)
	}
	ms := methods(srv)
	if n := count(ms, "conversations.list"); n != 2 {
		t.Errorf("conversations.list called %d times, want 2 (%v)", n, ms)
	}
	var infos []string
	for _, cl := range srv.Calls() {
		if strings.HasSuffix(cl.Path, "conversations.list") {
			if cl.Query.Get("types") != "public_channel" || cl.Query.Get("exclude_archived") != "true" || cl.Query.Get("limit") != "200" {
				t.Errorf("conversations.list query %v", cl.Query)
			}
		}
		if strings.HasSuffix(cl.Path, "conversations.info") {
			infos = append(infos, cl.Query.Get("channel"))
		}
	}
	if strings.Join(infos, ",") != cGeneral {
		t.Errorf("conversations.info called for %v, want only #general", infos)
	}

	// No properties object on #general: warn.
	f.channels[cGeneral].obj["properties"] = nil
	r, err = c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Summary, "channel properties visible") {
		t.Errorf("summary %q", r.Summary)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "no properties object") || !strings.Contains(r.Warnings[0], "assume_default_prefs") {
		t.Errorf("warnings %v", r.Warnings)
	}
	// #general not listed: warn, without a conversations.info call.
	f.channels[cGeneral].obj["is_general"] = false
	srv.Reset()
	r, err = c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "#general was not found") {
		t.Errorf("warnings %v", r.Warnings)
	}
	if count(methods(srv), "conversations.info") != 0 {
		t.Error("conversations.info called without #general")
	}
	// Failures of the listing are the probe's failures.
	f.fail["conversations.list"] = "missing_scope"
	f.needed = "channels:read"
	if _, err := c.Probe(context.Background()); !isCode(err, integration.CodeCredentialRejected) {
		t.Errorf("conversations.list missing_scope: %v", err)
	}
}

func TestPostersParsing(t *testing.T) {
	full := integration.Identity{ID: uFull}
	adm := integration.Identity{ID: uAdmin, Attrs: map[string]string{attrAdmin: "true"}}
	own := integration.Identity{ID: uOwner, Attrs: map[string]string{attrAdmin: "true", attrOwner: "true"}}
	cases := []struct {
		raw            string
		full, adm, own bool
		nilP, err      bool
		unknown        string // reported for whoever is not allowed
	}{
		{raw: "", nilP: true},
		{raw: "null", nilP: true},
		{raw: `{}`, full: true, adm: true, own: true},
		{raw: `{"type":[],"user":[]}`, full: true, adm: true, own: true},
		{raw: `{"type":["admin"],"user":[]}`, adm: true, own: true},
		{raw: `{"type":["owner"],"user":["` + uFull + `"]}`, full: true, own: true},
		{raw: `{"type":["weird"],"user":[]}`, unknown: "weird"},
		{raw: `{"type":["admin","weird"],"user":["` + uFull + `"]}`, full: true, adm: true, own: true},
		{raw: `{"type":["weird","owner"],"user":[]}`, own: true, unknown: "weird"},
		{raw: `"everyone"`, full: true, adm: true, own: true},
		{raw: `"admin"`, adm: true, own: true},
		{raw: `"owner"`, own: true},
		{raw: `"weird"`, err: true},
		{raw: `42`, err: true},
	}
	for _, cs := range cases {
		p, err := parsePosters(json.RawMessage(cs.raw))
		if cs.err {
			if err == nil {
				t.Errorf("%s: expected error", cs.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", cs.raw, err)
			continue
		}
		if cs.nilP {
			if p != nil {
				t.Errorf("%s: expected nil", cs.raw)
			}
			continue
		}
		for _, id := range []struct {
			id   integration.Identity
			want bool
		}{{full, cs.full}, {adm, cs.adm}, {own, cs.own}} {
			ok, unknown := p.allows(id.id)
			if ok != id.want {
				t.Errorf("%s: %s allowed=%v, want %v", cs.raw, id.id.ID, ok, id.want)
			}
			wantUnknown := ""
			if !ok {
				wantUnknown = cs.unknown
			}
			if unknown != wantUnknown {
				t.Errorf("%s: %s unknown=%q, want %q", cs.raw, id.id.ID, unknown, wantUnknown)
			}
		}
	}
}

// Allow/deny tests per action (coverage gate).

func TestAction_user_active_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "user.active", "workspace"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, guest, "user.active", "workspace"), integration.CodeAllowed)
}
func TestAction_user_active_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dead, "user.active", "workspace"), integration.CodeDenied)
}
func TestAction_workspace_admin_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, admin, "workspace.admin", "workspace"), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, owner, "workspace.admin", "workspace"), integration.CodeAllowed)
}
func TestAction_workspace_admin_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "workspace.admin", "workspace"), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dead, "workspace.admin", "workspace"), integration.CodeDenied)
}
func TestAction_org_admin_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, gridAdm, "org.admin", "workspace"), integration.CodeAllowed)
}
func TestAction_org_admin_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, gridUser, "org.admin", "workspace"), integration.CodeDenied)
}
func TestAction_channel_read_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+cPublic), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "channel.read", "channel:"+gPrivate), integration.CodeAllowed)
}
func TestAction_channel_read_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, admin, "channel.read", "channel:"+gPrivate), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, guest, "channel.read", "channel:"+cPublic), integration.CodeDenied)
}
func TestAction_channel_join_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "channel.join", "channel:"+cPublic), integration.CodeAllowed)
}
func TestAction_channel_join_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "channel.join", "channel:"+cPublic), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "channel.join", "channel:"+gPrivate), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "channel.join", "channel:"+cArchived), integration.CodeDenied)
}
func TestAction_message_post_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cPublic), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, admin, "message.post", "channel:"+cGeneral), integration.CodeAllowed)
}
func TestAction_message_post_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "message.post", "channel:"+cPublic), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cGeneral), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "message.post", "channel:"+cRestrict), integration.CodeDenied)
}
func TestAction_message_post_thread_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "message.post_thread", "channel:"+cPublic), integration.CodeAllowed)
	itest.ExpectCode(t, check(t, c, dana, "message.post_thread", "channel:"+cRestrict), integration.CodeAllowed)
}
func TestAction_message_post_thread_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "message.post_thread", "channel:"+cPublic), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "message.post_thread", "channel:"+cArchived), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "message.post_thread", "channel:"+cGeneral), integration.CodeDenied)
}
func TestAction_file_upload_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "file.upload", "channel:"+cPublic), integration.CodeAllowed)
}
func TestAction_file_upload_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "file.upload", "channel:"+cPublic), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, dana, "file.upload", "channel:"+cRestrict), integration.CodeDenied)
}
func TestAction_usergroup_member_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, dana, "usergroup.member", "usergroup:"+sGroup), integration.CodeAllowed)
}
func TestAction_usergroup_member_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "usergroup.member", "usergroup:"+sGroup), integration.CodeDenied)
}
func TestAction_channel_invite_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, admin, "channel.invite", "channel:"+cPublic), integration.CodeAllowed)
}
func TestAction_channel_invite_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "channel.invite", "channel:"+cPublic), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "channel.invite", "channel:"+gPrivate), integration.CodeDenied)
}
func TestAction_channel_create_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, admin, "channel.create", "workspace"), integration.CodeAllowed)
}
func TestAction_channel_create_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "channel.create", "workspace"), integration.CodeDenied)
}
func TestAction_channel_archive_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, admin, "channel.archive", "channel:"+cPublic), integration.CodeAllowed)
}
func TestAction_channel_archive_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "channel.archive", "channel:"+cPublic), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "channel.archive", "channel:"+gPrivate), integration.CodeDenied)
}
func TestAction_channel_rename_allow(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, admin, "channel.rename", "channel:"+cPublic), integration.CodeAllowed)
}
func TestAction_channel_rename_deny(t *testing.T) {
	_, _, c := setup(t, nil)
	itest.ExpectCode(t, check(t, c, guest, "channel.rename", "channel:"+cPublic), integration.CodeDenied)
	itest.ExpectCode(t, check(t, c, admin, "channel.rename", "channel:"+gPrivate), integration.CodeDenied)
}
