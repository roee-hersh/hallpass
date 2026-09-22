// Package slack answers questions about Slack users, channels and user
// groups by reading the Slack Web API with a bot token.
//
// hallpass resolves the caller's email with users.lookupByEmail, reads the
// channel with conversations.info, checks membership with users.conversations
// (falling back to conversations.members for users in very many channels) and
// reads #general's posting rule with team.preferences.list and user group
// membership with usergroups.list. The probe also lists public channels with
// conversations.list to find #general. Every call is a read; nothing is
// posted, joined or changed.
package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// DefaultURL is the Slack Web API base.
const DefaultURL = "https://slack.com/api"

// tokenPrefix is what a bot token starts with. hallpass refuses user (xoxp)
// and app-level (xapp) tokens so a check never runs as a person.
const tokenPrefix = "xoxb-"

// Scopes the bot token needs.
var (
	requiredScopes = []string{"users:read", "users:read.email", "channels:read", "groups:read"}
	optionalScopes = map[string]string{
		"team.preferences:read": "message.post in #general answers unknown",
		"usergroups:read":       "usergroup.member answers unknown",
	}
)

// Integration is the slack product.
type Integration struct{}

// Name is "slack".
func (Integration) Name() string { return "slack" }

var teamIDRe = regexp.MustCompile(`^[TE][A-Z0-9]{6,}$`)

// Fields of a slack connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.CredentialField(true, "bot token (xoxb-...) of an internal app with the read scopes listed in the docs"),
		{Name: "url", Default: DefaultURL, Validate: integration.ValidateHTTPSURL,
			Description: "Slack Web API base URL, default " + DefaultURL},
		{Name: "team_id", Validate: validateTeamID,
			Description: "workspace id (T...) to address with an Enterprise Grid org-level install; sent as team_id on every call"},
		{Name: "assume_default_prefs", Default: "false", Enum: []string{"true", "false"},
			Description: "treat workspace preferences the bot cannot read as Slack's defaults instead of answering unknown"},
	}
}

func validateTeamID(v string) error {
	if v == "" {
		return nil
	}
	if !teamIDRe.MatchString(v) {
		return fmt.Errorf("team_id %q must be a Slack workspace id such as T0123456789", v)
	}
	return nil
}

// New builds a connection. It does not touch the network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	cred := s.Secret("credential")
	if cred.IsZero() {
		return nil, errors.New("credential is required")
	}
	base := s.Get("url")
	if base == "" {
		base = DefaultURL
	}
	c := &Connection{
		teamID:         s.Get("team_id"),
		assumeDefaults: s.Bool("assume_default_prefs", false),
	}
	c.client = &httpx.Client{
		HTTP:    hc,
		Base:    base,
		Logger:  d.Logger,
		Retries: 1,
		Auth:    httpx.BearerAuth(botToken(cred)),
	}
	return c, nil
}

// botToken reads the credential at call time and refuses anything that is
// not a bot token. The error names neither the token nor its prefix.
func botToken(cred secret.Secret) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		tok, err := cred.GetString()
		if err != nil {
			return "", integration.Wrap(integration.CodeCredentialRejected, err, "the connection's credential could not be read")
		}
		if !strings.HasPrefix(tok, tokenPrefix) {
			return "", integration.Errorf(integration.CodeCredentialRejected, "the connection's credential is not a Slack bot token (it must start with %s)", tokenPrefix)
		}
		return tok, nil
	}
}

// Connection is one Slack workspace (or one workspace of an Enterprise Grid
// org-level install, selected by team_id).
type Connection struct {
	client         *httpx.Client
	teamID         string
	assumeDefaults bool
}

// apiError is an HTTP 200 response with ok:false.
type apiError struct {
	method string
	code   string
	needed string // the scope named by missing_scope
}

func (e *apiError) Error() string { return "slack " + e.method + ": " + e.code }

// apiCode returns the Slack error code carried by err, or "".
func apiCode(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.code
	}
	return ""
}

// result is what call returns besides the decoded body.
type result struct {
	Header     http.Header
	NextCursor string
}

type envelope struct {
	OK               bool   `json:"ok"`
	Error            string `json:"error"`
	Needed           string `json:"needed"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// call performs one Web API method as a GET with query parameters (so httpx
// retries apply; every method used here is a read) and decodes the body into
// out when ok is true. team_id is added when configured.
func (c *Connection) call(ctx context.Context, method string, q url.Values, out any) (*result, error) {
	query := url.Values{}
	for k, vs := range q {
		query[k] = append([]string(nil), vs...)
	}
	if c.teamID != "" {
		query.Set("team_id", c.teamID)
	}
	resp, err := c.client.GetJSON(ctx, method, query, nil)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := resp.JSON(&env); err != nil {
		return nil, fmt.Errorf("decode %s: %w", method, err)
	}
	if !env.OK {
		code := env.Error
		if code == "" {
			code = "unknown_error"
		}
		return nil, &apiError{method: method, code: code, needed: env.Needed}
	}
	if out != nil {
		if err := resp.JSON(out); err != nil {
			return nil, fmt.Errorf("decode %s: %w", method, err)
		}
	}
	return &result{Header: resp.Header, NextCursor: env.ResponseMetadata.NextCursor}, nil
}

// classify maps an ok:false error or a transport error to an *integration.Error.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var ae *apiError
	if !errors.As(err, &ae) {
		return httpx.Classify(err)
	}
	switch ae.code {
	case "invalid_auth", "not_authed", "account_inactive", "token_revoked", "token_expired":
		return integration.Wrap(integration.CodeCredentialRejected, err, "Slack rejected the connection's bot token (%s)", ae.code)
	case "missing_scope":
		scope := ae.needed
		if scope == "" {
			scope = "a required"
		}
		return integration.Wrap(integration.CodeCredentialRejected, err, "the bot token lacks the %s scope that %s needs", scope, ae.method)
	case "ratelimited":
		return integration.Wrap(integration.CodeUpstreamRateLimit, err, "rate limited by Slack")
	case "users_not_found", "user_not_found":
		return integration.Wrap(integration.CodeUserNotFound, err, "no Slack account matches the user")
	case "channel_not_found":
		return integration.Wrap(integration.CodeResourceNotVisible, err, "the channel does not exist or is a private channel the bot is not in; invite the bot to the channel")
	case "not_in_channel":
		return integration.Wrap(integration.CodeResourceNotVisible, err, "the bot is not a member of the channel; invite the bot to the channel")
	}
	return integration.Wrap(integration.CodeUpstreamError, err, "Slack %s returned error %s", ae.method, ae.code)
}

// slackUser is the Web API user object, as far as hallpass reads it.
type slackUser struct {
	ID                string `json:"id"`
	TeamID            string `json:"team_id"`
	Name              string `json:"name"`
	RealName          string `json:"real_name"`
	Deleted           bool   `json:"deleted"`
	IsAdmin           bool   `json:"is_admin"`
	IsOwner           bool   `json:"is_owner"`
	IsPrimaryOwner    bool   `json:"is_primary_owner"`
	IsRestricted      bool   `json:"is_restricted"`
	IsUltraRestricted bool   `json:"is_ultra_restricted"`
	IsBot             bool   `json:"is_bot"`
	IsAppUser         bool   `json:"is_app_user"`
	IsInvitedUser     bool   `json:"is_invited_user"`
	IsStranger        bool   `json:"is_stranger"`
	Profile           struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		RealName    string `json:"real_name"`
	} `json:"profile"`
	// UNVERIFIED: the enterprise_user field names is_admin / is_owner on
	// Enterprise Grid; hallpass has not seen a Grid user object.
	EnterpriseUser *struct {
		ID           string `json:"id"`
		EnterpriseID string `json:"enterprise_id"`
		IsAdmin      bool   `json:"is_admin"`
		IsOwner      bool   `json:"is_owner"`
	} `json:"enterprise_user"`
}

// Attribute keys on the resolved identity.
const (
	attrDeleted         = "deleted"
	attrBot             = "is_bot"
	attrInvited         = "is_invited_user"
	attrAdmin           = "is_admin"
	attrOwner           = "is_owner"
	attrPrimaryOwner    = "is_primary_owner"
	attrRestricted      = "is_restricted"
	attrUltraRestricted = "is_ultra_restricted"
	attrStranger        = "is_stranger"
	attrTeamID          = "team_id"
	attrEnterpriseID    = "enterprise_id"
	attrEnterpriseAdmin = "enterprise_admin"
	attrEnterpriseOwner = "enterprise_owner"
)

func boolAttr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ResolveIdentity looks the email up with users.lookupByEmail.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	var out struct {
		User slackUser `json:"user"`
	}
	if _, err := c.call(ctx, "users.lookupByEmail", url.Values{"email": {u.Email}}, &out); err != nil {
		if code := apiCode(err); code == "users_not_found" || code == "user_not_found" {
			return integration.Identity{}, integration.UserNotFound("no Slack account for %s", u.Email)
		}
		return integration.Identity{}, classify(err)
	}
	usr := out.User
	if usr.ID == "" {
		return integration.Identity{}, integration.Wrap(integration.CodeUpstreamError, errors.New("users.lookupByEmail returned no user id"), "Slack returned an incomplete user object")
	}
	display := usr.RealName
	if display == "" {
		display = usr.Profile.RealName
	}
	if display == "" {
		display = usr.Name
	}
	if display == "" {
		display = u.Email
	}
	attrs := map[string]string{
		attrDeleted:         boolAttr(usr.Deleted),
		attrBot:             boolAttr(usr.IsBot || usr.ID == "USLACKBOT"),
		attrInvited:         boolAttr(usr.IsInvitedUser),
		attrAdmin:           boolAttr(usr.IsAdmin),
		attrOwner:           boolAttr(usr.IsOwner),
		attrPrimaryOwner:    boolAttr(usr.IsPrimaryOwner),
		attrRestricted:      boolAttr(usr.IsRestricted),
		attrUltraRestricted: boolAttr(usr.IsUltraRestricted),
		attrStranger:        boolAttr(usr.IsStranger),
		attrTeamID:          usr.TeamID,
	}
	if usr.EnterpriseUser != nil {
		attrs[attrEnterpriseID] = usr.EnterpriseUser.EnterpriseID
		attrs[attrEnterpriseAdmin] = boolAttr(usr.EnterpriseUser.IsAdmin)
		attrs[attrEnterpriseOwner] = boolAttr(usr.EnterpriseUser.IsOwner)
	}
	return integration.Identity{ID: usr.ID, Display: display, Attrs: attrs, Native: &usr}, nil
}

// inactive reports why the account cannot act at all, if so.
func inactive(id integration.Identity) (string, bool) {
	switch {
	case id.Attr(attrDeleted) == "true":
		return "account deactivated", true
	case id.Attr(attrBot) == "true":
		return "bot account", true
	case id.Attr(attrInvited) == "true":
		return "invited, not yet joined", true
	}
	return "", false
}

func isAdmin(id integration.Identity) bool {
	return id.Attr(attrAdmin) == "true" || id.Attr(attrOwner) == "true" || id.Attr(attrPrimaryOwner) == "true"
}

func isOwner(id integration.Identity) bool {
	return id.Attr(attrOwner) == "true" || id.Attr(attrPrimaryOwner) == "true"
}

func isGuest(id integration.Identity) bool {
	return id.Attr(attrRestricted) == "true" || id.Attr(attrUltraRestricted) == "true"
}

// otherWorkspace reports whether, on an Enterprise Grid org-level install
// addressed with team_id, the user object belongs to a different workspace.
// Slack then says nothing about the user's membership of the addressed
// workspace, so rules that rest on "any full member of this workspace" are
// not evaluated.
// UNVERIFIED: on a Grid org-level install, the team_id of the user object
// users.lookupByEmail returns names the user's workspace; a user of the
// addressed workspace is taken to carry the configured team_id.
func (c *Connection) otherWorkspace(id integration.Identity) bool {
	return c.teamID != "" && id.Attr(attrTeamID) != "" && id.Attr(attrTeamID) != c.teamID
}

func role(id integration.Identity) string {
	switch {
	case id.Attr(attrPrimaryOwner) == "true":
		return "primary owner"
	case id.Attr(attrOwner) == "true":
		return "owner"
	case id.Attr(attrAdmin) == "true":
		return "admin"
	case id.Attr(attrUltraRestricted) == "true":
		return "single-channel guest"
	case id.Attr(attrRestricted) == "true":
		return "multi-channel guest"
	}
	return "full member"
}

// posters is Slack's "who may post" shape: {"type":["admin"],"user":["U.."]}.
// UNVERIFIED: the shape of who_can_post_general (team.preferences.list) and
// whether conversations.info exposes properties.posting_restricted_to to a
// bot token. Both are read in this shape; a string form is accepted too.
type posters struct {
	Type []string `json:"type"`
	User []string `json:"user"`
}

// parsePosters accepts the object form, or a string such as "everyone",
// "admin" or "owner".
func parsePosters(raw json.RawMessage) (*posters, error) {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		switch s {
		case "", "everyone", "regular", "ra": // UNVERIFIED: string values of who_can_post_general
			return &posters{}, nil
		case "admin", "owner":
			return &posters{Type: []string{s}}, nil
		}
		return nil, fmt.Errorf("unrecognised value %q", s)
	}
	var p posters
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// allows reports whether the identity is among the posters. An empty rule
// means everyone. When the identity matches nothing and the rule names a
// type hallpass does not model, unknown carries that type: the rule could
// not be evaluated, so the caller answers unsupported rather than deny.
func (p *posters) allows(id integration.Identity) (ok bool, unknown string) {
	if p == nil || (len(p.Type) == 0 && len(p.User) == 0) {
		return true, ""
	}
	for _, t := range p.Type {
		switch t {
		case "everyone", "regular", "ra":
			return true, ""
		case "admin":
			if isAdmin(id) {
				return true, ""
			}
		case "owner":
			if isOwner(id) {
				return true, ""
			}
		default:
			if unknown == "" {
				unknown = t
			}
		}
	}
	for _, u := range p.User {
		if u == id.ID {
			return true, ""
		}
	}
	return false, unknown
}

func (p *posters) String() string {
	if p == nil || (len(p.Type) == 0 && len(p.User) == 0) {
		return "everyone"
	}
	var parts []string
	for _, t := range p.Type {
		switch t {
		case "admin":
			parts = append(parts, "admins and owners")
		case "owner":
			parts = append(parts, "owners")
		default:
			parts = append(parts, t)
		}
	}
	if n := len(p.User); n > 0 {
		parts = append(parts, fmt.Sprintf("%d named users", n))
	}
	return strings.Join(parts, " and ")
}

// channel is the conversations.info object, as far as hallpass reads it.
type channel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IsArchived  bool   `json:"is_archived"`
	IsPrivate   bool   `json:"is_private"`
	IsGeneral   bool   `json:"is_general"`
	IsMember    bool   `json:"is_member"` // the bot
	IsExtShared bool   `json:"is_ext_shared"`
	IsShared    bool   `json:"is_shared"`
	// Properties is nil when conversations.info returned no properties object.
	Properties *struct {
		PostingRestrictedTo json.RawMessage `json:"posting_restricted_to"`
	} `json:"properties"`
}

// postingRestrictedTo is the raw posting_restricted_to property, or nil when
// the channel object carries no properties at all.
func (ch *channel) postingRestrictedTo() json.RawMessage {
	if ch.Properties == nil {
		return nil
	}
	return ch.Properties.PostingRestrictedTo
}

func (ch *channel) label() string {
	if ch.Name != "" {
		return "#" + ch.Name + " (" + ch.ID + ")"
	}
	return ch.ID
}

func (c *Connection) channel(ctx context.Context, id string) (*channel, error) {
	var out struct {
		Channel channel `json:"channel"`
	}
	if _, err := c.call(ctx, "conversations.info", url.Values{"channel": {id}}, &out); err != nil {
		switch apiCode(err) {
		case "channel_not_found":
			// A private channel the bot is not in answers channel_not_found
			// too, for both C and G ids, so this is never a deny.
			return nil, integration.Wrap(integration.CodeResourceNotVisible, err,
				"channel %s does not exist or is a private channel the bot is not in; invite the bot to the channel", id)
		case "not_in_channel":
			return nil, integration.Wrap(integration.CodeResourceNotVisible, err,
				"the bot is not a member of channel %s; invite the bot to the channel", id)
		}
		return nil, classify(err)
	}
	if out.Channel.ID == "" {
		out.Channel.ID = id
	}
	return &out.Channel, nil
}

// membershipPages is how many users.conversations pages are read before
// switching to conversations.members.
const membershipPages = 5

// isMember reports whether the user is in the channel. users.conversations
// lists the user's channels (cost grows with how many the user is in); after
// membershipPages pages without a hit the channel's member list is read
// instead.
func (c *Connection) isMember(ctx context.Context, userID, channelID string) (bool, error) {
	cursor := ""
	for page := 0; page < membershipPages; page++ {
		q := url.Values{"user": {userID}, "types": {"public_channel,private_channel"}, "limit": {"1000"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var out struct {
			Channels []struct {
				ID string `json:"id"`
			} `json:"channels"`
		}
		res, err := c.call(ctx, "users.conversations", q, &out)
		if err != nil {
			return false, classify(err)
		}
		for _, ch := range out.Channels {
			if ch.ID == channelID {
				return true, nil
			}
		}
		cursor = res.NextCursor
		if cursor == "" {
			return false, nil
		}
	}
	cursor = ""
	for page := 0; page < httpx.MaxPages; page++ {
		q := url.Values{"channel": {channelID}, "limit": {"1000"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var out struct {
			Members []string `json:"members"`
		}
		res, err := c.call(ctx, "conversations.members", q, &out)
		if err != nil {
			return false, classify(err)
		}
		for _, m := range out.Members {
			if m == userID {
				return true, nil
			}
		}
		cursor = res.NextCursor
		if cursor == "" {
			return false, nil
		}
	}
	return false, integration.Errorf(integration.CodeUnsupported, "channel %s has more members than hallpass will list", channelID)
}

// generalPosters reads who may post in #general.
func (c *Connection) generalPosters(ctx context.Context) (*posters, error) {
	var out struct {
		WhoCanPostGeneral json.RawMessage `json:"who_can_post_general"`
	}
	if _, err := c.call(ctx, "team.preferences.list", nil, &out); err != nil {
		if apiCode(err) == "missing_scope" && c.assumeDefaults {
			return &posters{}, nil
		}
		return nil, classify(err)
	}
	p, err := parsePosters(out.WhoCanPostGeneral)
	if err != nil {
		return nil, integration.Errorf(integration.CodeUnsupported, "who_can_post_general has a shape hallpass does not understand")
	}
	if p == nil {
		if c.assumeDefaults {
			return &posters{}, nil
		}
		return nil, integration.Errorf(integration.CodeUnsupported, "team.preferences.list did not report who_can_post_general; set assume_default_prefs: true to assume everyone may post")
	}
	return p, nil
}

// usergroupMembers returns the member ids of one user group, or found=false
// when the group is not listed (unknown id, or a disabled group).
func (c *Connection) usergroupMembers(ctx context.Context, id string) (members []string, handle string, found bool, err error) {
	var out struct {
		Usergroups []struct {
			ID     string   `json:"id"`
			Handle string   `json:"handle"`
			Users  []string `json:"users"`
		} `json:"usergroups"`
	}
	if _, err := c.call(ctx, "usergroups.list", url.Values{"include_users": {"true"}}, &out); err != nil {
		return nil, "", false, classify(err)
	}
	for _, g := range out.Usergroups {
		if g.ID == id {
			return g.Users, g.Handle, true, nil
		}
	}
	return nil, "", false, nil
}

// Check answers one action.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	a, err := validateResource(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	id := r.Identity
	if reason, off := inactive(id); off {
		return integration.Denied("%s (%s): %s", id.Display, id.ID, reason), nil
	}
	switch a.name {
	case "user.active":
		return integration.Allowed("%s (%s) is an active %s", id.Display, id.ID, role(id)), nil
	case "workspace.admin":
		if isAdmin(id) {
			return integration.Allowed("%s is a workspace %s", id.Display, role(id)), nil
		}
		return integration.Denied("%s is a %s, not a workspace admin or owner", id.Display, role(id)), nil
	case "org.admin":
		if id.Attr(attrEnterpriseAdmin) == "" {
			return integration.Unsupported("the user object has no enterprise_user field; this is not an Enterprise Grid workspace, or the bot cannot see org roles"), nil
		}
		if id.Attr(attrEnterpriseAdmin) == "true" || id.Attr(attrEnterpriseOwner) == "true" {
			return integration.Allowed("%s is an org admin or owner", id.Display), nil
		}
		return integration.Denied("%s is not an org admin or owner", id.Display), nil
	case "channel.create":
		return c.prefGate(id, "create channels"), nil
	case "usergroup.member":
		return c.checkUsergroup(ctx, id, r.Resource.ID)
	}

	// Channel actions.
	if id.Attr(attrStranger) == "true" {
		return integration.Unsupported("%s is an external (Slack Connect) user; channel permissions in this workspace are not evaluated for external users", id.Display), nil
	}
	ch, err := c.channel(ctx, r.Resource.ID)
	if err != nil {
		return integration.Decision{}, err
	}
	switch a.name {
	case "channel.read":
		return c.checkRead(ctx, id, ch)
	case "channel.join":
		return c.checkJoin(ctx, id, ch)
	case "message.post", "file.upload":
		return c.checkPost(ctx, id, ch, false)
	case "message.post_thread":
		return c.checkPost(ctx, id, ch, true)
	case "channel.invite":
		if ch.IsArchived {
			return integration.Denied("%s is archived; nobody can be invited", ch.label()), nil
		}
		return c.memberPrefGate(ctx, id, ch, "invite members to channels")
	case "channel.rename":
		if ch.IsArchived {
			return integration.Denied("%s is archived and cannot be renamed", ch.label()), nil
		}
		return c.memberPrefGate(ctx, id, ch, "rename channels")
	case "channel.archive":
		if ch.IsArchived {
			return integration.Denied("%s is already archived", ch.label()), nil
		}
		if ch.IsGeneral {
			return integration.Denied("%s is the workspace's general channel and cannot be archived", ch.label()), nil
		}
		return c.memberPrefGate(ctx, id, ch, "archive channels")
	}
	return integration.Decision{}, errors.New("unreachable: unknown action")
}

// memberPrefGate answers the channel-scoped actions a workspace preference
// governs (invite, rename, archive). They all act from inside the channel,
// so membership is checked first: a non-member of a private channel is
// refused outright, a guest cannot join on their own, and anyone else could
// join a public channel first, which hallpass does not assume. Members go
// through prefGate.
func (c *Connection) memberPrefGate(ctx context.Context, id integration.Identity, ch *channel, verb string) (integration.Decision, error) {
	member, err := c.isMember(ctx, id.ID, ch.ID)
	if err != nil {
		return integration.Decision{}, err
	}
	if !member {
		switch {
		case ch.IsPrivate:
			return integration.Denied("%s is private and %s is not a member", ch.label(), id.Display), nil
		case isGuest(id):
			return integration.Denied("%s is a %s and not a member of %s", id.Display, role(id), ch.label()), nil
		}
		return integration.Unsupported("%s is not a member of %s; joining first is possible, but the action needs membership", id.Display, ch.label()), nil
	}
	return c.prefGate(id, verb), nil
}

func (c *Connection) checkUsergroup(ctx context.Context, id integration.Identity, groupID string) (integration.Decision, error) {
	members, handle, found, err := c.usergroupMembers(ctx, groupID)
	if err != nil {
		return integration.Decision{}, err
	}
	if !found {
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "user group %s is not listed for this workspace; it does not exist or is disabled", groupID), nil
	}
	label := groupID
	if handle != "" {
		label = "@" + handle + " (" + groupID + ")"
	}
	for _, m := range members {
		if m == id.ID {
			return integration.Allowed("%s is a member of user group %s", id.Display, label), nil
		}
	}
	return integration.Denied("%s is not a member of user group %s", id.Display, label), nil
}

func (c *Connection) checkRead(ctx context.Context, id integration.Identity, ch *channel) (integration.Decision, error) {
	archived := ""
	if ch.IsArchived {
		archived = " (archived; still readable)"
	}
	if ch.IsPrivate || isGuest(id) {
		member, err := c.isMember(ctx, id.ID, ch.ID)
		if err != nil {
			return integration.Decision{}, err
		}
		if member {
			return integration.Allowed("%s is a member of %s%s", id.Display, ch.label(), archived), nil
		}
		if ch.IsPrivate {
			return integration.Denied("%s is private and %s is not a member", ch.label(), id.Display), nil
		}
		return integration.Denied("%s is a %s and not a member of %s", id.Display, role(id), ch.label()), nil
	}
	if c.otherWorkspace(id) {
		return integration.Unsupported("%s belongs to another workspace of the organization; whether they are a member of the workspace that owns %s is not visible", id.Display, ch.label()), nil
	}
	return integration.Allowed("%s is public%s; any full member may read it", ch.label(), archived), nil
}

func (c *Connection) checkJoin(ctx context.Context, id integration.Identity, ch *channel) (integration.Decision, error) {
	if ch.IsArchived {
		return integration.Denied("%s is archived and cannot be joined", ch.label()), nil
	}
	if ch.IsPrivate || isGuest(id) {
		member, err := c.isMember(ctx, id.ID, ch.ID)
		if err != nil {
			return integration.Decision{}, err
		}
		if member {
			return integration.Allowed("%s is already a member of %s", id.Display, ch.label()), nil
		}
		if ch.IsPrivate {
			return integration.Denied("%s is private; %s must be invited", ch.label(), id.Display), nil
		}
		return integration.Denied("%s is a %s and cannot join channels on their own", id.Display, role(id)), nil
	}
	if c.otherWorkspace(id) {
		return integration.Unsupported("%s belongs to another workspace of the organization; whether they are a member of the workspace that owns %s is not visible", id.Display, ch.label()), nil
	}
	return integration.Allowed("%s is public; any full member may join it", ch.label()), nil
}

func (c *Connection) checkPost(ctx context.Context, id integration.Identity, ch *channel, thread bool) (integration.Decision, error) {
	if ch.IsArchived {
		return integration.Denied("%s is archived", ch.label()), nil
	}
	member, err := c.isMember(ctx, id.ID, ch.ID)
	if err != nil {
		return integration.Decision{}, err
	}
	if !member {
		switch {
		case ch.IsPrivate:
			return integration.Denied("%s is private and %s is not a member", ch.label(), id.Display), nil
		case isGuest(id):
			return integration.Denied("%s is a %s and not a member of %s", id.Display, role(id), ch.label()), nil
		}
		return integration.Denied("%s is not a member of %s; joining is possible for a full member, but posting needs membership first", id.Display, ch.label()), nil
	}
	if ch.IsGeneral {
		p, err := c.generalPosters(ctx)
		if err != nil {
			return integration.Decision{}, err
		}
		if ok, unknown := p.allows(id); !ok {
			if unknown != "" {
				return integration.Unsupported("who_can_post_general names a poster type %q hallpass does not understand", unknown), nil
			}
			return integration.Denied("posting in %s is restricted to %s and %s is a %s", ch.label(), p, id.Display, role(id)), nil
		}
	}
	restricted, err := parsePosters(ch.postingRestrictedTo())
	if err != nil {
		return integration.Unsupported("%s has a posting restriction in a shape hallpass does not understand", ch.label()), nil
	}
	if restricted == nil {
		// UNVERIFIED: whether a bot token sees properties.posting_restricted_to,
		// and whether Slack omits it for an unrestricted channel. An absent
		// property is therefore not taken as "unrestricted" unless the
		// connection opts in with assume_default_prefs.
		if c.assumeDefaults {
			return integration.Allowed("%s is a member of %s; no posting restriction is visible to the bot and assume_default_prefs treats the channel as unrestricted", id.Display, ch.label()), nil
		}
		return integration.Unsupported("posting restrictions of %s are not visible to the bot (no posting_restricted_to property); set assume_default_prefs: true to treat the channel as unrestricted", ch.label()), nil
	}
	if isAdmin(id) {
		return integration.Allowed("%s is a member of %s", id.Display, ch.label()), nil
	}
	ok, unknown := restricted.allows(id)
	if ok {
		return integration.Allowed("%s is a member of %s", id.Display, ch.label()), nil
	}
	if thread {
		// UNVERIFIED: posting_restricted_to is taken to limit top-level
		// posts only, not thread replies.
		return integration.Allowed("%s is a member of %s; top-level posting is restricted to %s but thread replies are not", id.Display, ch.label(), restricted), nil
	}
	if unknown != "" {
		return integration.Unsupported("the posting restriction of %s names a poster type %q hallpass does not understand", ch.label(), unknown), nil
	}
	return integration.Denied("posting in %s is restricted to %s and %s is a %s", ch.label(), restricted, id.Display, role(id)), nil
}

// prefGate answers the actions governed by a workspace preference a bot
// token cannot read: guests may not, admins and owners may, and for everyone
// else the answer is unknown unless assume_default_prefs is set.
func (c *Connection) prefGate(id integration.Identity, verb string) integration.Decision {
	if isGuest(id) {
		return integration.Denied("%s is a %s; guests may not %s", id.Display, role(id), verb)
	}
	if isAdmin(id) {
		return integration.Allowed("%s is a workspace %s", id.Display, role(id))
	}
	if c.assumeDefaults {
		// UNVERIFIED: Slack's default for each of these preferences is "everyone".
		return integration.Allowed("%s is a full member and assume_default_prefs treats the workspace preference 'who can %s' as Slack's default (everyone)", id.Display, verb)
	}
	return integration.Unsupported("the workspace preference 'who can %s' is not readable by a bot token; %s is a full member", verb, id.Display)
}

// Probe verifies the token with auth.test and the users:read.email scope
// with a lookup that cannot match, and warns about missing optional scopes
// and any write scope the token carries.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var auth struct {
		UserID              string `json:"user_id"`
		BotID               string `json:"bot_id"`
		Team                string `json:"team"`
		TeamID              string `json:"team_id"`
		IsEnterpriseInstall bool   `json:"is_enterprise_install"`
	}
	res, err := c.call(ctx, "auth.test", nil, &auth)
	if err != nil {
		return integration.ProbeResult{}, classify(err)
	}
	out := integration.ProbeResult{Summary: fmt.Sprintf("authenticated as bot user %s in workspace %s", auth.UserID, auth.Team)}
	if auth.BotID != "" {
		out.Summary += " (bot " + auth.BotID + ")"
	}
	if auth.IsEnterpriseInstall && c.teamID == "" {
		out.Warnings = append(out.Warnings, "the token is an Enterprise Grid org-level install but team_id is not set; set it to the workspace to check")
	}
	// UNVERIFIED: whether Slack sends X-OAuth-Scopes on Web API responses.
	if scopes := res.Header.Get("X-OAuth-Scopes"); scopes != "" {
		out.Warnings = append(out.Warnings, scopeWarnings(scopes)...)
	}

	_, err = c.call(ctx, "users.lookupByEmail", url.Values{"email": {"hallpass-probe-does-not-exist@example.invalid"}}, nil)
	switch code := apiCode(err); {
	case err == nil, code == "users_not_found", code == "user_not_found":
	case code == "missing_scope":
		out.Warnings = append(out.Warnings, "the token lacks users:read.email; every check will answer credential_rejected")
	default:
		return integration.ProbeResult{}, classify(err)
	}

	for _, m := range []struct{ method, scope string }{
		{"team.preferences.list", "team.preferences:read"},
		{"usergroups.list", "usergroups:read"},
	} {
		_, err := c.call(ctx, m.method, nil, nil)
		if err == nil {
			continue
		}
		if apiCode(err) == "missing_scope" {
			out.Warnings = append(out.Warnings, fmt.Sprintf("the token lacks the optional scope %s; %s", m.scope, optionalScopes[m.scope]))
			continue
		}
		return integration.ProbeResult{}, classify(err)
	}

	// Whether the bot sees channel properties at all, read off #general.
	genID, err := c.generalChannelID(ctx)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	if genID == "" {
		out.Warnings = append(out.Warnings, fmt.Sprintf("#general was not found among the first %d pages of public channels; whether channel properties are visible to the bot was not checked", generalListPages))
		return out, nil
	}
	gen, err := c.channel(ctx, genID)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	if gen.Properties != nil {
		out.Summary += "; channel properties visible"
	} else {
		out.Warnings = append(out.Warnings, fmt.Sprintf("conversations.info on #general (%s) returned no properties object; message.post answers unknown for channels without a visible posting_restricted_to unless assume_default_prefs is set", genID))
	}
	return out, nil
}

// generalListPages bounds the conversations.list pages the probe reads to
// find #general, which is the workspace's oldest channel and listed early.
const generalListPages = 5

// generalChannelID finds the workspace's general channel with
// conversations.list; "" when it is not among the first pages.
func (c *Connection) generalChannelID(ctx context.Context) (string, error) {
	cursor := ""
	for page := 0; page < generalListPages; page++ {
		q := url.Values{"types": {"public_channel"}, "exclude_archived": {"true"}, "limit": {"200"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var out struct {
			Channels []struct {
				ID        string `json:"id"`
				IsGeneral bool   `json:"is_general"`
			} `json:"channels"`
		}
		res, err := c.call(ctx, "conversations.list", q, &out)
		if err != nil {
			return "", classify(err)
		}
		for _, ch := range out.Channels {
			if ch.IsGeneral && ch.ID != "" {
				return ch.ID, nil
			}
		}
		cursor = res.NextCursor
		if cursor == "" {
			return "", nil
		}
	}
	return "", nil
}

// scopeWarnings reads a comma-separated scope list.
func scopeWarnings(header string) []string {
	have := map[string]bool{}
	var writes []string
	for _, s := range strings.Split(header, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		have[s] = true
		if isWriteScope(s) {
			writes = append(writes, s)
		}
	}
	var out []string
	if len(writes) > 0 {
		out = append(out, "the token carries write scopes it does not need: "+strings.Join(writes, ", "))
	}
	var missing []string
	for _, s := range requiredScopes {
		if !have[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		out = append(out, "the token lacks required scopes: "+strings.Join(missing, ", "))
	}
	return out
}

func isWriteScope(s string) bool {
	s = strings.ToLower(s)
	switch {
	case strings.HasPrefix(s, "admin"):
		return true
	case strings.Contains(s, ":write"), strings.Contains(s, ":manage"):
		return true
	case s == "incoming-webhook", s == "commands":
		return true
	}
	return false
}
