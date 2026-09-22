package microsoft365

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// actionList is the fixed action table. Every action names the resource
// types it accepts; Check rejects anything else as invalid_request.
var actionList = []struct {
	name, desc string
	resources  []string
}{
	{"user.active", "the account exists and is enabled (user:<email> or mailbox:<email>)", []string{"user", "mailbox"}},
	{"group.member", "transitive member of an Entra group (group:<guid>)", []string{"group"}},
	{"role.member", "holds an Entra directory role (role:<role template guid>)", []string{"role"}},
	{"team.member", "member of a team (team:<guid>)", []string{"team"}},
	{"team.owner", "owner of a team (team:<guid>)", []string{"team"}},
	{"channel.read", "can read a channel (team:<guid>/channel/<channel id>)", []string{"team"}},
	{"channel.message.post", "can post a message in a channel (team:<guid>/channel/<channel id>)", []string{"team"}},
	{"channel.owner", "owner of a channel, or of its team for standard channels (team:<guid>/channel/<channel id>)", []string{"team"}},
	{"file.read", "can read a drive item (drive:<drive id>/item/<item id>)", []string{"drive"}},
	{"file.edit", "can edit a drive item (drive:<drive id>/item/<item id>)", []string{"drive"}},
	{"file.share", "can share a drive item (drive:<drive id>/item/<item id>)", []string{"drive"}},
	{"file.delete", "can delete a drive item (drive:<drive id>/item/<item id>)", []string{"drive"}},
	{"mail.send_as_self", "can send mail from their own mailbox (mailbox:<email>)", []string{"mailbox"}},
	{"mail.send_as", "Exchange Send As on a mailbox: always unknown, no Graph API (mailbox:<email>)", []string{"mailbox"}},
	{"mail.send_on_behalf", "Exchange Send on Behalf on a mailbox: always unknown, no Graph API (mailbox:<email>)", []string{"mailbox"}},
	{"mailbox.full_access", "Exchange Full Access on a mailbox: always unknown, no Graph API (mailbox:<email>)", []string{"mailbox"}},
	{"calendar.read", "read another mailbox's calendar: always unknown, no Graph API for delegation (mailbox:<email>)", []string{"mailbox"}},
	{"calendar.write", "write another mailbox's calendar: always unknown, no Graph API for delegation (mailbox:<email>)", []string{"mailbox"}},
}

var actionResources = func() map[string][]string {
	m := map[string][]string{}
	for _, a := range actionList {
		m[a.name] = a.resources
	}
	return m
}()

// Actions of the microsoft365 integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc})
	}
	return out
}

var (
	guidRe      = regexp.MustCompile(`^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`)
	channelIDRe = regexp.MustCompile(`^[A-Za-z0-9:@._-]{1,200}$`)
	driveIDRe   = regexp.MustCompile(`^[A-Za-z0-9!_.-]{1,200}$`)
	// emailRe accepts ordinary addresses and guest UPNs (which contain #EXT#).
	emailRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}$`)
)

// ref is a parsed resource.
type ref struct {
	typ string
	// id is the primary identifier: a GUID for group/role/team, an email or
	// GUID for user/mailbox, a drive id for drive.
	id string
	// channel is set for team:<id>/channel/<id>.
	channel string
	// item is set for drive:<id>/item/<id>.
	item string
}

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// parseRef validates the resource for the action.
func parseRef(action string, r catalog.Resource) (ref, error) {
	allowed, ok := actionResources[action]
	if !ok {
		return ref{}, invalid("unknown action %q", action)
	}
	found := false
	for _, t := range allowed {
		if t == r.Type {
			found = true
		}
	}
	if !found {
		return ref{}, invalid("action %s takes a %s resource, not %s:", action, strings.Join(allowed, " or "), r.Type)
	}
	if len(r.Query) > 0 {
		return ref{}, invalid("resource %q must not carry a query", r.Raw)
	}
	t := ref{typ: r.Type, id: r.ID}
	switch r.Type {
	case "user", "mailbox":
		if !emailRe.MatchString(r.ID) && !guidRe.MatchString(r.ID) {
			return ref{}, invalid("%s: id must be an email address or a GUID", r.Type)
		}
	case "group", "role":
		if !guidRe.MatchString(r.ID) {
			return ref{}, invalid("%s: id must be a GUID", r.Type)
		}
	case "team":
		teamID, rest, hasRest := strings.Cut(r.ID, "/")
		if !guidRe.MatchString(teamID) {
			return ref{}, invalid("team: id must be a GUID, optionally followed by /channel/<channel id>")
		}
		t.id = teamID
		if hasRest {
			ch, ok := strings.CutPrefix(rest, "channel/")
			if !ok || !channelIDRe.MatchString(ch) {
				return ref{}, invalid("team: expected team:<guid>/channel/<channel id>")
			}
			t.channel = ch
		}
		if strings.HasPrefix(action, "channel.") && t.channel == "" {
			return ref{}, invalid("%s needs team:<guid>/channel/<channel id>", action)
		}
		if strings.HasPrefix(action, "team.") && t.channel != "" {
			return ref{}, invalid("%s takes team:<guid> without a channel", action)
		}
	case "drive":
		driveID, rest, hasRest := strings.Cut(r.ID, "/")
		item, ok := strings.CutPrefix(rest, "item/")
		if !hasRest || !ok || !driveIDRe.MatchString(driveID) || !driveIDRe.MatchString(item) {
			return ref{}, invalid("drive: expected drive:<drive id>/item/<item id>")
		}
		t.id, t.item = driveID, item
	default:
		return ref{}, invalid("unsupported resource type %q", r.Type)
	}
	return t, nil
}

// describe renders the resource for decision texts.
func (t ref) describe() string {
	switch {
	case t.channel != "":
		return fmt.Sprintf("channel %s of team %s", t.channel, t.id)
	case t.item != "":
		return fmt.Sprintf("item %s in drive %s", t.item, t.id)
	default:
		return t.typ + " " + t.id
	}
}
