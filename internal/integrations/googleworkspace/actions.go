package googleworkspace

import (
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// actionList is the fixed action table with the resource type each accepts.
var actionList = []struct {
	name, desc, resource string
	// capability is the Drive capabilities field the action maps to.
	capability string
}{
	{"user.active", "the account exists and is neither suspended nor archived (user:<email>)", "user", ""},
	{"drive.file.read", "can see a Drive file's metadata (file:<id>)", "file", ""},
	{"drive.file.download", "can download a Drive file (file:<id>)", "file", "canDownload"},
	{"drive.file.edit", "can edit a Drive file (file:<id>)", "file", "canEdit"},
	{"drive.file.comment", "can comment on a Drive file (file:<id>)", "file", "canComment"},
	{"drive.file.share", "can share a Drive file (file:<id>)", "file", "canShare"},
	{"drive.file.trash", "can move a Drive file to the trash (file:<id>)", "file", "canTrash"},
	{"drive.file.delete", "can permanently delete a Drive file (file:<id>)", "file", "canDelete"},
	{"drive.file.rename", "can rename a Drive file (file:<id>)", "file", "canRename"},
	{"drive.file.copy", "can copy a Drive file (file:<id>)", "file", "canCopy"},
	{"drive.folder.add_child", "can add files to a Drive folder (file:<id>)", "file", "canAddChildren"},
	{"drive.folder.list", "can list a Drive folder's children (file:<id>)", "file", "canListChildren"},
	{"calendar.read", "can read events of a calendar (calendar:<id>)", "calendar", ""},
	{"calendar.event.write", "can create and change events of a calendar (calendar:<id>)", "calendar", ""},
	{"calendar.share", "owns a calendar and can change its sharing (calendar:<id>)", "calendar", ""},
	{"mail.send_as", "can send mail as an address (mailbox:<email>)", "mailbox", ""},
	{"mail.delegate_access", "is an accepted Gmail delegate of a mailbox (mailbox:<email>)", "mailbox", ""},
	{"group.member", "member of a Google group (group:<email>)", "group", ""},
}

var actionIndex = func() map[string]int {
	m := map[string]int{}
	for i, a := range actionList {
		m[a.name] = i
	}
	return m
}()

// Actions of the googleworkspace integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc})
	}
	return out
}

var (
	fileIDRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{10,200}$`)
	calendarIDRe = regexp.MustCompile(`^[A-Za-z0-9._%+@#-]{1,320}$`)
	emailRe      = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}$`)
)

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// parseRef validates the resource for the action and returns the id.
func parseRef(action string, r catalog.Resource) (string, error) {
	i, ok := actionIndex[action]
	if !ok {
		return "", invalid("unknown action %q", action)
	}
	a := actionList[i]
	if r.Type != a.resource {
		return "", invalid("action %s takes a %s: resource, not %s:", action, a.resource, r.Type)
	}
	if len(r.Query) > 0 {
		return "", invalid("resource %q must not carry a query", r.Raw)
	}
	id := r.ID
	switch r.Type {
	case "user", "mailbox", "group":
		id = strings.ToLower(strings.TrimSpace(id))
		if !emailRe.MatchString(id) {
			return "", invalid("%s: id must be an email address", r.Type)
		}
	case "file":
		if !fileIDRe.MatchString(id) {
			return "", invalid("file: id must be a Drive file id")
		}
	case "calendar":
		if !calendarIDRe.MatchString(id) {
			return "", invalid("calendar: id must be a calendar id (an email or primary)")
		}
	}
	return id, nil
}
