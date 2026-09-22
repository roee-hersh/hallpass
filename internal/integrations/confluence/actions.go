package confluence

import (
	"fmt"
	"regexp"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

type resourceKind string

const (
	resPage     resourceKind = "page"
	resBlogpost resourceKind = "blogpost"
	resSpace    resourceKind = "space"
)

func (k resourceKind) idShape() string {
	if k == resSpace {
		return "KEY"
	}
	return "id"
}

// action is one Confluence operation. Page and blog post actions are asked
// of the content permission check with operation; space actions are matched
// against the space permission list by operation key and target type.
type action struct {
	name, desc string
	resource   resourceKind
	operation  string // content check operation, or space permission operation key
	target     string // space permission targetType (space actions only)
}

var actionList = []action{
	{name: "page.read", desc: "view a page", resource: resPage, operation: "read"},
	{name: "page.update", desc: "edit a page", resource: resPage, operation: "update"},
	{name: "page.delete", desc: "delete a page", resource: resPage, operation: "delete"},
	{name: "blogpost.read", desc: "view a blog post", resource: resBlogpost, operation: "read"},
	{name: "blogpost.update", desc: "edit a blog post", resource: resBlogpost, operation: "update"},
	{name: "blogpost.delete", desc: "delete a blog post", resource: resBlogpost, operation: "delete"},
	{name: "space.read", desc: "view the space (space permission read/space)", resource: resSpace, operation: "read", target: "space"},
	{name: "page.create", desc: "add pages in the space (create/page)", resource: resSpace, operation: "create", target: "page"},
	{name: "blogpost.create", desc: "add blog posts in the space (create/blogpost)", resource: resSpace, operation: "create", target: "blogpost"},
	{name: "comment.create", desc: "add comments in the space (create/comment)", resource: resSpace, operation: "create", target: "comment"},
	{name: "attachment.create", desc: "add attachments in the space (create/attachment)", resource: resSpace, operation: "create", target: "attachment"},
	{name: "space.export", desc: "export the space (export/space)", resource: resSpace, operation: "export", target: "space"},
	{name: "page.restrict", desc: "add or remove content restrictions in the space (restrict_content/space)", resource: resSpace, operation: "restrict_content", target: "space"},
	{name: "space.admin", desc: "administer the space (administer/space)", resource: resSpace, operation: "administer", target: "space"},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

var (
	contentIDRe = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	spaceKeyRe  = regexp.MustCompile(`^[A-Za-z0-9~_-]{1,255}$`)
)

// resource is a parsed page:<id>, blogpost:<id> or space:<KEY>.
type resource struct {
	kind resourceKind
	id   string
}

func parseResource(res catalog.Resource) (resource, error) {
	switch res.Type {
	case "page", "blogpost":
		if !contentIDRe.MatchString(res.ID) {
			return resource{}, fmt.Errorf("%s id %q must be a numeric content id", res.Type, res.ID)
		}
		return resource{kind: resourceKind(res.Type), id: res.ID}, nil
	case "space":
		if !spaceKeyRe.MatchString(res.ID) {
			return resource{}, fmt.Errorf("space key %q must match %s", res.ID, spaceKeyRe)
		}
		return resource{kind: resSpace, id: res.ID}, nil
	default:
		return resource{}, fmt.Errorf("resource type %q; use page:<id>, blogpost:<id> or space:<KEY>", res.Type)
	}
}
